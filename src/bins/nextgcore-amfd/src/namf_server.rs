//! Namf HTTP/2 SBI server resources (TS 29.518)
//!
//! Server-side implementation of the AMF's own SBI services:
//! - Namf_Communication (§6.1): N1N2MessageTransfer,
//!   N1N2MessageSubscribe/UnSubscribe (§5.2.2.6/§5.2.2.7 — the per-UE uplink
//!   notify-callback registry), UEContextTransfer, RegistrationStatusUpdate
//! - Namf_EventExposure (§6.2): Subscribe / Unsubscribe / Modify with real
//!   HTTP POST notification delivery to the subscribed notify URI
//! - Namf_MT (§6.3): EnableUeReachability, ProvideDomainSelectionInfo
//! - Namf_Location (§6.4): ProvidePositioningInfo
//!
//! All error outcomes carry ProblemDetails bodies per TS 29.500 §5.2.7.
//! Malformed input returns 400 — handlers never panic on bad bodies.

use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::message::{ProblemDetails, SbiPart, SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_error, send_method_not_allowed, send_not_found};
use serde_json::{json, Value};

use crate::ngap_mcast::Tmgi;

use crate::context::{
    amf_self, AmfSess, AmfUe, AssignedEbi, EbiArp, EventSubscription, LcsCorrelationRecord, NrCgi,
    PendingPositioningDl, PlmnId, PositioningDlKind, RanUe, Tai5gs, UeContextTransferState,
    UeN1N2InfoSubscription, EBI_ASSIGNABLE, NEXTGCORE_INVALID_POOL_ID,
};
use crate::namf_handler::{
    self, AccessType, DeregistrationData, DeregistrationReason, N1N2MessageTransferCause,
    N1N2MessageTransferReqData, N2InfoContainer, NgapIeType,
};

/// Notification client connect timeout (bounded so notification tasks can
/// never hang)
const NOTIFY_CONNECT_TIMEOUT_SECS: u64 = 2;
/// Notification client request timeout
const NOTIFY_REQUEST_TIMEOUT_SECS: u64 = 3;

// ============================================================================
// Request router
// ============================================================================

/// Top-level Namf SBI request handler. Routes all Namf services served by
/// the AMF (TS 29.518): namf-comm, namf-evts, namf-mt, namf-loc.
pub async fn namf_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.clone();
    let uri = request.header.uri.clone();
    log::debug!("AMF SBI request: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(&uri);
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() < 3 {
        return send_not_found(
            "Invalid resource path",
            Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
        );
    }

    let service = parts[0];
    let method = method.as_str();

    match service {
        // --------------------------------------------------------------
        // Namf_EventExposure (TS 29.518 §6.2)
        //   POST   /namf-evts/v1/subscriptions
        //   PATCH  /namf-evts/v1/subscriptions/{subscriptionId}
        //   DELETE /namf-evts/v1/subscriptions/{subscriptionId}
        // --------------------------------------------------------------
        "namf-evts" if parts[2] == "subscriptions" => match (method, parts.len()) {
            ("POST", 3) => handle_event_subscription_create(&request),
            ("PATCH", 4) => handle_event_subscription_modify(parts[3], &request),
            ("DELETE", 4) => handle_event_subscription_delete(parts[3]),
            _ => send_method_not_allowed(method, path),
        },

        // --------------------------------------------------------------
        // Namf_Communication (TS 29.518 §6.1)
        //   PUT    /namf-comm/v1/ue-contexts/{ueContextId}          (CreateUEContext)
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/release
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/relocate
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/cancel-relocate
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions
        //   DELETE /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions/{subscriptionId}
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/assign-ebi
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/transfer
        //   POST   /namf-comm/v1/ue-contexts/{ueContextId}/transfer-update
        //
        // #74: the length guard was `>= 5`, so `PUT .../ue-contexts/{id}` — which
        // has FOUR path segments — could not reach this arm at all and fell to the
        // 404 at the bottom. Widened to `>= 4` with the 4-segment case handled
        // explicitly. It stays ONE arm rather than a second `parts[2] ==
        // "ue-contexts"` arm, because a second one would be shadowed by this for
        // every path they share, which is how a route ends up unreachable.
        // --------------------------------------------------------------
        "namf-comm" if parts[2] == "ue-contexts" && parts.len() >= 4 => {
            let ue_context_id = parts[3];
            // CreateUEContext (TS 29.518 §5.2.2.2.3.1): the "Individual UeContext"
            // document itself, addressed with no sub-resource.
            if parts.len() == 4 {
                return match method {
                    "PUT" => handle_create_ue_context(ue_context_id, &request),
                    _ => send_method_not_allowed(method, path),
                };
            }
            match (method, parts[4], parts.len()) {
                ("POST", "n1-n2-messages", 5) => {
                    handle_n1_n2_message_transfer_request(ue_context_id, &request)
                }
                // N1N2MessageSubscribe (TS 29.518 §5.2.2.6)
                ("POST", "n1-n2-messages", 6) if parts[5] == "subscriptions" => {
                    handle_n1n2_subscription_create(ue_context_id, &request)
                }
                // N1N2MessageUnSubscribe (TS 29.518 §5.2.2.7)
                ("DELETE", "n1-n2-messages", 7) if parts[5] == "subscriptions" => {
                    handle_n1n2_subscription_delete(ue_context_id, parts[6])
                }
                // EBIAssignment (TS 29.518 §6.1.6.2.5), #117
                ("POST", "assign-ebi", 5) => handle_assign_ebi(ue_context_id, &request),
                ("POST", "transfer", 5) => handle_ue_context_transfer(ue_context_id, &request),
                ("POST", "transfer-update", 5) => {
                    handle_registration_status_update(ue_context_id, &request)
                }
                // ReleaseUEContext (TS 29.518 §5.2.2.2.4.1), #74
                ("POST", "release", 5) => handle_release_ue_context(ue_context_id, &request),
                // RelocateUEContext (TS 29.518 §5.2.2.2.5.1), #74
                ("POST", "relocate", 5) => handle_relocate_ue_context(ue_context_id, &request),
                // CancelRelocateUEContext (TS 29.518 §5.2.2.2.6.1), #74
                ("POST", "cancel-relocate", 5) => {
                    handle_cancel_relocate_ue_context(ue_context_id, &request)
                }
                _ => send_method_not_allowed(method, path),
            }
        }

        // --------------------------------------------------------------
        // Namf_Communication NonUeN2MessageTransfer (TS 29.518 §5.2.2.4.1,
        // `TS29518_Namf_Communication.yaml:1718`), #396. A CBCF/PWS-IWF hands the
        // AMF a non-UE-associated N2 container for the NG-RAN; the PWS
        // information class is the Warning Request Transfer Procedure
        // (§5.2.2.4.1.3).
        //   POST /namf-comm/v1/non-ue-n2-messages/transfer
        // --------------------------------------------------------------
        "namf-comm"
            if method == "POST"
                && parts.len() == 4
                && parts[2] == "non-ue-n2-messages"
                && parts[3] == "transfer" =>
        {
            handle_non_ue_n2_message_transfer(&request)
        }

        // --------------------------------------------------------------
        // Namf_Communication NonUeN2InfoSubscribe / NonUeN2InfoUnSubscribe
        // (TS 29.518 §5.2.2.4.2 / §5.2.2.4.3), #399. A CBCF/PWS-IWF subscribes so
        // the AMF tells it what each NG-RAN node answered to a warning.
        //   POST   /namf-comm/v1/non-ue-n2-messages/subscriptions
        //   DELETE /namf-comm/v1/non-ue-n2-messages/subscriptions/{n2NotifySubscriptionId}
        //
        // The resource URI is the spec's, NOT #399's prose. §6.1.3.9.2
        // (`29518-k00.txt:9962`) and §6.1.3.10.2 (`:10111`) both put the
        // collection at `non-ue-n2-messages/subscriptions` — a SIBLING of
        // `transfer` above — and `grep -n "non-ue-n2"
        // TS29518_Namf_Communication.yaml` returns exactly those three paths
        // (`:1718`, `:1921`, `:2123`). The `non-ue-n2-info-subscriptions`
        // spelling appears nowhere in TS 29.518; serving it would expose an
        // endpoint no conformant consumer ever calls.
        //
        // This arm sits AFTER the transfer arm and is disjoint from it on
        // `parts[3]`, so neither shadows the other (the shadowing hazard #74
        // recorded for two `ue-contexts` arms).
        // --------------------------------------------------------------
        // `parts.get(3)`, not `parts[3]`: the guard above only proves
        // `parts.len() >= 3`, so indexing would panic on
        // `/namf-comm/v1/non-ue-n2-messages`.
        "namf-comm"
            if parts[2] == "non-ue-n2-messages" && parts.get(3) == Some(&"subscriptions") =>
        {
            match (method, parts.len()) {
                ("POST", 4) => handle_non_ue_n2_info_subscribe(&request),
                ("DELETE", 5) => handle_non_ue_n2_info_unsubscribe(parts[4]),
                _ => send_method_not_allowed(method, path),
            }
        }

        // --------------------------------------------------------------
        // Namf_Communication AMFStatusChange subscriptions (TS 29.518 §5.2.2.5.1),
        // #74. A consumer subscribes so it is told when this AMF's availability or
        // GUAMI service changes — the AMF planned-removal procedure (TS 23.501
        // §5.21.2.2) is what §5.2.2.5.1.1 names as this service's purpose.
        //   POST   /namf-comm/v1/subscriptions
        //   GET    /namf-comm/v1/subscriptions/{subscriptionId}
        //   PUT    /namf-comm/v1/subscriptions/{subscriptionId}
        //   DELETE /namf-comm/v1/subscriptions/{subscriptionId}
        // --------------------------------------------------------------
        "namf-comm" if parts[2] == "subscriptions" => match (method, parts.len()) {
            ("POST", 3) => handle_amf_status_subscription_create(&request),
            ("GET", 4) => handle_amf_status_subscription_read(parts[3]),
            ("PUT", 4) => handle_amf_status_subscription_replace(parts[3], &request),
            ("DELETE", 4) => handle_amf_status_subscription_delete(parts[3]),
            _ => send_method_not_allowed(method, path),
        },

        // --------------------------------------------------------------
        // Namf_MT (TS 29.518 §6.3)
        //   POST /namf-mt/v1/ue-contexts/{ueContextId}/ue-reachind
        //   GET  /namf-mt/v1/ue-contexts/{ueContextId}?info-class=...
        // --------------------------------------------------------------
        "namf-mt" if parts[2] == "ue-contexts" => match (method, parts.len()) {
            ("POST", 5) if parts[4] == "ue-reachind" => {
                handle_enable_ue_reachability(parts[3], &request)
            }
            ("GET", 4) => handle_mt_ue_context_info(parts[3], &request),
            _ => send_method_not_allowed(method, path),
        },

        // --------------------------------------------------------------
        // Namf_Location (TS 29.518 §6.4)
        //   POST /namf-loc/v1/{ueContextId}/provide-pos-info    (§5.5.2.2)
        //   POST /namf-loc/v1/{ueContextId}/provide-loc-info    (§5.5.2.4, #74)
        //   POST /namf-loc/v1/{ueContextId}/cancel-pos-info     (§5.5.2.5, #74)
        //
        // The three are `TS29518_Namf_Location.yaml`'s complete path set
        // (`:28`, `:132`, `:188`); only the first was routed before #74.
        // --------------------------------------------------------------
        "namf-loc" if method == "POST" && parts.len() == 4 => match parts[3] {
            "provide-pos-info" => handle_provide_positioning_info(parts[2], &request).await,
            "provide-loc-info" => handle_provide_location_info(parts[2], &request),
            "cancel-pos-info" => handle_cancel_location(parts[2], &request).await,
            _ => send_not_found(
                &format!("No resource for {method} {path}"),
                Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
            ),
        },

        // --------------------------------------------------------------
        // Namf_Callback: Nudm_UECM DeregistrationNotification (WSB-4,
        // TS 29.503 §5.3.2.3.2). UDM POSTs a DeregistrationData to the
        // absolute deregCallbackUri the AMF registered at UECM registration
        // (sbi_path::call_udm_uecm_registration) when the serving AMF changed.
        //   POST /namf-callback/v1/{supi}/dereg-notify
        // --------------------------------------------------------------
        "namf-callback" if parts.len() == 4 && parts[3] == "dereg-notify" && method == "POST" => {
            handle_dereg_notify_callback(parts[2], &request)
        }

        // --------------------------------------------------------------
        // Namf_Callback: Npcf_UEPolicyControl update/terminate notification
        // (#92, TS 29.525 §4.2.4). The PCF POSTs a `PolicyUpdate` to
        // `{notificationUri}/update`, or a terminate to
        // `{notificationUri}/terminate`, where `notificationUri` is the absolute
        // URI the AMF registered at association create
        // (`sbi_path::ue_policy_notification_uri`). Before #92 this path was
        // unrouted and fell to the 404 arm below, so the PCF's notification had
        // nowhere to land even once the PCF started sending it.
        //   POST /namf-callback/v1/{supi}/ue-policy-notify/{update|terminate}
        //   POST /namf-callback/v1/{supi}/ue-policy-notify
        // --------------------------------------------------------------
        "namf-callback"
            if method == "POST"
                && (4..=5).contains(&parts.len())
                && parts[3] == "ue-policy-notify" =>
        {
            handle_ue_policy_notify_callback(parts[2], parts.get(4).copied(), &request)
        }

        // --------------------------------------------------------------
        // Namf_MBSCommunication (TS 29.518 §5.7, TS 23.247 §7.2.5.2)
        //   POST /namf-mbs-comm/v1/n2-messages/transfer
        //
        // The MB-SMF's N2 message transfer: the AMF relays the MBS SM container
        // to the NG-RAN. Resource names are the OpenAPI's
        // (TS29518_Namf_MBSCommunication.yaml server url `{apiRoot}/namf-mbs-comm/v1`),
        // not the issue's prose.
        // --------------------------------------------------------------
        "namf-mbs-comm"
            if method == "POST"
                && parts.len() == 4
                && parts[2] == "n2-messages"
                && parts[3] == "transfer" =>
        {
            handle_mbs_n2_message_transfer(&request).await
        }

        // --------------------------------------------------------------
        // Namf_MBSBroadcast (TS 29.518 §5.6, TS 23.247 §7.3.1)
        //   POST /namf-mbs-bc/v1/mbs-contexts
        // --------------------------------------------------------------
        "namf-mbs-bc" if method == "POST" && parts.len() == 3 && parts[2] == "mbs-contexts" => {
            handle_mbs_context_create(&request).await
        }

        _ => {
            log::warn!("Unknown AMF SBI request: {method} {uri}");
            send_not_found(
                &format!("No resource for {method} {path}"),
                Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
            )
        }
    }
}

// ============================================================================
// Shared helpers
// ============================================================================

/// Parse the request body as JSON, or None when missing/malformed
fn parse_json_body(request: &SbiRequest) -> Option<Value> {
    request
        .http
        .content
        .as_deref()
        .and_then(|body| serde_json::from_str(body).ok())
}

/// 400 with ProblemDetails cause MANDATORY_IE_MISSING (TS 29.500 Table 5.2.7.2-1)
fn mandatory_ie_missing(attr: &str) -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        &format!("Mandatory attribute '{attr}' is missing"),
        Some("MANDATORY_IE_MISSING"),
    )
}

/// 400 with ProblemDetails cause MANDATORY_IE_INCORRECT
fn mandatory_ie_incorrect(attr: &str, detail: &str) -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        &format!("Attribute '{attr}' is incorrect: {detail}"),
        Some("MANDATORY_IE_INCORRECT"),
    )
}

/// 400 for an unparseable body
fn malformed_body() -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        "Request body is missing or not valid JSON",
        Some("INVALID_MSG_FORMAT"),
    )
}

/// 404 with ProblemDetails cause CONTEXT_NOT_FOUND (TS 29.518 §6.1.7.3)
fn context_not_found(ue_context_id: &str) -> SbiResponse {
    send_error(
        404,
        "Not Found",
        &format!("UE context '{ue_context_id}' not found"),
        Some("CONTEXT_NOT_FOUND"),
    )
}

/// Look up a UE by its ueContextId path component.
///
/// TS 29.518 Table 6.1.3.2.2-1 (`29518-k00.txt:7675`) permits three forms, and a
/// `5g-guti-…` is the one an inter-AMF `UEContextTransfer` arrives under: a target
/// AMF holding only the UE's 5G-GUTI has, by definition, no SUPI to address the
/// old AMF with. §5.2.2.2.1.1 (`:2321`) is explicit — the consumer "shall retrieve
/// the UE Context by invoking the "transfer" custom method on the URI of an
/// "Individual ueContext" resource **identified by UE's 5G-GUTI**".
///
/// So before #352 the producer half of UEContextTransfer was unreachable in the
/// only situation it exists for: every `5g-guti-…` request fell to the `else` and
/// became `404 CONTEXT_NOT_FOUND`. It was addressable by SUPI, which no real
/// consumer has at that point in the procedure.
pub(crate) fn find_ue_by_context_id(ue_context_id: &str) -> Option<AmfUe> {
    let ctx = amf_self();
    let guard = ctx.read().ok()?;
    if ue_context_id.starts_with("imsi-") || ue_context_id.starts_with("nai-") {
        guard.amf_ue_find_by_supi(ue_context_id)
    } else if let Some(guti) = crate::context::Guti5gs::from_context_id(ue_context_id) {
        // Resolved against the live store's DERIVED GUTI resolver (#341), so this
        // sees whatever the NGAP registration path committed as `current_guti`
        // (`ngap_path.rs` Registration Complete / Configuration Update Complete).
        // Before #341 this would have read an index no production path wrote.
        guard.amf_ue_find_by_guti(&guti)
    } else {
        None
    }
}

/// CM state check: the UE is CM-CONNECTED when it has a live RAN UE context
fn ue_ran_context(ue: &AmfUe) -> Option<RanUe> {
    if ue.ran_ue_id == NEXTGCORE_INVALID_POOL_ID {
        return None;
    }
    let ctx = amf_self();
    let guard = ctx.read().ok()?;
    guard.ran_ue_find_by_id(ue.ran_ue_id)
}

/// Map a TS 29.503 `DeregistrationReason` enum string to the internal reason.
/// Returns `None` for an unrecognised value (the callback fails closed).
fn parse_dereg_reason(s: &str) -> Option<DeregistrationReason> {
    Some(match s {
        "UE_INITIAL_REGISTRATION" => DeregistrationReason::UeInitialRegistration,
        "UE_REGISTRATION_AREA_CHANGE" => DeregistrationReason::UeRegistrationAreaChange,
        "SUBSCRIPTION_WITHDRAWN" => DeregistrationReason::SubscriptionWithdrawn,
        "5GS_TO_EPS_MOBILITY" => DeregistrationReason::FiveGsToEpsMobility,
        "5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION" => {
            DeregistrationReason::FiveGsToEpsMobilityUeInitialRegistration
        }
        "REREGISTRATION_REQUIRED" => DeregistrationReason::ReregistrationRequired,
        "SMF_CONTEXT_TRANSFERRED" => DeregistrationReason::SmfContextTransferred,
        _ => return None,
    })
}

/// Nudm_UECM DeregistrationNotification callback (WSB-4, TS 29.503 §5.3.2.3.2).
///
/// The UDM POSTs a `DeregistrationData` (deregReason + accessType) to the
/// absolute `deregCallbackUri` the AMF registered at UECM registration, when
/// the serving AMF for the SUPI changed. The AMF triggers a network-initiated
/// deregistration toward the UE (TS 23.502 §4.2.2.3.3 → DEREGISTRATION REQUEST,
/// TS 24.501 §5.5.2.3), enqueued for the NGAP server task by
/// [`namf_handler::handle_dereg_notify`].
///
/// Fail-closed (TS 29.500 §5.2.7): an unparseable body is 400
/// INVALID_MSG_FORMAT; a missing/unknown mandatory member is 400
/// MANDATORY_IE_MISSING / MANDATORY_IE_INCORRECT; an unknown SUPI is 404
/// CONTEXT_NOT_FOUND. On success the AMF answers 204 No Content.
fn handle_dereg_notify_callback(supi: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // deregReason (mandatory — TS 29.503 DeregistrationData).
    let Some(reason_str) = body.get("deregReason").and_then(Value::as_str) else {
        return mandatory_ie_missing("deregReason");
    };
    let Some(dereg_reason) = parse_dereg_reason(reason_str) else {
        return mandatory_ie_incorrect("deregReason", &format!("unknown reason '{reason_str}'"));
    };

    // accessType (mandatory — the AMF keys its network-initiated
    // deregistration on it; fail-closed if absent, WSB-4).
    let Some(access_str) = body.get("accessType").and_then(Value::as_str) else {
        return mandatory_ie_missing("accessType");
    };
    let access_type = match access_str {
        "3GPP_ACCESS" => AccessType::ThreeGppAccess,
        "NON_3GPP_ACCESS" => AccessType::NonThreeGppAccess,
        other => {
            return mandatory_ie_incorrect("accessType", &format!("unknown access type '{other}'"))
        }
    };

    // Resolve the UE by SUPI (ueContextId form, TS 29.518 §6.1.3.2.2).
    let Some(ue) = find_ue_by_context_id(supi) else {
        return context_not_found(supi);
    };

    let data = DeregistrationData {
        dereg_reason,
        access_type,
    };
    match namf_handler::handle_dereg_notify(&ue, &data) {
        Ok(()) => SbiResponse::no_content(),
        Err(e) => {
            log::warn!("[{supi}] dereg-notify handling error: {e:?}");
            send_error(
                500,
                "Internal Server Error",
                "deregistration notify handling failed",
                None,
            )
        }
    }
}

/// `Npcf_UEPolicyControl` update / terminate notification callback (#92,
/// TS 29.525 §4.2.4).
///
/// The PCF POSTs a `PolicyUpdate` to `{notificationUri}/update` when it
/// re-evaluates UE policy, and to `{notificationUri}/terminate` when it releases the
/// association — `notificationUri` being the absolute URI this AMF registered at
/// association create ([`crate::sbi_path::ue_policy_notification_uri`]).
///
/// `operation` is the trailing path segment (`Some("update")`, `Some("terminate")`,
/// or `None` for a POST to the bare notification URI). All three answer **204 No
/// Content**, which is what TS 29.525 specifies for the notification callbacks and
/// what #92's criterion asks for.
///
/// # Why this consumes rather than acts
///
/// The AMF's role in §4.2.4 is to LEARN that UE policy changed; the policy itself
/// travels on the N1 wire (TS 24.501 Annex D), which reaches the UE through the
/// separate `N1N2MessageTransfer` leg the PCF drives. So there is nothing for this
/// route to forward: acting on the `PolicyUpdate` body would mean the AMF inventing
/// a second delivery path for content it cannot decode (the UE policy container is
/// opaque to the AMF — see `try_ue_policy_relay`). The notification is therefore
/// logged with the resource it names and acknowledged.
///
/// A terminate additionally CLEARS the association id from the UE context, because
/// after it the id names a resource the PCF has released: keeping it would have the
/// AMF DELETE a 404 at deregistration and, worse, report a live UE-policy
/// association that does not exist.
///
/// Fail-soft rather than fail-closed, unlike `dereg-notify`: a malformed body is
/// logged and still 204'd. TS 29.500 §5.2.7's fail-closed rule protects a producer
/// from acting on a request it did not understand, and this route acts on nothing —
/// 400-ing it would make the PCF retry a notification that cannot be acted on either
/// way, and TS 29.500 §6.10 makes a 4xx the one status that stops the retry loop.
fn handle_ue_policy_notify_callback(
    supi: &str,
    operation: Option<&str>,
    request: &SbiRequest,
) -> SbiResponse {
    let resource_uri = parse_json_body(request)
        .and_then(|b| {
            b.get("resourceUri")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "<none>".to_string());

    match operation {
        Some("terminate") => {
            log::info!(
                "[{supi}] Npcf_UEPolicyControl terminate notification (resourceUri={resource_uri}); \
                 releasing the stored UE policy association id"
            );
            clear_ue_policy_association(supi);
        }
        Some("update") | None => {
            log::info!(
                "[{supi}] Npcf_UEPolicyControl update notification (resourceUri={resource_uri}); \
                 the UE policy itself arrives over N1N2MessageTransfer, so this is acknowledged \
                 and not forwarded"
            );
        }
        Some(other) => {
            // An unknown sub-resource under a URI this AMF advertised. Logged loudly
            // because it means the PCF is using an operation this build does not know
            // about, and answering 204 to it would hide that from both sides.
            log::warn!(
                "[{supi}] Npcf_UEPolicyControl notification with unknown operation \
                 '{other}' (resourceUri={resource_uri}); acknowledged without action"
            );
        }
    }

    SbiResponse::no_content()
}

/// Forget the UE-policy association id held for `supi` (#92), after the PCF says it
/// terminated the association.
///
/// Best-effort and silent on a missing UE: a terminate for a UE the AMF has already
/// released is the ordinary race (the PCF's notification and the AMF's own
/// deregistration cross), not an error worth a WARN on every deregistration.
fn clear_ue_policy_association(supi: &str) {
    let Some(mut ue) = find_ue_by_context_id(supi) else {
        log::debug!(
            "[{supi}] UE policy terminate notification for a UE this AMF no longer holds; \
             nothing to clear"
        );
        return;
    };
    // The context's own clearer, not a hand-rolled field assignment: it also drops
    // `resource_uri`, and `pcf_ue_policy_associated` reads `id` — leaving a resource URI
    // behind for an association that no longer exists is how a later DELETE ends up
    // addressing a released resource.
    ue.pcf_ue_policy_clear();
    if let Ok(guard) = amf_self().read() {
        guard.amf_ue_update(&ue);
    }
}

/// Encode a PlmnId as TS 29.571 JSON ({"mcc": "...", "mnc": "..."})
fn plmn_id_json(plmn: &PlmnId) -> Value {
    let mcc = format!("{}{}{}", plmn.mcc1, plmn.mcc2, plmn.mcc3);
    let mnc = if plmn.mnc3 == 0xf {
        format!("{}{}", plmn.mnc1, plmn.mnc2)
    } else {
        format!("{}{}{}", plmn.mnc1, plmn.mnc2, plmn.mnc3)
    };
    json!({ "mcc": mcc, "mnc": mnc })
}

/// Encode an NCGI as TS 29.571 JSON (nrCellId: 9 hex digits / 36 bits)
fn ncgi_json(ncgi: &NrCgi) -> Value {
    json!({
        "plmnId": plmn_id_json(&ncgi.plmn_id),
        "nrCellId": format!("{:09X}", ncgi.cell_id & 0xF_FFFF_FFFF),
    })
}

/// Encode a TAI as TS 29.571 JSON (tac: 4 or 6 hex digits)
fn tai_json(tai: &Tai5gs) -> Value {
    let tac = if tai.tac > 0xFFFF {
        format!("{:06X}", tai.tac & 0xFF_FFFF)
    } else {
        format!("{:04X}", tai.tac)
    };
    json!({ "plmnId": plmn_id_json(&tai.plmn_id), "tac": tac })
}

/// NrLocation user-location JSON for a UE (TS 29.571 UserLocation)
fn nr_location_json(ue: &AmfUe) -> Value {
    json!({
        "nrLocation": {
            "tai": tai_json(&ue.nr_tai),
            "ncgi": ncgi_json(&ue.nr_cgi),
        }
    })
}

// ============================================================================
// RFC 3339 DateTime helpers (3GPP DateTime, TS 29.571)
// ============================================================================

/// Convert days-since-epoch to (year, month, day) — Howard Hinnant's
/// civil_from_days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Inverse of `civil_from_days`: (year, month, day) to days-since-epoch
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Format a SystemTime as an RFC 3339 UTC timestamp
fn system_time_to_rfc3339(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Current time as an RFC 3339 UTC timestamp
fn rfc3339_now() -> String {
    system_time_to_rfc3339(std::time::SystemTime::now())
}

/// Parse an RFC 3339 timestamp ("YYYY-MM-DDTHH:MM:SS[.frac](Z|±hh:mm)") into
/// a SystemTime. Returns None on malformed input (never panics).
fn rfc3339_to_system_time(s: &str) -> Option<std::time::SystemTime> {
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> { s.get(range)?.parse::<i64>().ok() };
    if bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b't') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)? as u32, num(8..10)? as u32);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..61).contains(&sec) {
        return None;
    }
    // Skip fractional seconds, then parse the offset
    let mut idx = 19;
    if bytes.get(idx) == Some(&b'.') {
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    let offset_secs: i64 = match bytes.get(idx) {
        Some(b'Z') | Some(b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let oh = num(idx + 1..idx + 3)?;
            let om = num(idx + 4..idx + 6)?;
            let v = oh * 3600 + om * 60;
            if *sign == b'+' {
                v
            } else {
                -v
            }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    let epoch_secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    if epoch_secs < 0 {
        return Some(std::time::UNIX_EPOCH);
    }
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch_secs as u64))
}

// ============================================================================
// Namf_EventExposure — subscription resource handlers (TS 29.518 §6.2)
// ============================================================================

/// Event types this AMF accepts a subscription for (TS 29.518 `AmfEventType`,
/// `TS29518_Namf_EventExposure.yaml:1513-1543`).
///
/// A SUBSET of the enumeration's 25 values, by design: the 13 absent ones
/// (`SUBSCRIPTION_TERMINATION`, `5GS_USER_STATE_REPORT`, the trends and measurement
/// reports, ...) need state this AMF does not hold, and accepting a subscription it can
/// never notify is what an event-exposure producer must not do.
///
/// # Where each accepted type fires (#397)
///
/// Ten of the twelve fire from a live NGAP or SBI path. Before #398 and #397 **none
/// did**: the three #74 counted as working all fired from `gmm_handler` functions whose
/// only callers are inside `mod tests`.
///
/// | type | production site |
/// |---|---|
/// | `LOCATION_REPORT` | `send_registration_accept`, `handle_service_request_nas` |
/// | `REGISTRATION_STATE_REPORT` | `send_registration_accept` (REGISTERED), `finish_deregistration` (DEREGISTERED) |
/// | `REACHABILITY_REPORT` | `handle_service_request_nas` |
/// | `ACCESS_TYPE_REPORT` | `send_registration_accept` |
/// | `CONNECTIVITY_STATE_REPORT` | `handle_service_request_nas`, `start_reachability_supervision` |
/// | `LOSS_OF_CONNECTIVITY` | `process_reachability_timers`, `finish_deregistration` |
/// | `COMMUNICATION_FAILURE_REPORT` | `handle_ue_context_release`, on an unexpected RAN Cause |
/// | `SUBSCRIPTION_ID_CHANGE` / `_ADDITION` | `handle_create_ue_context`, the §5.2.2.2.3.1 takeover |
///
/// # The two that do NOT fire, and why (ceilings, not omissions)
///
/// `PRESENCE_IN_AOI_REPORT` and `UES_IN_AREA_REPORT` need an area-of-interest /
/// presence-area model this AMF does not have in any form. `AmfEventReport.areaList`
/// (Table 6.2.6.2.5-1, `29518-k00.txt:21923-21940`) must report which subscribed AoI
/// the UE is *"currently IN / OUT / UNKNOWN"*, and for a PRA identifier naming a set it
/// must additionally report *"the additional PRA identifier of the actually individual
/// PRA(s)"* per TS 23.501 §5.6.11. `AmfEventArea`
/// (`TS29518_Namf_EventExposure.yaml:1011-1024`) is a choice of `PresenceInfo`,
/// `LadnInfo`, `SliceAreaRestrictionInfo`, `sNssai` or `nsiId` — none of which this AMF
/// stores or evaluates the UE against. `UES_IN_AREA_REPORT`'s `numberOfUes` (`:778`)
/// needs the same model plus a per-area count.
///
/// They remain ACCEPTED rather than removed from this list, for the reason `group_id`
/// subscriptions are accepted (#74 criterion 4): the subscription itself is conformant
/// and refusing it is a wrong 400. What is refused is fabricating the report. Deciding
/// the presence-area model is feature work in its own right and is filed as **#400**,
/// with the five open model questions stated.
///
/// `TIMEZONE_REPORT` is a THIRD kind of gap: the AMF holds no UE time zone at all.
/// `gmm_build.rs:983-985` sends `local_time_zone: None`,
/// `universal_time_and_local_time_zone: None` and `network_daylight_saving_time: None`
/// in every CONFIGURATION UPDATE COMMAND, and nothing ever parses one in — the time
/// zone is network-to-UE information (NITZ, TS 22.042), so there is no uplink IE to
/// learn it from. TS 23.501 §5.6.2 (`23501-k20.txt:11296`) has the AMF *"also provide
/// the corresponding UE Time Zone"* to the SMF, which confirms the AMF is meant to HOLD
/// one, but it comes from operator configuration keyed on the serving TAI and this tree
/// has no such configuration. §6.2's trigger is *"when AMF becomes aware of a time zone change of
/// the UE"*; with no value there is neither a value to report nor a change to detect.
/// Reporting the AMF HOST's zone would be a fabrication: the host is wherever the core
/// runs, not where the UE is.
const AMF_EVENT_TYPES: &[&str] = &[
    "LOCATION_REPORT",
    "PRESENCE_IN_AOI_REPORT",
    "TIMEZONE_REPORT",
    "ACCESS_TYPE_REPORT",
    "REGISTRATION_STATE_REPORT",
    "CONNECTIVITY_STATE_REPORT",
    "REACHABILITY_REPORT",
    "COMMUNICATION_FAILURE_REPORT",
    "UES_IN_AREA_REPORT",
    "SUBSCRIPTION_ID_CHANGE",
    "SUBSCRIPTION_ID_ADDITION",
    "LOSS_OF_CONNECTIVITY",
];

/// Rebuild the AmfEventSubscription JSON echo from the stored subscription
fn subscription_echo_json(sub: &EventSubscription) -> Value {
    let mut subscription = json!({
        "eventList": sub.event_types.iter()
            .map(|t| json!({"type": t}))
            .collect::<Vec<_>>(),
        "eventNotifyUri": sub.notify_uri,
        "notifyCorrelationId": sub.notify_correlation_id,
        "nfId": sub.nf_id,
    });
    if let Some(supi) = &sub.supi {
        subscription["supi"] = json!(supi);
    }
    // #74 criterion 4: the echo returns every targeting key the consumer sent, not
    // just the SUPI the AMF may have resolved from it. A consumer that subscribed
    // by GPSI must see its GPSI back, or it cannot correlate the resource with the
    // request it made.
    if let Some(gpsi) = &sub.gpsi {
        subscription["gpsi"] = json!(gpsi);
    }
    if let Some(pei) = &sub.pei {
        subscription["pei"] = json!(pei);
    }
    if let Some(group_id) = &sub.group_id {
        subscription["groupId"] = json!(group_id);
    }
    // #397: the subscription-change callback round-trips too. A consumer that gave
    // the AMF a separate endpoint for subscription-ID changes must see it back, for
    // the same reason the GPSI echo exists — it is how the consumer confirms the
    // created resource matches the request it made.
    if let Some(uri) = &sub.subs_change_notify_uri {
        subscription["subsChangeNotifyUri"] = json!(uri);
    }
    if let Some(id) = &sub.subs_change_notify_correlation_id {
        subscription["subsChangeNotifyCorrelationId"] = json!(id);
    }
    if sub.any_ue {
        subscription["anyUE"] = json!(true);
    }
    if let Some(expiry) = sub.expiry {
        subscription["options"] = json!({
            "trigger": "CONTINUOUS",
            "expiry": system_time_to_rfc3339(expiry),
        });
    }
    subscription
}

/// POST /namf-evts/v1/subscriptions — Namf_EventExposure_Subscribe
/// (TS 29.518 §5.3.2.2.2). Persists the subscription in the AMF context and
/// returns 201 with Location + AmfCreatedEventSubscription.
fn handle_event_subscription_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };
    let Some(subscription) = body.get("subscription") else {
        return mandatory_ie_missing("subscription");
    };

    // Mandatory attributes per TS 29.518 Table 6.2.6.2.3-1
    let Some(notify_uri) = subscription.get("eventNotifyUri").and_then(Value::as_str) else {
        return mandatory_ie_missing("subscription.eventNotifyUri");
    };
    let Some(correlation_id) = subscription
        .get("notifyCorrelationId")
        .and_then(Value::as_str)
    else {
        return mandatory_ie_missing("subscription.notifyCorrelationId");
    };
    let Some(nf_id) = subscription.get("nfId").and_then(Value::as_str) else {
        return mandatory_ie_missing("subscription.nfId");
    };
    let Some(event_list) = subscription.get("eventList").and_then(Value::as_array) else {
        return mandatory_ie_missing("subscription.eventList");
    };
    if event_list.is_empty() {
        return mandatory_ie_incorrect("subscription.eventList", "must contain at least one event");
    }
    if parse_http_uri(notify_uri).is_none() {
        return mandatory_ie_incorrect("subscription.eventNotifyUri", "not a valid HTTP URI");
    }

    let mut event_types = Vec::new();
    let mut immediate_types = Vec::new();
    for event in event_list {
        let Some(event_type) = event.get("type").and_then(Value::as_str) else {
            return mandatory_ie_missing("subscription.eventList[].type");
        };
        if !AMF_EVENT_TYPES.contains(&event_type) {
            return mandatory_ie_incorrect(
                "subscription.eventList[].type",
                &format!("unknown event type '{event_type}'"),
            );
        }
        if event
            .get("immediateFlag")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            immediate_types.push(event_type.to_string());
        }
        event_types.push(event_type.to_string());
    }

    // Targeting (#74 criterion 4, TS 29.518 §5.3.2.2.2).
    //
    // `AmfEventSubscription` (TS29518_Namf_EventExposure.yaml:534-594) offers FIVE
    // target keys — `supi` (:553), `groupId` (:555), `gpsi` (:577), `pei` (:579)
    // and `anyUE` (:581) — and its `required` list (:589-593) carries none of
    // them, only `eventList`/`eventNotifyUri`/`notifyCorrelationId`/`nfId`. So a
    // subscription keyed solely by GPSI is conformant.
    //
    // This guard used to read `supi`/`anyUE` ONLY and answer
    // `MANDATORY_IE_MISSING` for the other three, which refused a conformant
    // NWDAF/AF outright. Now `MANDATORY_IE_MISSING` is returned only when the
    // request names NO target at all — which is still a defect worth refusing,
    // because the AMF would otherwise have to guess whose events to report.
    let mut supi = subscription
        .get("supi")
        .and_then(Value::as_str)
        .map(String::from);
    let gpsi = subscription
        .get("gpsi")
        .and_then(Value::as_str)
        .map(String::from);
    let pei = subscription
        .get("pei")
        .and_then(Value::as_str)
        .map(String::from);
    let group_id = subscription
        .get("groupId")
        .and_then(Value::as_str)
        .map(String::from);
    let any_ue = subscription
        .get("anyUE")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if supi.is_none() && gpsi.is_none() && pei.is_none() && group_id.is_none() && !any_ue {
        return mandatory_ie_missing(
            "subscription.supi, subscription.gpsi, subscription.pei, \
             subscription.groupId or subscription.anyUE",
        );
    }

    // Resolve an external identity to the internal one when the UE is known, so a
    // GPSI/PEI subscription keys exactly the way a SUPI one does and the existing
    // SUPI-keyed fire points reach it with no change.
    //
    // An UNRESOLVABLE gpsi/pei is accepted and stored unresolved rather than
    // refused: nothing in §5.3.2.2 conditions a subscription on the target being
    // registered at subscribe time, so refusing it would swap one wrong rejection
    // for another. `event_subscriptions_matching_ue` matches on the external
    // identity too, so such a subscription starts firing once the UE registers.
    let ctx = amf_self();
    if supi.is_none() {
        if let Ok(guard) = ctx.read() {
            let resolved = gpsi
                .as_deref()
                .and_then(|g| guard.amf_ue_find_by_gpsi(g))
                .or_else(|| pei.as_deref().and_then(|p| guard.amf_ue_find_by_pei(p)));
            if let Some(ue) = resolved {
                supi = ue.supi.clone();
            }
        }
    }

    // #397: the subscription-change callback pair (`subsChangeNotifyUri`,
    // `subsChangeNotifyCorrelationId`, yaml:549-551). Optional, and validated only
    // for well-formedness — §6.2.6.2.2 makes neither conditional on anything the AMF
    // can check at subscribe time.
    //
    // A present-but-unusable URI is refused rather than stored, because storing it
    // would produce a subscription whose SUBSCRIPTION_ID_CHANGE notification can
    // never be delivered, and the consumer would have no way to learn that.
    let subs_change_notify_uri = subscription
        .get("subsChangeNotifyUri")
        .and_then(Value::as_str)
        .map(String::from);
    if let Some(uri) = &subs_change_notify_uri {
        if parse_http_uri(uri).is_none() {
            return mandatory_ie_incorrect(
                "subscription.subsChangeNotifyUri",
                "not a valid HTTP URI",
            );
        }
    }
    let subs_change_notify_correlation_id = subscription
        .get("subsChangeNotifyCorrelationId")
        .and_then(Value::as_str)
        .map(String::from);

    // Optional expiry: AmfEventMode.expiry (options) or top-level expiry
    let expiry_str = subscription
        .pointer("/options/expiry")
        .or_else(|| subscription.get("expiry"))
        .and_then(Value::as_str);
    let expiry = match expiry_str {
        Some(s) => match rfc3339_to_system_time(s) {
            Some(t) => Some(t),
            None => {
                return mandatory_ie_incorrect("subscription.options.expiry", "invalid DateTime");
            }
        },
        None => None,
    };

    let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
    let sub = EventSubscription {
        subscription_id: subscription_id.clone(),
        notify_uri: notify_uri.to_string(),
        notify_correlation_id: correlation_id.to_string(),
        nf_id: nf_id.to_string(),
        event_types,
        supi: supi.clone(),
        gpsi,
        pei,
        group_id,
        any_ue,
        expiry,
        subs_change_notify_uri,
        subs_change_notify_correlation_id,
    };

    // Immediate reports for events with immediateFlag (current state)
    let report_list = build_immediate_reports(&immediate_types, supi.as_deref());

    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        // Opportunistic cleanup of expired subscriptions
        guard.event_subscriptions_remove_expired();
        if !guard.event_subscription_add(sub.clone()) {
            return send_error(
                500,
                "Internal Server Error",
                "subscription ID collision",
                None,
            );
        }
    }

    log::info!(
        "Event subscription created: id={subscription_id}, events={:?}, notifyUri={notify_uri}",
        sub.event_types
    );

    let mut response_body = json!({
        "subscription": subscription_echo_json(&sub),
        "subscriptionId": subscription_id,
    });
    if !report_list.is_empty() {
        response_body["reportList"] = json!(report_list);
    }

    let location = format!("/namf-evts/v1/subscriptions/{subscription_id}");
    match SbiResponse::with_status(201).with_json_body(&response_body) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// Build immediate event reports for the subscribed UE's current state
fn build_immediate_reports(immediate_types: &[String], supi: Option<&str>) -> Vec<Value> {
    let Some(supi) = supi else {
        return Vec::new();
    };
    let Some(ue) = find_ue_by_context_id(supi) else {
        return Vec::new();
    };
    immediate_types
        .iter()
        .filter_map(|event_type| {
            let extra = match event_type.as_str() {
                "LOCATION_REPORT" => json!({ "location": nr_location_json(&ue) }),
                "REGISTRATION_STATE_REPORT" => json!({
                    "rmInfoList": [{ "rmState": "REGISTERED", "accessType": "3GPP_ACCESS" }]
                }),
                "REACHABILITY_REPORT" => {
                    let reachable = ue_ran_context(&ue).is_some();
                    json!({ "reachability": if reachable { "REACHABLE" } else { "UNREACHABLE" } })
                }
                "CONNECTIVITY_STATE_REPORT" => {
                    let connected = ue_ran_context(&ue).is_some();
                    json!({
                        "cmInfoList": [{
                            "cmState": if connected { "CONNECTED" } else { "IDLE" },
                            "accessType": "3GPP_ACCESS"
                        }]
                    })
                }
                _ => return None,
            };
            Some(build_event_report(event_type, Some(supi), extra))
        })
        .collect()
}

/// PATCH /namf-evts/v1/subscriptions/{subscriptionId} —
/// Namf_EventExposure_Subscribe (modify). Accepts the
/// AmfUpdateEventSubscriptionItem array form (op/path/value); only
/// `replace` of eventNotifyUri, eventList and options/expiry is supported.
fn handle_event_subscription_modify(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let ctx = amf_self();
    let existing = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.event_subscription_find(subscription_id)
    };
    let Some(mut sub) = existing else {
        return send_error(
            404,
            "Not Found",
            &format!("Subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };

    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };
    let Some(items) = body.as_array() else {
        return malformed_body();
    };

    for item in items {
        let op = item.get("op").and_then(Value::as_str).unwrap_or("");
        let path = item.get("path").and_then(Value::as_str).unwrap_or("");
        let value = item.get("value");
        match (op, path) {
            ("replace", "/subscription/eventNotifyUri") => {
                let Some(uri) = value.and_then(Value::as_str) else {
                    return mandatory_ie_incorrect("value", "eventNotifyUri must be a string");
                };
                if parse_http_uri(uri).is_none() {
                    return mandatory_ie_incorrect("value", "not a valid HTTP URI");
                }
                sub.notify_uri = uri.to_string();
            }
            ("replace", "/subscription/eventList") => {
                let Some(list) = value.and_then(Value::as_array) else {
                    return mandatory_ie_incorrect("value", "eventList must be an array");
                };
                let mut event_types = Vec::new();
                for event in list {
                    let Some(t) = event.get("type").and_then(Value::as_str) else {
                        return mandatory_ie_missing("value[].type");
                    };
                    if !AMF_EVENT_TYPES.contains(&t) {
                        return mandatory_ie_incorrect("value[].type", "unknown event type");
                    }
                    event_types.push(t.to_string());
                }
                if event_types.is_empty() {
                    return mandatory_ie_incorrect("value", "eventList must not be empty");
                }
                sub.event_types = event_types;
            }
            ("replace", "/subscription/options/expiry") => {
                let Some(expiry) = value
                    .and_then(Value::as_str)
                    .and_then(rfc3339_to_system_time)
                else {
                    return mandatory_ie_incorrect("value", "invalid DateTime");
                };
                sub.expiry = Some(expiry);
            }
            _ => {
                return mandatory_ie_incorrect(
                    "op/path",
                    &format!("unsupported patch item op='{op}' path='{path}'"),
                );
            }
        }
    }

    let updated = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.event_subscription_update(sub.clone())
    };
    if !updated {
        return send_error(
            404,
            "Not Found",
            &format!("Subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    }

    let response_body = json!({ "subscription": subscription_echo_json(&sub) });
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// DELETE /namf-evts/v1/subscriptions/{subscriptionId} —
/// Namf_EventExposure_Unsubscribe (TS 29.518 §5.3.2.3). 204 on success,
/// 404 when the subscription does not exist.
fn handle_event_subscription_delete(subscription_id: &str) -> SbiResponse {
    let ctx = amf_self();
    let removed = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.event_subscription_remove(subscription_id)
    };
    match removed {
        Some(_) => {
            log::info!("Event subscription removed: {subscription_id}");
            SbiResponse::no_content()
        }
        None => send_error(
            404,
            "Not Found",
            &format!("Subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// Namf_EventExposure — notification delivery (TS 29.518 §6.2.5.2)
// ============================================================================

/// Build a notification SBI client with bounded connect/request timeouts
fn notify_client(host: &str, port: u16) -> SbiClient {
    let config = nextgcore_sbi::security::sbi_peer_client_config(host, port)
        .with_connect_timeout(std::time::Duration::from_secs(NOTIFY_CONNECT_TIMEOUT_SECS))
        .with_request_timeout(std::time::Duration::from_secs(NOTIFY_REQUEST_TIMEOUT_SECS));
    SbiClient::new(config)
}

/// Parse an absolute http/https URI into (host, port, path)
pub(crate) fn parse_http_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(rest) = uri.strip_prefix("https://") {
        (443u16, rest)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        (80u16, rest)
    } else {
        return None;
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if host_port.is_empty() {
        return None;
    }
    match host_port.rsplit_once(':') {
        Some((host, port_str)) => {
            let port: u16 = port_str.parse().ok()?;
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), port, path))
        }
        None => Some((host_port.to_string(), default_port, path)),
    }
}

/// Build a single AmfEventReport (TS 29.518 §6.2.6.2.5). `extra` carries the
/// event-specific attributes (location, rmInfoList, reachability, ...).
fn build_event_report(event_type: &str, supi: Option<&str>, extra: Value) -> Value {
    let mut report = json!({
        "type": event_type,
        "state": { "active": true },
        "timeStamp": rfc3339_now(),
    });
    if let Some(supi) = supi {
        report["supi"] = json!(supi);
    }
    if let Value::Object(extra_map) = extra {
        if let Value::Object(report_map) = &mut report {
            for (k, v) in extra_map {
                report_map.insert(k, v);
            }
        }
    }
    report
}

/// POST one AmfEventNotification to a subscriber's notify URI with bounded
/// timeouts. Returns Err on any delivery failure.
async fn deliver_event_notification(sub: EventSubscription, report: Value) -> Result<(), String> {
    let (host, port, path) =
        parse_http_uri(&sub.notify_uri).ok_or_else(|| format!("bad URI {}", sub.notify_uri))?;

    let body = json!({
        "notifyCorrelationId": sub.notify_correlation_id,
        "subsChangeNotifyCorrelationId": Value::Null,
        "reportList": [report],
    });
    // Strip the null field (serde_json keeps explicit nulls)
    let mut body = body;
    if let Value::Object(map) = &mut body {
        map.remove("subsChangeNotifyCorrelationId");
    }

    let client = notify_client(&host, port);

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("notify POST to {} failed: {e}", sub.notify_uri))?;

    if response.is_success() {
        log::debug!(
            "Event notification delivered: sub={}, status={}",
            sub.subscription_id,
            response.status
        );
        Ok(())
    } else {
        Err(format!(
            "notify POST to {} returned {}",
            sub.notify_uri, response.status
        ))
    }
}

/// Fire an AMF event: collect matching subscriptions (expired ones are
/// skipped and swept) and deliver one notification POST per subscriber on
/// background tasks. Safe to call from sync code; outside a tokio runtime
/// the event is dropped with a debug log.
pub fn fire_amf_event(event_type: &str, supi: Option<&str>, extra: Value) {
    fire_amf_event_for(event_type, supi, None, None, extra);
}

/// Fire an AMF event, matching on every identity the reported UE carries (#74).
///
/// [`fire_amf_event`] keys on the SUPI alone. Since a subscription may now be
/// targeted by `gpsi`/`pei` (TS29518_Namf_EventExposure.yaml:577, :579), a SUPI-only
/// match would leave those subscriptions stored and never delivered. The report also
/// carries the GPSI and PEI, per Table 6.2.6.2.5-1 (`29518-k00.txt:21951`: `gpsi`
/// "shall be present if available"; `:21963`: `pei` "may be included").
pub fn fire_amf_event_for(
    event_type: &str,
    supi: Option<&str>,
    gpsi: Option<&str>,
    pei: Option<&str>,
    extra: Value,
) {
    let ctx = amf_self();
    let subs = {
        let Ok(guard) = ctx.read() else {
            return;
        };
        guard.event_subscriptions_remove_expired();
        guard.event_subscriptions_matching_ue(event_type, supi, gpsi, pei)
    };
    if subs.is_empty() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("fire_amf_event({event_type}): no tokio runtime, skipping delivery");
        return;
    };
    let mut report = build_event_report(event_type, supi, extra);
    if let Some(gpsi) = gpsi {
        report["gpsi"] = json!(gpsi);
    }
    if let Some(pei) = pei {
        report["pei"] = json!(pei);
    }
    for sub in subs {
        let report = report.clone();
        let sub_id = sub.subscription_id.clone();
        handle.spawn(async move {
            if let Err(e) = deliver_event_notification(sub, report).await {
                log::warn!("Event notification delivery failed (sub={sub_id}): {e}");
            }
        });
    }
}

/// Fire an AMF event for a UE, passing every identity it carries.
fn fire_ue_event(ue: &AmfUe, event_type: &str, extra: Value) {
    fire_amf_event_for(
        event_type,
        ue.supi.as_deref(),
        ue.gpsi.as_deref(),
        ue.pei.as_deref(),
        extra,
    );
}

/// Fire a LOCATION_REPORT for the UE's current TAI/NCGI
pub fn fire_location_report(ue: &AmfUe) {
    fire_ue_event(
        ue,
        "LOCATION_REPORT",
        json!({ "location": nr_location_json(ue) }),
    );
}

/// Fire a REGISTRATION_STATE_REPORT (REGISTERED / DEREGISTERED)
pub fn fire_registration_state_report(ue: &AmfUe, registered: bool) {
    fire_ue_event(
        ue,
        "REGISTRATION_STATE_REPORT",
        json!({
            "rmInfoList": [{
                "rmState": if registered { "REGISTERED" } else { "DEREGISTERED" },
                "accessType": "3GPP_ACCESS",
            }]
        }),
    );
}

/// Fire a REACHABILITY_REPORT (REACHABLE / UNREACHABLE)
pub fn fire_reachability_report(ue: &AmfUe, reachable: bool) {
    fire_ue_event(
        ue,
        "REACHABILITY_REPORT",
        json!({ "reachability": if reachable { "REACHABLE" } else { "UNREACHABLE" } }),
    );
}

/// Fire a CONNECTIVITY_STATE_REPORT (CM-CONNECTED / CM-IDLE), #74 criterion 5.
///
/// TS 29.518 §6.2 (`29518-k00.txt:24011`): *"A NF subscribes to this event to
/// receive the current connection management state of a UE... and report for
/// updated connection management state of a UE... when AMF becomes aware of a
/// connection management state change of the UE."*
///
/// The CM state is exactly what the AMF already derives for the immediate-report
/// path (`build_immediate_reports`: CM-CONNECTED iff a live RAN UE context
/// exists), so the same two values are reported at the two transitions the AMF
/// genuinely observes: Service Request (IDLE→CONNECTED) and N1 release
/// (CONNECTED→IDLE).
pub fn fire_connectivity_state_report(ue: &AmfUe, connected: bool) {
    fire_ue_event(
        ue,
        "CONNECTIVITY_STATE_REPORT",
        json!({
            "cmInfoList": [{
                "cmState": if connected { "CONNECTED" } else { "IDLE" },
                "accessType": "3GPP_ACCESS",
            }]
        }),
    );
}

/// Fire an ACCESS_TYPE_REPORT for the access the UE is reachable over,
/// #74 criterion 5.
///
/// TS 29.518 §6.2 (`29518-k00.txt:23991`): the consumer receives *"the current
/// access type(s) of a UE... and updated access type(s)... when AMF becomes aware
/// of the access type change of the UE."* Fired at registration, which is where
/// the AMF learns the access type for a UE it did not previously serve.
pub fn fire_access_type_report(ue: &AmfUe, access_type: &str) {
    fire_ue_event(
        ue,
        "ACCESS_TYPE_REPORT",
        json!({ "accessTypeList": [access_type] }),
    );
}

/// Fire a LOSS_OF_CONNECTIVITY report, #74 criterion 5.
///
/// TS 29.518 §6.2 (`29518-k00.txt:24089`) names the triggers exactly: *"when AMF
/// detects that a target UE is no longer reachable for either signalling or user
/// plane communication. Such condition is identified when Mobile Reachable timer
/// expires in the AMF (see TS 23.501), when the UE detaches and when AMF
/// deregisters from UDM for an active UE."*
///
/// The mobile-reachable expiry is the trigger wired here, because it is the one
/// this AMF already detects: `ngap_path::process_reachability_timers` advances
/// `ReachabilityPhase::MobileReachable` on the same poll as the retransmission
/// timers. `lossOfConnectReason` is the TS 29.518 `LossOfConnectivityReason`;
/// `MAX_DETECTION_TIME_EXPIRED` is the value for that trigger.
pub fn fire_loss_of_connectivity(ue: &AmfUe, reason: &str) {
    fire_ue_event(
        ue,
        "LOSS_OF_CONNECTIVITY",
        json!({ "lossOfConnectReason": reason }),
    );
}

/// Fire a `COMMUNICATION_FAILURE_REPORT` for a RAN-detected connection release
/// (#397).
///
/// TS 29.518 §6.2 (`29518-k00.txt:24032-24037`): the consumer receives *"the
/// Communication failure report of a UE or group of UEs or any UE"*, and
/// `29518-k00.txt:5126-5131` says when: *"when the AMF becomes aware of a RAN or NAS
/// failure event. This event implements the 'Communication failure' event in table
/// 4.15.3.1-1 of TS 23.502, which is an unexpected termination of the
/// communication."* That table's own row (`23502-k20.txt:28570-28577`) names the
/// detector and the mechanism: *"This event is detected when RAN or NAS level failure
/// is detected based on connection release and it identifies RAN/NAS release code"*,
/// with the AMF as the detecting NF.
///
/// A `UEContextReleaseRequest` from the gNB IS that: the RAN, not the AMF, decided to
/// tear the UE's signalling connection down, and it carries the Cause saying why.
///
/// # Why `ranReleaseCode`, and why only for an UNEXPECTED cause
///
/// `CommunicationFailure` (Table 6.2.6.2.11-1, `29518-k00.txt:22479-22485`) defines
/// `ranReleaseCode` as an `NgApCause` holding *"the decimal value of the NG AP cause
/// code values as specified in TS 38.413"* — group and value, both `required`
/// (`TS29571_CommonData.yaml:2562-2564`). The NGAP Cause is already decoded into
/// `UeContextReleaseRequest.cause` by `nextgcore_ngap::parser` and was simply
/// discarded; it is the real release code, not a placeholder.
///
/// `nasReleaseCode` is NOT set: its pattern is `^(MM|SM)-[0-9]{1,3}$`
/// (`:22465-22477`), a 5GMM/5GSM cause, and a RAN-initiated release carries no NAS
/// cause at all. Inventing one would report a NAS failure that did not happen.
///
/// The caller decides whether the cause is a FAILURE — see
/// `ngap_path::handle_ue_context_release`. A normal release is not "an unexpected
/// termination of the communication", so reporting one would tell a consumer a
/// failure occurred every time a UE went idle.
pub fn fire_communication_failure(ue: &AmfUe, cause_group: u8, cause_value: i64) {
    fire_ue_event(
        ue,
        "COMMUNICATION_FAILURE_REPORT",
        json!({
            "commFailure": {
                "ranReleaseCode": { "group": cause_group, "value": cause_value },
            }
        }),
    );
}

/// Fire a `SUBSCRIPTION_ID_CHANGE` or `SUBSCRIPTION_ID_ADDITION` to a
/// subscription's `subsChangeNotifyUri` (#397).
///
/// # These are not subscribable events
///
/// TS 29.518 §6.2 says of both that *"This event needs no explicit subscription
/// form an NF service consumer"* (`29518-k00.txt:24052-24053`, `:24069-24070`). They
/// are therefore NOT matched against `event_types` the way every other emitter is —
/// no consumer ever lists them in an `eventList`, so a match would find nothing.
/// They fire for a subscription whose `subsChangeNotifyUri` is set, whatever that
/// subscription was for.
///
/// # The trigger
///
/// Table 6.2.6.2.5-1's `subscriptionId` row (`29518-k00.txt:21886-21911`) gives the
/// only trigger: the IE *"shall be included when the event notification is for
/// informing the creation of a subscription Id at the AMF during mobility of a UE
/// across AMFs"*, with `SUBSCRIPTION_ID_CHANGE` *"when the AMF creates a subscription
/// Id for a UE specific event subscription"* and `SUBSCRIPTION_ID_ADDITION` *"when
/// the AMF creates a subscription Id for a group Id specific event subscription"*,
/// both *"during mobility registration and handover procedures involving an AMF
/// change"*. §5.2.2.2.3.1 (`:2769-2772`) is where that happens: the target AMF shall
/// *"for each created event subscription, allocate a new subscription Id... and if
/// allocated send the new subscription Id to the notification endpoint for informing
/// the subscription Id creation, along with the notification correlation Id for the
/// subscription Id change."*
///
/// # Shape of the notification
///
/// Two members differ from every other emitter, and both are conditional on THIS
/// being a subscription-ID notification:
///
/// - `reportList[].subscriptionId` carries *"the URI of the created subscription
///   resource at the AMF"* — an absolute URI per §6.2.3.3.2, not the bare ID.
/// - The correlation ID is `subsChangeNotifyCorrelationId` when the subscription
///   carried one, and `notifyCorrelationId` otherwise. Table 6.2.6.2.4-1
///   (`:21795-21833`) makes them mutually exclusive for exactly this case, so this
///   is not a matter of sending both.
///
/// `state.active` is `true` because Table 6.2.6.2.5-1 (`:21878-21881`) requires it:
/// *"This IE shall be set to 'TRUE' when subscriptionId IE is present."*
async fn deliver_subscription_id_change(
    sub: EventSubscription,
    event_type: &str,
    subscription_uri: String,
) -> Result<(), String> {
    let uri = sub
        .subs_change_notify_uri
        .as_deref()
        .ok_or("no subsChangeNotifyUri")?;
    let (host, port, path) = parse_http_uri(uri).ok_or_else(|| format!("bad URI {uri}"))?;

    let mut report = json!({
        "type": event_type,
        // Required TRUE whenever `subscriptionId` is present (Table 6.2.6.2.5-1).
        "state": { "active": true },
        "timeStamp": rfc3339_now(),
        "subscriptionId": subscription_uri,
    });
    // The UE the transferred subscription is for. `supi` is "present if available"
    // (`:21920`), and here it is: the subscription was created FOR this UE.
    if let Some(supi) = &sub.supi {
        report["supi"] = json!(supi);
    }

    // Exactly one correlation ID, chosen by Table 6.2.6.2.4-1, not both.
    let mut body = json!({ "reportList": [report] });
    match &sub.subs_change_notify_correlation_id {
        Some(id) => body["subsChangeNotifyCorrelationId"] = json!(id),
        None => body["notifyCorrelationId"] = json!(sub.notify_correlation_id),
    }

    let response = notify_client(&host, port)
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("subsChange POST to {uri} failed: {e}"))?;
    if response.is_success() {
        Ok(())
    } else {
        Err(format!(
            "subsChange POST to {uri} returned {}",
            response.status
        ))
    }
}

/// Take over a transferred event subscription and tell its consumer the new
/// subscription ID (TS 29.518 §5.2.2.2.3.1, #397).
///
/// Called from `handle_create_ue_context` for each entry of the transferred
/// `ueContext.eventSubscriptionList` (`TS29518_Namf_Communication.yaml:3050-3053`,
/// items `ExtAmfEventSubscription` = `AmfEventSubscription` plus additional info,
/// yaml:4049-4054). §5.2.2.2.3.1 requires the target AMF to *"create event
/// subscriptions for the UE specific events"* and then notify the consumer of the new
/// ID — which is the whole reason `SUBSCRIPTION_ID_CHANGE` exists.
///
/// # Why the event type is chosen by `groupId`, not by a flag
///
/// Table 6.2.6.2.5-1 ties the two types to the two cases §5.2.2.2.3.1 lists: a
/// UE-specific subscription is case a) and reports `SUBSCRIPTION_ID_CHANGE`; a group
/// subscription is case b) and reports `SUBSCRIPTION_ID_ADDITION`. `groupId` being
/// present IS which case this is, so there is nothing else to decide from.
///
/// Returns the number of subscriptions created, so the caller can log a count that
/// reflects what happened rather than what was offered.
fn take_over_transferred_event_subscriptions(
    ue_context_id: &str,
    supi: Option<&str>,
    ue_context: &Value,
) -> usize {
    let Some(list) = ue_context
        .get("eventSubscriptionList")
        .and_then(Value::as_array)
    else {
        return 0;
    };

    let ctx = amf_self();
    let mut created = 0usize;
    for entry in list {
        // `eventList`/`eventNotifyUri`/`notifyCorrelationId`/`nfId` are
        // `AmfEventSubscription`'s required members (yaml:589-593). An entry missing
        // one is skipped rather than defaulted: a subscription with no notify URI
        // could never be delivered to, and inventing one would point notifications at
        // an endpoint the consumer never gave.
        let Some(notify_uri) = entry.get("eventNotifyUri").and_then(Value::as_str) else {
            log::warn!(
                "[{ue_context_id}] transferred event subscription without `eventNotifyUri`: \
                 skipped (TS29518_Namf_Communication.yaml:589-593 makes it required)"
            );
            continue;
        };
        let Some(event_types) = entry.get("eventList").and_then(Value::as_array).map(|l| {
            l.iter()
                .filter_map(|e| e.get("type").and_then(Value::as_str).map(String::from))
                .collect::<Vec<_>>()
        }) else {
            log::warn!(
                "[{ue_context_id}] transferred event subscription without `eventList`: skipped"
            );
            continue;
        };
        if event_types.is_empty() {
            continue;
        }

        let group_id = entry
            .get("groupId")
            .and_then(Value::as_str)
            .map(String::from);
        // A NEW subscription ID, allocated by THIS AMF: that allocation is the event.
        // The NOTE at `29518-k00.txt:24100` permits reuse "if the mobility is between
        // AMFs of same AMF Set", but this AMF has no way to tell whether the source was
        // in its own set — `UeContextCreateData` carries no source GUAMI — so it
        // allocates, which is the unconditionally-correct branch.
        let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
        let sub = EventSubscription {
            subscription_id: subscription_id.clone(),
            notify_uri: notify_uri.to_string(),
            notify_correlation_id: entry
                .get("notifyCorrelationId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            nf_id: entry
                .get("nfId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            event_types,
            // The transferred subscription is for THIS UE. The `supi` the source sent
            // is preferred, but this AMF's own resolution wins when the source omitted
            // it, because the context it just created is what the reports will be about.
            supi: entry
                .get("supi")
                .and_then(Value::as_str)
                .map(String::from)
                .or_else(|| supi.map(String::from)),
            gpsi: entry.get("gpsi").and_then(Value::as_str).map(String::from),
            pei: entry.get("pei").and_then(Value::as_str).map(String::from),
            group_id: group_id.clone(),
            any_ue: entry.get("anyUE").and_then(Value::as_bool).unwrap_or(false),
            expiry: entry
                .pointer("/options/expiry")
                .and_then(Value::as_str)
                .and_then(rfc3339_to_system_time),
            subs_change_notify_uri: entry
                .get("subsChangeNotifyUri")
                .and_then(Value::as_str)
                .map(String::from),
            subs_change_notify_correlation_id: entry
                .get("subsChangeNotifyCorrelationId")
                .and_then(Value::as_str)
                .map(String::from),
        };

        let added = ctx
            .read()
            .map(|guard| guard.event_subscription_add(sub.clone()))
            .unwrap_or(false);
        if !added {
            log::warn!(
                "[{ue_context_id}] transferred event subscription {subscription_id} not stored"
            );
            continue;
        }
        created += 1;

        // §6.2.6.2.5: an ABSOLUTE URI to the created resource, per §6.2.3.3.2.
        let subscription_uri = format!("/namf-evts/v1/subscriptions/{subscription_id}");
        // Group subscription -> ADDITION, UE-specific -> CHANGE (Table 6.2.6.2.5-1).
        let event_type = if group_id.is_some() {
            "SUBSCRIPTION_ID_ADDITION"
        } else {
            "SUBSCRIPTION_ID_CHANGE"
        };

        // Only when the consumer gave a subscription-change endpoint. §6.2.5.2.1 has
        // this notification go to `subsChangeNotifyUri`, and a consumer that supplied
        // none did not ask to be told; posting the ID change to `eventNotifyUri`
        // instead would send a report for an event type that consumer never subscribed
        // to, down the channel it uses for the ones it did.
        if sub.subs_change_notify_uri.is_none() {
            log::debug!(
                "[{ue_context_id}] event subscription {subscription_id} created from the \
                 transferred context; no `subsChangeNotifyUri`, so no {event_type} is sent \
                 (TS 29.518 §6.2.5.2.1)"
            );
            continue;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            log::debug!("{event_type}: no tokio runtime, skipping delivery");
            continue;
        };
        log::info!(
            "[{ue_context_id}] {event_type}: subscription {subscription_id} created from the \
             transferred UE context (TS 29.518 §5.2.2.2.3.1)"
        );
        handle.spawn(async move {
            if let Err(e) = deliver_subscription_id_change(sub, event_type, subscription_uri).await
            {
                log::warn!("{event_type} delivery failed: {e}");
            }
        });
    }
    created
}

// ============================================================================
// Namf_Communication — N1N2MessageTransfer (TS 29.518 §5.2.2.3)
// ============================================================================

/// Map a TS 29.518 NgapIeType string onto the internal enum
fn parse_ngap_ie_type(s: &str) -> Option<NgapIeType> {
    match s {
        "PDU_RES_SETUP_REQ" => Some(NgapIeType::PduResSetupReq),
        "PDU_RES_MOD_REQ" => Some(NgapIeType::PduResModReq),
        "PDU_RES_REL_CMD" => Some(NgapIeType::PduResRelCmd),
        "PDU_RES_NTY" => Some(NgapIeType::PduResNotify),
        "PDU_RES_MOD_IND" => Some(NgapIeType::PduResModInd),
        // LCS positioning (TS 29.518 / TS 23.273): the LMF tags an NRPPa PDU
        // carried under n2InfoContainer.nrppaInfo with this ngapIeType.
        "NRPPA_PDU" => Some(NgapIeType::Nrppa),
        _ => None,
    }
}

/// Resolve a RefToBinaryData contentId against the multipart binary parts
fn find_binary_part(request: &SbiRequest, content_id: &str) -> Option<Vec<u8>> {
    request
        .http
        .parts
        .iter()
        .find(|p| p.content_id.as_deref() == Some(content_id))
        .map(|p| p.data.to_vec())
}

/// 504 N1N2MessageTransferError with cause UE_NOT_REACHABLE
/// (TS 29.518 Table 6.1.7.3-1) + asynchronous failure notification when
/// the consumer supplied n1n2FailureTxfNotifURI.
fn ue_not_reachable_error(ue_context_id: &str, failure_uri: Option<&str>) -> SbiResponse {
    if let Some(uri) = failure_uri {
        send_n1n2_failure_notification(
            uri.to_string(),
            "UE_NOT_REACHABLE",
            format!("/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"),
        );
    }
    let problem = ProblemDetails::with_status(504)
        .with_title("Gateway Timeout")
        .with_detail("UE is not reachable")
        .with_cause("UE_NOT_REACHABLE");
    let body = json!({ "error": problem });
    match SbiResponse::with_status(504).with_json_body(&body) {
        Ok(resp) => resp.with_header("content-type", "application/problem+json"),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// Send the N1N2MsgTxfrFailureNotification callback POST
/// (TS 29.518 §6.1.6.2.8: cause and n1n2MsgDataUri are both mandatory).
/// Fire-and-forget on a background task with bounded timeouts.
pub fn send_n1n2_failure_notification(notify_uri: String, cause: &str, n1n2_msg_data_uri: String) {
    let cause = cause.to_string();
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("N1N2 failure notification skipped (no tokio runtime)");
        return;
    };
    handle.spawn(async move {
        let Some((host, port, path)) = parse_http_uri(&notify_uri) else {
            log::warn!("Invalid n1n2FailureTxfNotifURI: {notify_uri}");
            return;
        };
        let body = json!({
            "cause": cause,
            "n1n2MsgDataUri": n1n2_msg_data_uri,
        });
        let client = notify_client(&host, port);
        match client.post_json(&path, &body).await {
            Ok(resp) if resp.is_success() => {
                log::info!("N1N2 failure notification delivered to {notify_uri}");
            }
            Ok(resp) => {
                log::warn!(
                    "N1N2 failure notification to {notify_uri} returned {}",
                    resp.status
                );
            }
            Err(e) => log::warn!("N1N2 failure notification to {notify_uri} failed: {e}"),
        }
    });
}

/// Content-Id of the binary NRPPa part inside an N2InfoNotify multipart body
/// (referenced from `n2InfoContainer.nrppaInfo.nrppaPdu.ngapData.contentId`).
pub(crate) const N2_INFO_NOTIFY_NRPPA_CONTENT_ID: &str = "nrppa";

/// Build the multipart Namf_Communication N2InfoNotify callback POST
/// (TS 29.518 §5.2.2.3.3, callback `{$request.body#/n2NotifyCallbackUri}` —
/// TS29518_Namf_Communication.yaml:1597-1661): jsonData is an
/// `N2InformationNotification` (yaml:2637-2670, `n2NotifySubscriptionId`
/// mandatory) with `n2InformationClass` "NRPPa" and the NRPPa payload as a
/// `binaryDataN2Information` part, Content-Id "nrppa", Content-Type
/// `application/vnd.3gpp.ngap`, carried **verbatim** (the AMF is a
/// transparent relay per TS 23.273 §6.11).
///
/// `nf_id` is the originating LMF NF-instance id echoed back from the NGAP
/// RoutingID (our downlink relay seeds the RoutingID from the transfer's
/// `nrppaInfo.nfId`, so a conformant gNB echo round-trips it); included as
/// `nrppaInfo.nfId` when it survives the echo as a UTF-8 string.
pub(crate) fn build_n2_info_notify_request(
    path: &str,
    n2_notify_subscription_id: &str,
    lcs_correlation_id: Option<&str>,
    nf_id: Option<&str>,
    nrppa_pdu: &[u8],
) -> Result<SbiRequest, serde_json::Error> {
    let mut notification = json!({
        "n2NotifySubscriptionId": n2_notify_subscription_id,
        "n2InfoContainer": {
            "n2InformationClass": "NRPPa",
            "nrppaInfo": {
                "nrppaPdu": {
                    "ngapIeType": "NRPPA_PDU",
                    "ngapData": { "contentId": N2_INFO_NOTIFY_NRPPA_CONTENT_ID },
                },
            },
        },
    });
    if let Some(nf_id) = nf_id {
        notification["n2InfoContainer"]["nrppaInfo"]["nfId"] = json!(nf_id);
    }
    if let Some(corr) = lcs_correlation_id {
        notification["lcsCorrelationId"] = json!(corr);
    }
    Ok(SbiRequest::post(path)
        .with_json_body(&notification)?
        .with_part(SbiPart::with_content(
            N2_INFO_NOTIFY_NRPPA_CONTENT_ID,
            nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
            bytes::Bytes::copy_from_slice(nrppa_pdu),
        )))
}

/// POST an N2InfoNotify to the LMF's registered `n2NotifyCallbackUri`
/// (TS 29.518 §5.2.2.3.3) relaying an uplink NRPPa PDU (TS 38.413 §8.15.3 /
/// §8.15.5). Fire-and-forget on a background task with bounded timeouts,
/// mirroring [`send_n1n2_failure_notification`] — a notify failure is logged,
/// never surfaced toward the gNB.
pub fn send_n2_info_notify(
    callback_uri: String,
    n2_notify_subscription_id: String,
    lcs_correlation_id: Option<String>,
    nf_id: Option<String>,
    nrppa_pdu: Vec<u8>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("N2InfoNotify skipped (no tokio runtime)");
        return;
    };
    handle.spawn(async move {
        let Some((host, port, path)) = parse_http_uri(&callback_uri) else {
            log::warn!("Invalid n2NotifyCallbackUri: {callback_uri}");
            return;
        };
        let request = match build_n2_info_notify_request(
            &path,
            &n2_notify_subscription_id,
            lcs_correlation_id.as_deref(),
            nf_id.as_deref(),
            &nrppa_pdu,
        ) {
            Ok(req) => req,
            Err(e) => {
                log::warn!("N2InfoNotify body build failed: {e}");
                return;
            }
        };
        let client = notify_client(&host, port);
        match client.send_request(request).await {
            Ok(resp) if resp.is_success() => {
                log::info!(
                    "N2InfoNotify delivered to {callback_uri} \
                     (sub={n2_notify_subscription_id})"
                );
            }
            Ok(resp) => {
                log::warn!(
                    "N2InfoNotify to {callback_uri} returned {} \
                     (sub={n2_notify_subscription_id})",
                    resp.status
                );
            }
            Err(e) => log::warn!("N2InfoNotify to {callback_uri} failed: {e}"),
        }
    });
}

/// Content-Id of the binary PWS part inside a non-UE `n2InfoNotify` multipart
/// body (referenced from
/// `n2InfoContainer.pwsInfo.pwsContainer.ngapData.contentId`).
pub(crate) const NON_UE_N2_INFO_NOTIFY_PWS_CONTENT_ID: &str = "pws";

/// Build the multipart Namf_Communication **NonUeN2InfoNotify** callback POST
/// (#399, TS 29.518 §5.2.2.4.4, callback `onN2InfoNotify` on
/// `{$request.body#/n2NotifyCallbackUri}` —
/// `TS29518_Namf_Communication.yaml:2041-2060`): jsonData is an
/// `N2InformationNotification` (`yaml:2637-2679`, `n2NotifySubscriptionId`
/// mandatory) whose `n2InfoContainer` carries the PWS class and a
/// `PwsInformation`, with the NG-RAN's own PDU as a `binaryDataN2Information`
/// part.
///
/// ## The RAN's bytes go out verbatim
///
/// §6.1.6.4.3.3 (`29518-k00.txt:19069-19077`) *permits* the AMF to aggregate the
/// area lists from several nodes and "transfer the ASN.1 (re-)encoded" result. It
/// is a "may", and it is declined: re-encoding through a partial model drops every
/// IE the gNB sent that this build does not represent — the same reasoning that
/// made the forward relay verbatim in #396/#401, applied in the notification
/// direction. §5.2.2.4.4.1 (`:4416`) and §5.2.2.4.4.3 (`:4478`) both provide for
/// "one (or more) NonUEN2InfoNotify request(s)", so one notify per responding node
/// is conformant.
///
/// ## `bcEmptyAreaList` is the one thing the AMF composes
///
/// Because the spec orders it in the imperative, not the permissive
/// (§5.2.2.4.4.3, `:4468-4471`): "If the NG-RAN node(s) have responded **without**
/// the Broadcast Completed Area List IE then the AMF **shall** include the NG-RAN
/// node ID(s) in "bcEmptyAreaList" attribute in the request body." Both inputs are
/// honestly held — whether the list was present comes from decoding the PDU, and
/// which node answered comes from the SCTP association (a WRITE-REPLACE WARNING
/// RESPONSE carries no Global RAN Node ID at all, `38413-j30.txt:15916-15939`).
///
/// `ran_node_id` is the `GlobalRanNodeId` JSON of the responding node
/// (`N2InformationNotification.ranNodeId`, `yaml:2659`).
pub(crate) fn build_non_ue_n2_info_notify_request(
    path: &str,
    n2_notify_subscription_id: &str,
    n2_information_class: &str,
    message_identifier: u16,
    serial_number: u16,
    ran_node_id: &Value,
    bc_empty_area_list: bool,
    nf_id: Option<&str>,
    notif_correlation_id: Option<&str>,
    ngap_pdu: &[u8],
) -> Result<SbiRequest, serde_json::Error> {
    // `messageIdentifier`, `serialNumber` and `pwsContainer` are the three
    // required members of `PwsInformation` (`yaml:3298-3300`).
    let mut pws_info = json!({
        "messageIdentifier": message_identifier,
        "serialNumber": serial_number,
        "pwsContainer": {
            "ngapMessageType": ngap_pdu.get(1).copied().unwrap_or(0),
            "ngapData": { "contentId": NON_UE_N2_INFO_NOTIFY_PWS_CONTENT_ID },
        },
    });
    if bc_empty_area_list {
        // `minItems: 1` (`yaml:3287`), so this is only ever set with the node in
        // it — an empty array would be a schema violation dressed as information.
        pws_info["bcEmptyAreaList"] = json!([ran_node_id]);
    }
    if let Some(nf_id) = nf_id {
        pws_info["nfId"] = json!(nf_id);
    }
    let mut notification = json!({
        "n2NotifySubscriptionId": n2_notify_subscription_id,
        "n2InfoContainer": {
            "n2InformationClass": n2_information_class,
            "pwsInfo": pws_info,
        },
        "ranNodeId": ran_node_id,
    });
    if let Some(corr) = notif_correlation_id {
        notification["notifCorrelationId"] = json!(corr);
    }
    Ok(SbiRequest::post(path)
        .with_json_body(&notification)?
        .with_part(SbiPart::with_content(
            NON_UE_N2_INFO_NOTIFY_PWS_CONTENT_ID,
            nextgcore_sbi::constants::content_type::APPLICATION_NGAP,
            bytes::Bytes::copy_from_slice(ngap_pdu),
        )))
}

/// POST a NonUeN2InfoNotify to a PWS consumer's registered
/// `n2NotifyCallbackUri` (#399, TS 29.518 §5.2.2.4.4). Fire-and-forget on a
/// background task with bounded timeouts, exactly like [`send_n2_info_notify`] —
/// a notify failure is logged and never surfaced toward the gNB, which is not
/// waiting on it (both the responses and the indications are class-2/terminated
/// NGAP procedures at this point).
///
/// §5.2.2.4.4.1 step 2a (`29518-k00.txt:4415-4417`) makes the success answer
/// "204 No Content", so any 2xx is accepted and anything else is a WARN.
#[allow(clippy::too_many_arguments)]
pub fn send_non_ue_n2_info_notify(
    callback_uri: String,
    n2_notify_subscription_id: String,
    n2_information_class: String,
    message_identifier: u16,
    serial_number: u16,
    ran_node_id: Value,
    bc_empty_area_list: bool,
    nf_id: Option<String>,
    notif_correlation_id: Option<String>,
    ngap_pdu: Vec<u8>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("NonUeN2InfoNotify skipped (no tokio runtime)");
        return;
    };
    handle.spawn(async move {
        let Some((host, port, path)) = parse_http_uri(&callback_uri) else {
            log::warn!("Invalid n2NotifyCallbackUri: {callback_uri}");
            return;
        };
        let request = match build_non_ue_n2_info_notify_request(
            &path,
            &n2_notify_subscription_id,
            &n2_information_class,
            message_identifier,
            serial_number,
            &ran_node_id,
            bc_empty_area_list,
            nf_id.as_deref(),
            notif_correlation_id.as_deref(),
            &ngap_pdu,
        ) {
            Ok(req) => req,
            Err(e) => {
                log::warn!("NonUeN2InfoNotify body build failed: {e}");
                return;
            }
        };
        let client = notify_client(&host, port);
        match client.send_request(request).await {
            Ok(resp) if resp.is_success() => {
                log::info!(
                    "NonUeN2InfoNotify ({n2_information_class}) delivered to {callback_uri} \
                     (sub={n2_notify_subscription_id} \
                     messageIdentifier={message_identifier:#06x} \
                     serialNumber={serial_number:#06x})"
                );
            }
            Ok(resp) => {
                log::warn!(
                    "NonUeN2InfoNotify to {callback_uri} returned {} \
                     (sub={n2_notify_subscription_id})",
                    resp.status
                );
            }
            Err(e) => log::warn!("NonUeN2InfoNotify to {callback_uri} failed: {e}"),
        }
    });
}

/// Render a `GlobalRanNodeId` (TS 29.571, `TS29571_CommonData.yaml:2859-2884`)
/// for an NG-RAN node the AMF knows by PLMN + gNB ID.
///
/// `GNbId` requires BOTH `bitLength` and `gNBValue` (`:2911-2913`), and
/// `gNBValue` is hex with an even number of nibbles, 6 to 8 characters
/// (`^[A-Fa-f0-9]{6,8}$`). A 22-to-32-bit ID needs 6 nibbles below 24 bits and 8
/// at or above, so the width is derived from the bit length rather than fixed —
/// padding to 8 always would claim a 32-bit ID for a 22-bit node.
pub(crate) fn global_ran_node_id_json(
    plmn: &crate::context::PlmnId,
    gnb_id: u32,
    gnb_id_len: u8,
) -> Value {
    let nibbles = if gnb_id_len > 24 { 8 } else { 6 };
    json!({
        "plmnId": { "mcc": plmn.mcc(), "mnc": plmn.mnc() },
        "gNbId": {
            "bitLength": gnb_id_len,
            "gNBValue": format!("{gnb_id:0width$X}", width = nibbles),
        },
    })
}

/// Content-Id of the binary N1 (LPP) part inside an N1MessageNotify multipart
/// body (referenced from `n1MessageContainer.n1MessageContent.contentId`).
pub(crate) const N1_MESSAGE_NOTIFY_CONTENT_ID: &str = "n1-lpp";

/// Build the multipart Namf_Communication N1MessageNotify callback POST
/// (Wave-6 A4; TS 29.518 §5.2.2.4, callback `{$request.body#/n1NotifyCallbackUri}`
/// — TS29518_Namf_Communication.yaml:1540-1596): jsonData is an
/// `N1MessageNotification` (yaml:2708-2725, `n1MessageContainer` mandatory)
/// with `n1MessageClass` (e.g. "LPP") and the uplink N1 payload as a
/// `binaryDataN1Message` part, Content-Id "n1-lpp", Content-Type
/// `application/vnd.3gpp.5gnas`, carried **verbatim** (the AMF is a transparent
/// relay for the uplink LPP leg per TS 23.273 §6.11.2).
///
/// `lcs_correlation_id` (TS 29.572 CorrelationID) is the LCS correlation the
/// consuming LMF keys its pending positioning session on (specs/29518-j60.txt:
/// 12361 — "If the N1 message notified is for LCS procedures ... may include an
/// LCS correlation identifier"). `supi` is included when known.
///
/// `pub` (not `pub(crate)`) so peer NF crates can drive the real producer body
/// in-process for strict-peer tests (Wave-6 H1 lib-targetization).
pub fn build_n1_message_notify_request(
    path: &str,
    n1_notify_subscription_id: Option<&str>,
    n1_message_class: &str,
    lcs_correlation_id: Option<&str>,
    supi: Option<&str>,
    n1_payload: &[u8],
) -> Result<SbiRequest, serde_json::Error> {
    let mut notification = json!({
        "n1MessageContainer": {
            "n1MessageClass": n1_message_class,
            "n1MessageContent": { "contentId": N1_MESSAGE_NOTIFY_CONTENT_ID },
        },
    });
    if let Some(id) = n1_notify_subscription_id {
        notification["n1NotifySubscriptionId"] = json!(id);
    }
    if let Some(corr) = lcs_correlation_id {
        notification["lcsCorrelationId"] = json!(corr);
    }
    if let Some(supi) = supi {
        notification["supi"] = json!(supi);
    }
    Ok(SbiRequest::post(path)
        .with_json_body(&notification)?
        .with_part(SbiPart::with_content(
            N1_MESSAGE_NOTIFY_CONTENT_ID,
            nextgcore_sbi::constants::content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(n1_payload),
        )))
}

/// POST an N1MessageNotify to the LMF's registered `n1NotifyCallbackUri`
/// (Wave-6 A4; TS 29.518 §5.2.2.4) relaying an uplink N1 (LPP) payload verbatim
/// (TS 23.273 §6.11.2). Fire-and-forget on a background task with bounded
/// timeouts, mirroring [`send_n2_info_notify`] — a notify failure is logged,
/// never surfaced toward the UE.
pub fn send_n1_message_notify(
    callback_uri: String,
    n1_notify_subscription_id: Option<String>,
    n1_message_class: String,
    lcs_correlation_id: Option<String>,
    supi: Option<String>,
    n1_payload: Vec<u8>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("N1MessageNotify skipped (no tokio runtime)");
        return;
    };
    handle.spawn(async move {
        let Some((host, port, path)) = parse_http_uri(&callback_uri) else {
            log::warn!("Invalid n1NotifyCallbackUri: {callback_uri}");
            return;
        };
        let request = match build_n1_message_notify_request(
            &path,
            n1_notify_subscription_id.as_deref(),
            &n1_message_class,
            lcs_correlation_id.as_deref(),
            supi.as_deref(),
            &n1_payload,
        ) {
            Ok(req) => req,
            Err(e) => {
                log::warn!("N1MessageNotify body build failed: {e}");
                return;
            }
        };
        let client = notify_client(&host, port);
        match client.send_request(request).await {
            Ok(resp) if resp.is_success() => {
                log::info!("N1MessageNotify delivered to {callback_uri}");
            }
            Ok(resp) => {
                log::warn!("N1MessageNotify to {callback_uri} returned {}", resp.status)
            }
            Err(e) => log::warn!("N1MessageNotify to {callback_uri} failed: {e}"),
        }
    });
}

/// LCS positioning relay (TS 23.273 §7): build the downlink wire messages for
/// an LMF-originated `Namf_Communication_N1N2MessageTransfer` carrying NRPPa
/// (→ serving gNB over N2) and/or LPP (→ UE over N1). Returns `Some(response)`
/// when `body` is a positioning transfer (so the caller skips SM handling), or
/// `None` when it is an ordinary SM transfer.
///
/// A positioning transfer is identified structurally: it carries
/// `n1MessageClass == "LPP"` and/or an `n2InfoContainer.nrppaInfo`, and never an
/// `smInfo` / `pduSessionId`. This guard runs before the SM-centric logic so
/// that path is completely untouched (strictly additive).
///
/// Egress is performed by the NGAP server task (it owns the SCTP associations +
/// the per-UE NAS security context): this handler validates the request, models
/// the downlink, and enqueues it on `positioning_dl_queue`; the NGAP pump
/// (`process_positioning_downlinks`) resolves the serving association and
/// delivers. The opaque NRPPa/LPP payloads are carried verbatim — the AMF is a
/// transparent relay. The `Nlmf` uplink callback (UE/gNB→LMF) is `lmfd-07`.
fn try_positioning_relay(
    ue_context_id: &str,
    ue: &AmfUe,
    request: &SbiRequest,
    body: &Value,
) -> Option<SbiResponse> {
    let is_lpp = body
        .pointer("/n1MessageContainer/n1MessageClass")
        .and_then(Value::as_str)
        == Some("LPP");
    let nrppa_info = body.pointer("/n2InfoContainer/nrppaInfo");
    if !is_lpp && nrppa_info.is_none() {
        return None; // not a positioning transfer — fall through to SM handling
    }

    // Both LPP→UE and UE-associated NRPPa→gNB require the UE to be CM-CONNECTED.
    if ue_ran_context(ue).is_none() {
        return Some(ue_not_reachable_error(ue_context_id, None));
    }

    // Fallback correlation record (TS 29.518 N1N2MessageTransferReqData
    // lcsCorrelationId / servingLMFIdentification, yaml:2771-2774): capture
    // the originating LMF onto the UE context so the uplink leg can route a
    // UE/gNB reply back even without an explicit N1N2 subscription
    // (last-writer-wins).
    if let Some(corr) = body.get("lcsCorrelationId").and_then(Value::as_str) {
        let record = LcsCorrelationRecord {
            lcs_correlation_id: corr.to_string(),
            serving_lmf_identification: body
                .get("servingLMFIdentification")
                .and_then(Value::as_str)
                .map(String::from),
        };
        if let Ok(context) = amf_self().read() {
            context.lcs_correlation_set(ue_context_id, record);
        }
    }

    let mut downlinks: Vec<PendingPositioningDl> = Vec::new();

    // LPP → UE (N1, DL NAS Transport, payload container type LPP).
    if is_lpp {
        let Some(lpp_pdu) = body
            .pointer("/n1MessageContainer/n1MessageContent/contentId")
            .and_then(Value::as_str)
            .and_then(|cid| find_binary_part(request, cid))
        else {
            return Some(mandatory_ie_incorrect(
                "n1MessageContainer.n1MessageContent.contentId",
                "no binary part for the LPP payload",
            ));
        };
        downlinks.push(PendingPositioningDl {
            amf_ue_ngap_id: ue.id,
            kind: PositioningDlKind::LppToUe { lpp_pdu },
        });
    }

    // NRPPa → serving gNB (N2, UE-associated NRPPa transport, NGAP procedure 8).
    if let Some(nrppa) = nrppa_info {
        let ie_ok = nrppa
            .pointer("/nrppaPdu/ngapIeType")
            .and_then(Value::as_str)
            .and_then(parse_ngap_ie_type)
            == Some(NgapIeType::Nrppa);
        if !ie_ok {
            return Some(mandatory_ie_incorrect(
                "n2InfoContainer.nrppaInfo.nrppaPdu.ngapIeType",
                "expected NRPPA_PDU",
            ));
        }
        let Some(nrppa_pdu) = nrppa
            .pointer("/nrppaPdu/ngapData/contentId")
            .and_then(Value::as_str)
            .and_then(|cid| find_binary_part(request, cid))
        else {
            return Some(mandatory_ie_incorrect(
                "n2InfoContainer.nrppaInfo.nrppaPdu.ngapData.contentId",
                "no binary part for the NRPPa PDU",
            ));
        };
        // The originating LMF id seeds the NGAP RoutingID so the gNB's uplink
        // reply routes back to the right LMF (opaque echo for our relay).
        let routing_id = nrppa
            .get("nfId")
            .and_then(Value::as_str)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        downlinks.push(PendingPositioningDl {
            amf_ue_ngap_id: ue.id,
            kind: PositioningDlKind::NrppaToGnb {
                routing_id,
                nrppa_pdu,
            },
        });
    }

    // Enqueue for NGAP-task egress (TS 23.273). The pump resolves the serving
    // SCTP association from its per-UE state and delivers over N2/N1.
    if let Ok(context) = amf_self().read() {
        let n = downlinks.len();
        for dl in downlinks {
            context.positioning_dl_add(dl);
        }
        log::info!("[{ue_context_id}] LCS: enqueued {n} positioning downlink(s) for egress");
    }

    let rsp = json!({ "cause": "N1_N2_TRANSFER_INITIATED" });
    Some(match SbiResponse::ok().with_json_body(&rsp) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    })
}

/// UPDP (UE policy) downlink relay — Wave-6 E5 (TS 29.525 §4.2.2.2: the PCF
/// delivers UE policies via `Namf_Communication_N1N2MessageTransfer`;
/// TS 29.518 N1MessageClass `UPDP`, TS29518_Namf_Communication.yaml:4453).
/// Returns `Some(response)` when `body` is a UPDP transfer (so the caller
/// skips SM handling), or `None` otherwise.
///
/// A UPDP transfer is identified structurally, same guard style as
/// [`try_positioning_relay`]: `n1MessageClass == "UPDP"`. The UPDP payload
/// (e.g. MANAGE UE POLICY COMMAND, TS 24.501 Annex D) is opaque to the AMF
/// and relayed verbatim as a DL NAS TRANSPORT with payload container type
/// "UE policy container" (0x05, TS 24.501 §9.11.3.40 / §5.4.5).
///
/// Fail-closed: a UE that is not CM-CONNECTED gets 504 UE_NOT_REACHABLE
/// (honoring `n1n2FailureTxfNotifURI`), and a missing binary part gets 400 —
/// never the pre-E5 fake-success 200-and-drop. Egress is performed by the
/// NGAP server task via `positioning_dl_queue` /
/// `process_positioning_downlinks`, exactly like the LPP leg.
fn try_ue_policy_relay(
    ue_context_id: &str,
    ue: &AmfUe,
    request: &SbiRequest,
    body: &Value,
) -> Option<SbiResponse> {
    let is_updp = body
        .pointer("/n1MessageContainer/n1MessageClass")
        .and_then(Value::as_str)
        == Some("UPDP");
    if !is_updp {
        return None; // not a UE-policy transfer — fall through
    }

    let failure_uri = body.get("n1n2FailureTxfNotifURI").and_then(Value::as_str);

    // The N1 downlink needs a live NAS signalling connection (CM-CONNECTED).
    if ue_ran_context(ue).is_none() {
        return Some(ue_not_reachable_error(ue_context_id, failure_uri));
    }

    let Some(updp_pdu) = body
        .pointer("/n1MessageContainer/n1MessageContent/contentId")
        .and_then(Value::as_str)
        .and_then(|cid| find_binary_part(request, cid))
    else {
        return Some(mandatory_ie_incorrect(
            "n1MessageContainer.n1MessageContent.contentId",
            "no binary part for the UPDP payload",
        ));
    };

    if let Ok(context) = amf_self().read() {
        context.positioning_dl_add(PendingPositioningDl {
            amf_ue_ngap_id: ue.id,
            kind: PositioningDlKind::UePolicyToUe { updp_pdu },
        });
        log::info!("[{ue_context_id}] UE policy: enqueued UPDP downlink for N1 egress");
    }

    let rsp = json!({ "cause": "N1_N2_TRANSFER_INITIATED" });
    Some(match SbiResponse::ok().with_json_body(&rsp) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    })
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages —
/// Namf_Communication_N1N2MessageTransfer (TS 29.518 §5.2.2.3.1).
pub fn handle_n1_n2_message_transfer_request(
    ue_context_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let n1_container = body.get("n1MessageContainer");
    let n2_container = body.get("n2InfoContainer");
    if n1_container.is_none() && n2_container.is_none() {
        // At least one of N1/N2 content must be present
        return mandatory_ie_missing("n1MessageContainer or n2InfoContainer");
    }

    // LCS positioning relay (TS 23.273): an LMF push of NRPPa (→gNB, N2) and/or
    // LPP (→UE, N1) carries no PDU session and no smInfo. Detect and handle it
    // up front so the SM-centric path below is completely untouched.
    if let Some(resp) = try_positioning_relay(ue_context_id, &ue, request, &body) {
        return resp;
    }

    // UPDP (UE policy) relay — Wave-6 E5 (TS 29.525 §4.2.2.2): a PCF push of
    // a UE-policy container (n1MessageClass "UPDP", no PDU session). Handled
    // up front, same pattern as the positioning relay, so the SM-centric path
    // below stays untouched.
    if let Some(resp) = try_ue_policy_relay(ue_context_id, &ue, request, &body) {
        return resp;
    }

    // N1 message: RefToBinaryData into the multipart binary parts
    let n1_message = match n1_container {
        Some(c) => {
            let Some(content_id) = c
                .pointer("/n1MessageContent/contentId")
                .and_then(Value::as_str)
            else {
                return mandatory_ie_missing("n1MessageContainer.n1MessageContent.contentId");
            };
            match find_binary_part(request, content_id) {
                Some(data) => Some(data),
                None => {
                    return mandatory_ie_incorrect(
                        "n1MessageContainer.n1MessageContent.contentId",
                        &format!("no binary part with contentId '{content_id}'"),
                    );
                }
            }
        }
        None => None,
    };

    // N2 info: ngapIeType + RefToBinaryData
    let mut sm_psi: Option<u8> = None;
    let n2_info = match n2_container {
        Some(c) => {
            let sm_info = c.get("smInfo");
            let Some(sm_info) = sm_info else {
                return mandatory_ie_missing("n2InfoContainer.smInfo");
            };
            sm_psi = sm_info
                .get("pduSessionId")
                .and_then(Value::as_u64)
                .and_then(|v| u8::try_from(v).ok());
            if sm_psi.is_none() {
                return mandatory_ie_missing("n2InfoContainer.smInfo.pduSessionId");
            }
            let Some(ie_type_str) = sm_info
                .pointer("/n2InfoContent/ngapIeType")
                .and_then(Value::as_str)
            else {
                return mandatory_ie_missing("n2InfoContainer.smInfo.n2InfoContent.ngapIeType");
            };
            let Some(ngap_ie_type) = parse_ngap_ie_type(ie_type_str) else {
                return mandatory_ie_incorrect(
                    "n2InfoContainer.smInfo.n2InfoContent.ngapIeType",
                    &format!("unknown value '{ie_type_str}'"),
                );
            };
            let ngap_data = sm_info
                .pointer("/n2InfoContent/ngapData/contentId")
                .and_then(Value::as_str)
                .and_then(|cid| find_binary_part(request, cid));
            Some(N2InfoContainer {
                ngap_ie_type,
                ngap_data,
            })
        }
        None => None,
    };

    let pdu_session_id = body
        .get("pduSessionId")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .or(sm_psi);
    let skip_ind = body
        .get("skipInd")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let failure_uri = body
        .get("n1n2FailureTxfNotifURI")
        .and_then(Value::as_str)
        .map(String::from);

    let ran_ue = ue_ran_context(&ue);

    // Pure N1 transfer without an SM context: LPP and UPDP are relayed by the
    // classful handlers above; any class remaining here has NO downlink
    // forwarding path yet. Wave-6 E5: name the dropped class in a WARN
    // instead of silently faking success (the 200 is kept this wave for
    // backward compatibility — the full fail-closed fix is WS-A scope).
    let Some(psi) = pdu_session_id else {
        return if ran_ue.is_some() {
            let class = body
                .pointer("/n1MessageContainer/n1MessageClass")
                .and_then(Value::as_str)
                .unwrap_or("<none>");
            log::warn!(
                "[{ue_context_id}] N1N2MessageTransfer with unhandled pure-N1 \
                 class '{class}' acknowledged (200) but NOT forwarded to the \
                 UE — no relay for this n1MessageClass"
            );
            let rsp = json!({ "cause": "N1_N2_TRANSFER_INITIATED" });
            match SbiResponse::ok().with_json_body(&rsp) {
                Ok(resp) => resp,
                Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
            }
        } else {
            ue_not_reachable_error(ue_context_id, failure_uri.as_deref())
        };
    };

    // Look up the session for this PSI
    let ctx = amf_self();
    let sess = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_find_by_psi(ue.id, psi)
    };
    let Some(mut sess) = sess else {
        return send_error(
            404,
            "Not Found",
            &format!("PDU session {psi} not found for UE '{ue_context_id}'"),
            Some("CONTEXT_NOT_FOUND"),
        );
    };

    let req_data = N1N2MessageTransferReqData {
        pdu_session_id: Some(psi),
        n1_message,
        n2_info,
        n1n2_failure_txf_notif_uri: failure_uri.clone(),
        skip_ind,
    };

    let result =
        namf_handler::handle_n1_n2_message_transfer(&ue, &mut sess, ran_ue.as_ref(), &req_data);

    // Persist any session mutations (paging state, release flags)
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_update(&sess);
    }

    match result {
        Ok(rsp) => match rsp.cause {
            N1N2MessageTransferCause::N1N2TransferInitiated => {
                let body = json!({ "cause": rsp.cause.as_str() });
                match SbiResponse::ok().with_json_body(&body) {
                    Ok(resp) => resp,
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                }
            }
            N1N2MessageTransferCause::AttemptingToReachUe => {
                // 202 Accepted with a Location pointing at the transfer
                // resource (TS 29.518 §5.2.2.3.1)
                let body = json!({ "cause": rsp.cause.as_str() });
                let location =
                    format!("/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages/{psi}");
                match SbiResponse::with_status(202).with_json_body(&body) {
                    Ok(resp) => resp.with_header("location", location),
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                }
            }
            N1N2MessageTransferCause::N1MsgNotTransferred
            | N1N2MessageTransferCause::N2MsgNotTransferred
            | N1N2MessageTransferCause::UeNotResponding
            | N1N2MessageTransferCause::UeNotReachable => {
                ue_not_reachable_error(ue_context_id, failure_uri.as_deref())
            }
            N1N2MessageTransferCause::TemporaryRejectRegistrationOngoing
            | N1N2MessageTransferCause::TemporaryRejectHandoverOngoing => {
                // 409 Conflict per TS 29.518 §5.2.2.3.1
                let problem = ProblemDetails::with_status(409)
                    .with_title("Conflict")
                    .with_detail("Temporary rejection, procedure ongoing")
                    .with_cause(rsp.cause.as_str());
                let body = json!({ "error": problem });
                match SbiResponse::with_status(409).with_json_body(&body) {
                    Ok(resp) => resp.with_header("content-type", "application/problem+json"),
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                }
            }
        },
        Err(namf_handler::NamfHandlerError::MissingField(f)) => mandatory_ie_missing(&f),
        Err(e) => send_error(
            500,
            "Internal Server Error",
            &format!("N1N2 transfer failed: {e:?}"),
            None,
        ),
    }
}

// ============================================================================
// Namf_Communication — N1N2MessageSubscribe / UnSubscribe
// (TS 29.518 §5.2.2.6/§5.2.2.7; TS 23.273 §6.11 — the LMF registers here for
// uplink LPP/NRPPa delivery)
// ============================================================================

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions —
/// Namf_Communication_N1N2MessageSubscribe (TS 29.518 §5.2.2.6,
/// UeN1N2InfoSubscriptionCreateData). Stores the consumer's per-UE uplink
/// notify callbacks and returns 201 with a Location header of the form
/// {apiRoot}/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions/{subscriptionId}
/// and a UeN1N2InfoSubscriptionCreatedData body ({n1n2NotifySubscriptionId}).
///
/// Fail-closed validation: at least one complete (class, callback URI) pair —
/// (n1MessageClass AND n1NotifyCallbackUri) or (n2InformationClass AND
/// n2NotifyCallbackUri) — must be present; a class without its callback URI
/// (or vice versa) is rejected 400 MANDATORY_IE_MISSING, never silently
/// accepted. Classes LPP/NRPPa are the consumers wired today; other classes
/// are stored opaquely (producers do exact-class lookups, so a class that was
/// never stored is never notified).
fn handle_n1n2_subscription_create(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    // The subscription targets an individual UE context (TS 29.518 §6.1.3.5)
    if find_ue_by_context_id(ue_context_id).is_none() {
        return context_not_found(ue_context_id);
    }
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let n1_message_class = body.get("n1MessageClass").and_then(Value::as_str);
    let n1_notify_callback_uri = body.get("n1NotifyCallbackUri").and_then(Value::as_str);
    let n2_information_class = body.get("n2InformationClass").and_then(Value::as_str);
    let n2_notify_callback_uri = body.get("n2NotifyCallbackUri").and_then(Value::as_str);

    // Reject half-pairs: a class with no callback URI is unusable and a
    // callback URI with no class would notify a class we never stored.
    if n1_message_class.is_some() && n1_notify_callback_uri.is_none() {
        return mandatory_ie_missing("n1NotifyCallbackUri");
    }
    if n1_notify_callback_uri.is_some() && n1_message_class.is_none() {
        return mandatory_ie_missing("n1MessageClass");
    }
    if n2_information_class.is_some() && n2_notify_callback_uri.is_none() {
        return mandatory_ie_missing("n2NotifyCallbackUri");
    }
    if n2_notify_callback_uri.is_some() && n2_information_class.is_none() {
        return mandatory_ie_missing("n2InformationClass");
    }
    // At least one complete pair must be present
    if n1_message_class.is_none() && n2_information_class.is_none() {
        return mandatory_ie_missing(
            "(n1MessageClass, n1NotifyCallbackUri) or (n2InformationClass, n2NotifyCallbackUri)",
        );
    }
    // Callback URIs must be resolvable HTTP URIs (we must be able to POST
    // N1MessageNotify / N2InfoNotify to them)
    if let Some(uri) = n1_notify_callback_uri {
        if parse_http_uri(uri).is_none() {
            return mandatory_ie_incorrect("n1NotifyCallbackUri", "not a valid HTTP URI");
        }
    }
    if let Some(uri) = n2_notify_callback_uri {
        if parse_http_uri(uri).is_none() {
            return mandatory_ie_incorrect("n2NotifyCallbackUri", "not a valid HTTP URI");
        }
    }

    let subscription_id = format!("n1n2sub-{}", uuid::Uuid::new_v4());
    let sub = UeN1N2InfoSubscription {
        subscription_id: subscription_id.clone(),
        n1_message_class: n1_message_class.map(String::from),
        n1_notify_callback_uri: n1_notify_callback_uri.map(String::from),
        n2_information_class: n2_information_class.map(String::from),
        n2_notify_callback_uri: n2_notify_callback_uri.map(String::from),
        lcs_correlation_id: body
            .get("lcsCorrelationId")
            .and_then(Value::as_str)
            .map(String::from),
    };

    let added = {
        let ctx = amf_self();
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.n1n2_subscription_add(ue_context_id, sub)
    };
    if !added {
        return send_error(
            500,
            "Internal Server Error",
            "subscription ID collision",
            None,
        );
    }

    log::info!(
        "[{ue_context_id}] N1N2 subscription created: id={subscription_id}, \
         n1Class={n1_message_class:?}, n2Class={n2_information_class:?}"
    );

    // UeN1N2InfoSubscriptionCreatedData (n1n2NotifySubscriptionId mandatory)
    let response_body = json!({ "n1n2NotifySubscriptionId": subscription_id });
    let location = format!(
        "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages/subscriptions/{subscription_id}"
    );
    match SbiResponse::with_status(201).with_json_body(&response_body) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// DELETE /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions/{subscriptionId}
/// — Namf_Communication_N1N2MessageUnSubscribe (TS 29.518 §5.2.2.7).
/// 204 on success, 404 CONTEXT_NOT_FOUND when the subscription does not exist.
fn handle_n1n2_subscription_delete(ue_context_id: &str, subscription_id: &str) -> SbiResponse {
    let ctx = amf_self();
    let removed = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.n1n2_subscription_remove(ue_context_id, subscription_id)
    };
    match removed {
        Some(_) => {
            log::info!("[{ue_context_id}] N1N2 subscription removed: {subscription_id}");
            SbiResponse::no_content()
        }
        None => send_error(
            404,
            "Not Found",
            &format!("N1N2 subscription '{subscription_id}' not found for UE '{ue_context_id}'"),
            Some("CONTEXT_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// Namf_Communication — UEContextTransfer (TS 29.518 §5.2.2.2.1)
// ============================================================================

/// Selected NAS integrity algorithm name (TS 29.571 IntegrityAlgorithm)
fn nia_name(alg: u8) -> &'static str {
    match alg {
        1 => "NIA1",
        2 => "NIA2",
        3 => "NIA3",
        _ => "NIA0",
    }
}

/// Selected NAS ciphering algorithm name (TS 29.571 CipheringAlgorithm)
fn nea_name(alg: u8) -> &'static str {
    match alg {
        1 => "NEA1",
        2 => "NEA2",
        3 => "NEA3",
        _ => "NEA0",
    }
}

/// Build the UeContext JSON for UEContextTransfer responses
/// (TS 29.518 Table 6.1.6.2.50-1)
fn build_ue_context_json(ue: &AmfUe, sessions: &[AmfSess]) -> Value {
    let mut ue_context = json!({
        "mmContextList": [{
            "accessType": "3GPP_ACCESS",
            "nasSecurityMode": {
                "integrityAlgorithm": nia_name(ue.selected_int_algorithm),
                "cipheringAlgorithm": nea_name(ue.selected_enc_algorithm),
            },
            "nasDownlinkCount": ue.dl_count,
            "nasUplinkCount": ue.ul_count,
            "ueSecurityCapability": format!(
                "{:02X}{:02X}{:02X}{:02X}",
                ue.ue_security_capability.ea,
                ue.ue_security_capability.ia,
                ue.ue_security_capability.eea,
                ue.ue_security_capability.eia,
            ),
        }],
    });
    if let Some(supi) = &ue.supi {
        ue_context["supi"] = json!(supi);
    }
    if let Some(pei) = &ue.pei {
        ue_context["pei"] = json!(pei);
    }
    if ue.ue_ambr.uplink > 0 || ue.ue_ambr.downlink > 0 {
        ue_context["ueAmbr"] = json!({
            "uplink": format!("{} bps", ue.ue_ambr.uplink),
            "downlink": format!("{} bps", ue.ue_ambr.downlink),
        });
    }

    // PduSessionContext mandatory attrs: pduSessionId, smContextRef, sNssai,
    // dnn, accessType. Sessions missing any of them are skipped (we never
    // invent values).
    let session_contexts: Vec<Value> = sessions
        .iter()
        .filter_map(|sess| {
            let sm_context_ref = sess.sm_context_ref.as_ref()?;
            let dnn = sess.dnn.as_ref()?;
            let mut snssai = json!({ "sst": sess.s_nssai.sst });
            if let Some(sd) = sess.s_nssai.sd {
                snssai["sd"] = json!(format!("{sd:06X}"));
            }
            Some(json!({
                "pduSessionId": sess.psi,
                "smContextRef": sm_context_ref,
                "sNssai": snssai,
                "dnn": dnn,
                "accessType": "3GPP_ACCESS",
            }))
        })
        .collect();
    if !session_contexts.is_empty() {
        ue_context["sessionContextList"] = json!(session_contexts);
    }

    ue_context
}

// ---------------------------------------------------------------------------
// EBIAssignment (TS 29.518 §6.1.6.2.5), issue #117
// ---------------------------------------------------------------------------

/// Parse one `Arp` (TS 29.571): all three members are `required`.
///
/// `priorityLevel` is range-checked (1..=15) because it is a plain integer with
/// declared bounds. The two pre-emption members are checked for PRESENCE only:
/// both are `anyOf[enum, string]` in TS 29.571, i.e. extensible, so rejecting an
/// unlisted value would refuse something the schema permits. They are stored and
/// echoed verbatim.
fn parse_arp(value: &Value, attr: &str) -> Result<EbiArp, Box<SbiResponse>> {
    let priority_level = match value.get("priorityLevel").and_then(Value::as_u64) {
        Some(p) if (1..=15).contains(&p) => p as u8,
        Some(p) => {
            return Err(Box::new(mandatory_ie_incorrect(
                &format!("{attr}.priorityLevel"),
                &format!("{p} is outside the ArpPriorityLevel range 1..=15"),
            )))
        }
        None => {
            return Err(Box::new(mandatory_ie_missing(&format!(
                "{attr}.priorityLevel"
            ))))
        }
    };
    let member = |key: &str| -> Result<String, Box<SbiResponse>> {
        match value.get(key).and_then(Value::as_str) {
            Some(v) if !v.is_empty() => Ok(v.to_string()),
            _ => Err(Box::new(mandatory_ie_missing(&format!("{attr}.{key}")))),
        }
    };
    Ok(EbiArp {
        priority_level,
        preempt_cap: member("preemptCap")?,
        preempt_vuln: member("preemptVuln")?,
    })
}

/// Serialise an `Arp` back onto the wire.
fn arp_json(arp: &EbiArp) -> Value {
    json!({
        "priorityLevel": arp.priority_level,
        "preemptCap": arp.preempt_cap,
        "preemptVuln": arp.preempt_vuln,
    })
}

/// Serialise an `EbiArpMapping` (TS 29.502): both members are `required`.
fn ebi_arp_mapping_json(assigned: &AssignedEbi) -> Value {
    json!({
        "epsBearerId": assigned.ebi,
        "arp": arp_json(&assigned.arp),
    })
}

/// The lowest free EBI for this UE, or `None` when all eleven are taken.
///
/// Lowest-free rather than round-robin so a released EBI is reused promptly: the
/// space is only eleven wide per UE, and an allocator that kept climbing would
/// exhaust it after eleven session lifetimes rather than after eleven concurrent
/// bearers.
fn next_free_ebi(assigned: &[AssignedEbi]) -> Option<u8> {
    EBI_ASSIGNABLE
        .clone()
        .find(|c| !assigned.iter().any(|a| a.ebi == *c))
}

/// Free every EPS bearer identity a UE holds, because the UE has deregistered
/// (issue #291). Returns how many were freed.
///
/// This is the backstop that makes an SMF-side miss recoverable, and it turned out
/// to be **necessary rather than merely nice**: #291 asked whether deregistration
/// already frees `assigned_ebis` because the context is dropped, and it does not.
/// Nothing in production calls `amf_ue_remove` — `grep` finds only tests and
/// `amf_ue_remove_all` (context teardown) — so an `AmfUe` outlives every
/// deregistration it experiences, and with it every EBI recorded on it. Without this
/// the eleven-wide space (TS 24.301 §9.3.2 reserves 0..=4) is only ever reclaimed by
/// the SMF's `releasedEbiList`, and any release that fails to reach the AMF leaks an
/// identity for the lifetime of the process.
///
/// Freeing them here is what TS 23.502 §4.2.2.3.2 implies rather than an invention:
/// deregistration releases every PDU session the UE has, and an EPS bearer identity
/// exists only to map one of those sessions into EPS. A UE with no sessions holding
/// EBIs is the state this restores.
pub(crate) fn release_all_ebis_on_deregistration(supi: &str) -> usize {
    let Some(mut ue) = find_ue_by_context_id(supi) else {
        return 0;
    };
    if ue.assigned_ebis.is_empty() {
        return 0;
    }
    let freed: Vec<u8> = ue.assigned_ebis.iter().map(|a| a.ebi).collect();
    ue.assigned_ebis.clear();
    if let Ok(guard) = amf_self().read() {
        guard.amf_ue_update(&ue);
    }
    log::info!(
        "[{supi}] deregistration freed EPS bearer identities {freed:?}: the UE holds no \
         PDU sessions, so it holds no EPS bearers"
    );
    freed.len()
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/assign-ebi —
/// Namf_Communication_EBIAssignment (TS 29.518 §6.1.6.2.5), issue #117.
///
/// TS 23.502 §4.11.1.4.1: for a PDU session that may be moved to EPS, the SMF
/// asks the AMF for an EPS Bearer Identity per QoS flow that needs one, supplying
/// that flow's ARP. The AMF owns the EBI space for the UE and answers with what it
/// allocated. Without this operation the two sides cannot agree on bearer
/// identities and no PDU session can be transferred to the EPC.
///
/// The order of operations is release → modify → assign, and it matters: a
/// request that releases EBI 5 and asks for one more must be able to hand 5 back
/// out. Doing it the other way round would fail an assignment that the release in
/// the same request had just made possible.
fn handle_assign_ebi(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(mut ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // `pduSessionId` is the ONLY required member of AssignEbiData.
    let pdu_session_id = match body.get("pduSessionId").and_then(Value::as_u64) {
        Some(id) if id <= 255 => id as u8,
        Some(id) => {
            return mandatory_ie_incorrect(
                "pduSessionId",
                &format!("{id} is outside the PduSessionId range 0..=255"),
            )
        }
        None => return mandatory_ie_missing("pduSessionId"),
    };

    // ---- releasedEbiList: free these before allocating anything ----
    let mut released: Vec<u8> = Vec::new();
    if let Some(list) = body.get("releasedEbiList").and_then(Value::as_array) {
        for entry in list {
            let Some(ebi) = entry.as_u64().filter(|e| *e <= 15).map(|e| e as u8) else {
                return mandatory_ie_incorrect(
                    "releasedEbiList",
                    "entries must be an EpsBearerId in 0..=15",
                );
            };
            // Release is idempotent: an EBI this AMF does not hold is reported as
            // released anyway, because the SMF's intent (it is not in use) is
            // already satisfied and a 4xx would strand the SMF's retry.
            ue.assigned_ebis.retain(|a| a.ebi != ebi);
            if !released.contains(&ebi) {
                released.push(ebi);
            }
        }
    }

    // ---- modifiedEbiList: re-ARP an EBI already held ----
    let mut modified: Vec<u8> = Vec::new();
    if let Some(list) = body.get("modifiedEbiList").and_then(Value::as_array) {
        for entry in list {
            let Some(ebi) = entry
                .get("epsBearerId")
                .and_then(Value::as_u64)
                .filter(|e| *e <= 15)
                .map(|e| e as u8)
            else {
                return mandatory_ie_missing("modifiedEbiList.epsBearerId");
            };
            let arp = match entry.get("arp") {
                Some(v) => match parse_arp(v, "modifiedEbiList.arp") {
                    Ok(arp) => arp,
                    Err(response) => return *response,
                },
                None => return mandatory_ie_missing("modifiedEbiList.arp"),
            };
            match ue.assigned_ebis.iter_mut().find(|a| a.ebi == ebi) {
                Some(existing) => {
                    existing.arp = arp;
                    existing.pdu_session_id = pdu_session_id;
                    if !modified.contains(&ebi) {
                        modified.push(ebi);
                    }
                }
                None => {
                    // Modifying an EBI this AMF never assigned is a state
                    // disagreement, not a malformed request. 409 is what the
                    // operation defines for exactly that, and answering 200 while
                    // silently ignoring the entry would leave the SMF believing an
                    // ARP change took effect.
                    return assign_ebi_error(
                        409,
                        "Conflict",
                        &format!("EBI {ebi} is not assigned to UE '{ue_context_id}'"),
                        "EBI_NOT_ASSIGNED",
                        pdu_session_id,
                        &[],
                    );
                }
            }
        }
    }

    // ---- arpList: one EBI per ARP, in the order given ----
    let mut assigned_now: Vec<AssignedEbi> = Vec::new();
    let mut failed: Vec<EbiArp> = Vec::new();
    if let Some(list) = body.get("arpList").and_then(Value::as_array) {
        for entry in list {
            let arp = match parse_arp(entry, "arpList") {
                Ok(arp) => arp,
                Err(response) => return *response,
            };
            match next_free_ebi(&ue.assigned_ebis) {
                Some(ebi) => {
                    let assignment = AssignedEbi {
                        ebi,
                        pdu_session_id,
                        arp,
                    };
                    ue.assigned_ebis.push(assignment.clone());
                    assigned_now.push(assignment);
                }
                // Exhaustion is a modelled outcome, not an error: eleven EBIs is
                // also the most EPS bearers a UE can have, so a twelfth request is
                // the SMF asking for something that cannot exist.
                None => failed.push(arp),
            }
        }
    }

    // Every ARP failed AND at least one was asked for: nothing was achieved, so
    // the operation failed. TS 29.518 defines 403 + AssignEbiError for this, which
    // carries the failed ARPs so the SMF knows which flows have no EBI.
    if !failed.is_empty() && assigned_now.is_empty() {
        return assign_ebi_error(
            403,
            "Forbidden",
            &format!(
                "no EBI is available for UE '{ue_context_id}': all {} assignable \
                 identities (TS 24.301 §9.3.2 reserves 0..=4) are in use",
                EBI_ASSIGNABLE.clone().count()
            ),
            "INSUFFICIENT_RESOURCES",
            pdu_session_id,
            &failed,
        );
    }

    // Persist before answering: an EBI reported as assigned and not recorded would
    // be handed out again on the next request, and two PDU sessions of one UE
    // would map to one EPS bearer.
    if let Ok(guard) = amf_self().read() {
        guard.amf_ue_update(&ue);
    }

    let mut response = json!({
        "pduSessionId": pdu_session_id,
        // `required` and `minItems: 0`, so an empty array is emitted rather than
        // the member being omitted.
        "assignedEbiList": assigned_now
            .iter()
            .map(ebi_arp_mapping_json)
            .collect::<Vec<_>>(),
    });
    // The remaining members are `minItems: 1`, so each is emitted only when
    // non-empty: an empty array would violate the schema it is declared under.
    if !failed.is_empty() {
        response["failedArpList"] = json!(failed.iter().map(arp_json).collect::<Vec<_>>());
    }
    if !released.is_empty() {
        response["releasedEbiList"] = json!(released);
    }
    if !modified.is_empty() {
        response["modifiedEbiList"] = json!(modified);
    }

    log::info!(
        "[{ue_context_id}] EBI assignment psi={pdu_session_id}: assigned {:?}, failed {}, \
         released {:?}, modified {:?} ({} of {} EBIs now held)",
        assigned_now.iter().map(|a| a.ebi).collect::<Vec<_>>(),
        failed.len(),
        released,
        modified,
        ue.assigned_ebis.len(),
        EBI_ASSIGNABLE.clone().count()
    );

    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// An `AssignEbiError` response: `error` + `failureDetails`, both `required`.
///
/// Note this is NOT `application/problem+json`: the operation defines its own
/// error body with the ProblemDetails nested under `error`, because the SMF needs
/// the failed ARP list alongside the problem to know which QoS flows are without
/// an EBI.
fn assign_ebi_error(
    status: u16,
    title: &str,
    detail: &str,
    cause: &str,
    pdu_session_id: u8,
    failed: &[EbiArp],
) -> SbiResponse {
    let mut failure_details = json!({ "pduSessionId": pdu_session_id });
    if !failed.is_empty() {
        failure_details["failedArpList"] = json!(failed.iter().map(arp_json).collect::<Vec<_>>());
    }
    let body = json!({
        "error": {
            "status": status,
            "title": title,
            "detail": detail,
            "cause": cause,
        },
        "failureDetails": failure_details,
    });
    SbiResponse::with_status(status)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(status))
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer —
/// Namf_Communication_UEContextTransfer (TS 29.518 §5.2.2.2.1).
fn handle_ue_context_transfer(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(mut ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attributes per TS 29.518 Table 6.1.6.2.7-1
    let Some(reason) = body.get("reason").and_then(Value::as_str) else {
        return mandatory_ie_missing("reason");
    };
    let Some(access_type) = body.get("accessType").and_then(Value::as_str) else {
        return mandatory_ie_missing("accessType");
    };
    if access_type != "3GPP_ACCESS" && access_type != "NON_3GPP_ACCESS" {
        return mandatory_ie_incorrect("accessType", &format!("unknown value '{access_type}'"));
    }
    match reason {
        "INIT_REG" | "MOBI_REG" | "MOBI_REG_UE_VALIDATED" => {}
        _ => {
            return mandatory_ie_incorrect("reason", &format!("unknown value '{reason}'"));
        }
    }

    if reason == "MOBI_REG" {
        // The integrity-protected Registration Request must be supplied so
        // the old AMF can verify it (TS 29.518 §5.2.2.2.1.1)
        let Some(reg_content_id) = body
            .pointer("/regRequest/n1MessageContent/contentId")
            .and_then(Value::as_str)
        else {
            return mandatory_ie_missing("regRequest (required for MOBI_REG)");
        };
        if find_binary_part(request, reg_content_id).is_none() {
            return mandatory_ie_incorrect(
                "regRequest.n1MessageContent.contentId",
                &format!("no binary part with contentId '{reg_content_id}'"),
            );
        }
        // Integrity check of the Registration Request against the stored
        // security context. Without a valid security context the transfer
        // is rejected with 403 INTEGRITY_CHECK_FAIL.
        if !ue.security_context_available || ue.mac_failed {
            return send_error(
                403,
                "Forbidden",
                "Registration Request integrity check failed",
                Some("INTEGRITY_CHECK_FAIL"),
            );
        }
    }

    // Collect this UE's sessions and mark the transfer state (old-AMF side)
    let ctx = amf_self();
    let sessions = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_list_for_ue(ue.id)
    };

    ue.amf_ue_context_transfer_state = UeContextTransferState::TransferOldAmf;
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.amf_ue_update(&ue);
    }

    let response_body = json!({
        "ueContext": build_ue_context_json(&ue, &sessions),
    });
    log::info!(
        "[{}] UEContextTransfer: reason={reason}, accessType={access_type}, {} sessions",
        ue_context_id,
        sessions.len()
    );
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer-update —
/// Namf_Communication_RegistrationStatusUpdate (TS 29.518 §5.2.2.2.2).
fn handle_registration_status_update(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(mut ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attribute per TS 29.518 Table 6.1.6.2.9-1
    let Some(transfer_status) = body.get("transferStatus").and_then(Value::as_str) else {
        return mandatory_ie_missing("transferStatus");
    };
    match transfer_status {
        "TRANSFERRED" | "NOT_TRANSFERRED" => {}
        _ => {
            return mandatory_ie_incorrect(
                "transferStatus",
                &format!("unknown value '{transfer_status}'"),
            );
        }
    }

    let ctx = amf_self();
    if transfer_status == "TRANSFERRED" {
        ue.amf_ue_context_transfer_state = UeContextTransferState::RegistrationStatusUpdateOldAmf;
        {
            let Ok(guard) = ctx.read() else {
                return send_error(500, "Internal Server Error", "context lock poisoned", None);
            };
            guard.amf_ue_update(&ue);
        }

        // toReleaseSessionList: PDU sessions the new AMF could not accept
        if let Some(to_release) = body.get("toReleaseSessionList").and_then(Value::as_array) {
            for psi_val in to_release {
                let Some(psi) = psi_val.as_u64().and_then(|v| u8::try_from(v).ok()) else {
                    continue;
                };
                // Copy out, mutate, write back — never hold a lock across
                // a second context call (the documented lock-order rule)
                let sess = {
                    let Ok(guard) = ctx.read() else {
                        break;
                    };
                    guard.sess_find_by_psi(ue.id, psi)
                };
                if let Some(mut sess) = sess {
                    sess.n1_released = true;
                    sess.n2_released = true;
                    if let Ok(guard) = ctx.read() {
                        guard.sess_update(&sess);
                    }
                }
            }
        }
    } else {
        // NOT_TRANSFERRED: registration at the new AMF failed; keep the
        // context and clear any transfer state.
        ue.amf_ue_context_transfer_state = UeContextTransferState::Initial;
        if let Ok(guard) = ctx.read() {
            guard.amf_ue_update(&ue);
        }
    }

    log::info!("[{ue_context_id}] RegistrationStatusUpdate: {transfer_status}");
    let response_body = json!({ "regStatusTransferComplete": true });
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

// ============================================================================
// Inter-AMF UE-context management — the PRODUCER side (TS 29.518 §5.2.2.2, #74)
//
// #352/PR #390 built the AMF as the CONSUMER of `UEContextTransfer`; these are the
// operations a peer AMF calls ON this one. The split is by direction, and #390's
// own boundary table records it.
//
// The UE context this AMF holds is identified by `ueContextId` throughout, resolved
// by `find_ue_by_context_id` — which #352 already taught to accept a
// `5g-guti-…` component, so these inherit that rather than re-adding it.
// ============================================================================

/// Apply a `UeContext` (TS 29.518 §6.1.6.2.2) onto a newly created AMF UE.
///
/// Only members this AMF has somewhere to put are read; the rest of the schema is
/// tolerated and ignored rather than rejected, because a source AMF sending more
/// than the target can use is conformant and refusing it would break the handover
/// over an IE the target does not need.
///
/// Returns the SUPI when the context carried one, so the caller can index it.
fn apply_ue_context_json(ue: &mut AmfUe, ue_context: &Value) -> Option<String> {
    let supi = ue_context
        .get("supi")
        .and_then(Value::as_str)
        .map(String::from);
    if let Some(supi) = &supi {
        ue.supi = Some(supi.clone());
    }
    if let Some(pei) = ue_context.get("pei").and_then(Value::as_str) {
        ue.pei = Some(pei.to_string());
    }
    if let Some(gpsi) = ue_context.get("gpsi").and_then(Value::as_str) {
        ue.gpsi = Some(gpsi.to_string());
    }
    supi
}

/// Record the PDU sessions a source AMF transferred, and say plainly which part of
/// the handover is NOT being completed.
///
/// TS 29.518 §5.2.2.2.3.1 has the source AMF carry a `pduSessionList`, and
/// TS 23.502 step 21 then has the target AMF drive `Nsmf_PDUSession_UpdateSMContext`
/// per SMF to move the N3 tunnels. PR #390 named this as the gap neither #352 nor
/// #74 claimed, and it lands here.
///
/// **It is recorded, not moved, and the reason is structural.** The endpoints an
/// `UpdateSMContext` would have to carry are exactly what this tree cannot obtain:
/// for `/relocate` they come over **N26** from the source MME (§5.2.2.2.5.1: "the NF
/// Service Consumer shall carry per PDU session the S-NSSAI for serving PLMN, the
/// MME Control Plane Address and the TEID"), and this AMF has no N26 leg at all —
/// `gmm_build.rs` advertises `Iwk26::WithoutN26Supported` to every UE for precisely
/// that reason. Calling the SMF with invented tunnel endpoints would point a live
/// user plane at an address nobody supplied, which is strictly worse than a
/// session recorded and a logged omission.
fn record_transferred_sessions(ue_id: u64, ue_context: &Value, ue_context_id: &str) -> usize {
    let Some(sessions) = ue_context
        .get("sessionContextList")
        .and_then(Value::as_array)
    else {
        return 0;
    };
    let ctx = amf_self();
    let mut recorded = 0usize;
    for session in sessions {
        let Some(psi) = session
            .get("pduSessionId")
            .and_then(Value::as_u64)
            .and_then(|v| u8::try_from(v).ok())
        else {
            continue;
        };
        let created = {
            let Ok(guard) = ctx.read() else { break };
            guard.sess_add(ue_id, psi)
        };
        let Some(mut sess) = created else { continue };
        if let Some(sm_ref) = session.get("smContextRef").and_then(Value::as_str) {
            sess.sm_context_ref = Some(sm_ref.to_string());
        }
        if let Some(dnn) = session.get("dnn").and_then(Value::as_str) {
            sess.dnn = Some(dnn.to_string());
        }
        if let Some(sst) = session.pointer("/sNssai/sst").and_then(Value::as_u64) {
            sess.s_nssai.sst = sst as u8;
        }
        if let Some(sd) = session
            .pointer("/sNssai/sd")
            .and_then(Value::as_str)
            .and_then(|s| u32::from_str_radix(s, 16).ok())
        {
            sess.s_nssai.sd = Some(sd);
        }
        if let Ok(guard) = ctx.read() {
            guard.sess_update(&sess);
        }
        recorded += 1;
    }
    if recorded > 0 {
        log::warn!(
            "[{ue_context_id}] {recorded} transferred PDU session(s) RECORDED but their N3 \
             tunnels are NOT re-established: TS 23.502 step 21 needs an \
             Nsmf_PDUSession_UpdateSMContext per SMF carrying the MME control-plane address \
             and TEID, which arrive over N26 (TS 29.518 §5.2.2.2.5.1) and this AMF has no \
             N26 leg"
        );
    }
    recorded
}

/// Create a UE context on THIS AMF, seeded from a peer's `UeContext`.
///
/// Shared by CreateUEContext (§5.2.2.2.3.1) and RelocateUEContext (§5.2.2.2.5.1):
/// both create an "Individual ueContext" resource on the target AMF from a
/// transferred context, and differ only in what else the request carries and which
/// members are mandatory.
///
/// The created context is INSERTED INTO THE LIVE STORE. Answering 201 and recording
/// nothing would pass a routing test and fail every real handover, so the insertion
/// is what makes the operation observable — and it is what the tests assert.
fn create_transferred_ue_context(
    ue_context_id: &str,
    ue_context: &Value,
) -> Result<(AmfUe, usize), Box<SbiResponse>> {
    let ctx = amf_self();

    // A RAN UE context is allocated alongside, because an AMF UE without one has no
    // AMF-UE-NGAP-ID and so cannot be addressed when the target NG-RAN starts
    // signalling for it. `gnb_id`/`ran_ue_ngap_id` are 0: the target gNB has not yet
    // sent anything for this UE, and inventing identifiers it never allocated would
    // put values on the wire that match no RAN state.
    let (mut ue, ran_ue_id) = {
        let Ok(guard) = ctx.read() else {
            return Err(Box::new(send_error(
                500,
                "Internal Server Error",
                "context lock poisoned",
                None,
            )));
        };
        let Some(ran_ue) = guard.ran_ue_add(0, 0) else {
            // TS 29.518 Table 6.1.3.2.3.1-3 lists 503 for a producer that cannot
            // take the context; refusing is what lets the source AMF keep it.
            return Err(Box::new(send_error(
                503,
                "Service Unavailable",
                "no capacity for a new RAN UE context",
                Some("INSUFFICIENT_RESOURCES"),
            )));
        };
        let Some(ue) = guard.amf_ue_add(ran_ue.id) else {
            guard.ran_ue_remove(ran_ue.id);
            return Err(Box::new(send_error(
                503,
                "Service Unavailable",
                "no capacity for a new UE context",
                Some("INSUFFICIENT_RESOURCES"),
            )));
        };
        (ue, ran_ue.id)
    };
    ue.ran_ue_id = ran_ue_id;
    // The new-AMF side of TS 29.518 §5.2.2.2.1 — the same state #352's consumer
    // records when it pulls a context in, reached here by the push direction.
    ue.amf_ue_context_transfer_state = UeContextTransferState::TransferNewAmf;

    let supi = apply_ue_context_json(&mut ue, ue_context);

    // Write back, then PUBLISH. `amf_ue_add` returned a CLONE and every field set
    // above is on that clone, so the write-back is not optional — the
    // discarded-clone bug has been found in this crate twice (#361/PR #389).
    //
    // `amf_ue_publish` is the load-bearing half, and #341's own doc comment says why:
    // "a UE that is only in `amf_ue_list` is invisible to the derived resolvers,
    // because those read the live store. Anything that creates a UE outside the NGAP
    // registration path -- a test fixture, an inter-AMF context transfer -- has to
    // come through here or it will 404 exactly as the pre-#341 code did." That names
    // this operation. Without it `find_ue_by_context_id` — which resolves through
    // `ue_store` — would answer 404 for a context this AMF had just created, and
    // CreateUEContext would be correct-but-unreachable.
    //
    // `ran_ue_ngap_id`/`association_id` are 0: no target gNB has signalled for this UE
    // yet, so there is no real association, and a fabricated one would name an SCTP
    // association that does not exist.
    {
        let Ok(guard) = ctx.read() else {
            return Err(Box::new(send_error(
                500,
                "Internal Server Error",
                "context lock poisoned",
                None,
            )));
        };
        guard.amf_ue_update(&ue);
        guard.amf_ue_publish(&ue, 0, 0);
    }
    let _ = &supi;

    let sessions = record_transferred_sessions(ue.id, ue_context, ue_context_id);
    Ok((ue, sessions))
}

/// PUT /namf-comm/v1/ue-contexts/{ueContextId} —
/// Namf_Communication_CreateUEContext (TS 29.518 §5.2.2.2.3.1).
///
/// A source AMF that cannot serve the UE creates its context on this AMF during
/// inter-NG-RAN N2 handover. Mandatory members are `ueContext`, `targetId`,
/// `sourceToTargetData` and `pduSessionList`
/// (`TS29518_Namf_Communication.yaml:3668-3672`).
///
/// On success: *"the target AMF shall respond with the status code '201 Created'...
/// together with a HTTP Location header to provide the location of a newly created
/// resource"* (`29518-k00.txt:2718-2721`), body a `UeContextCreatedData`, whose own
/// required members are `ueContext`, `targetToSourceData` and `pduSessionList`
/// (yaml:3701-3704).
///
/// `targetToSourceData` echoes the `sourceToTargetData` reference the consumer sent.
/// The genuine article is the Target-to-Source Transparent Container the TARGET
/// NG-RAN produces in a HandoverRequestAcknowledge, and no such exchange has
/// happened at this point in the procedure — so the alternative to echoing is
/// fabricating a RAN container, which would be decoded by the source gNB.
fn handle_create_ue_context(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let Some(ue_context) = body.get("ueContext") else {
        return mandatory_ie_missing("ueContext");
    };
    let Some(target_id) = body.get("targetId") else {
        return mandatory_ie_missing("targetId");
    };
    // `NgRanTargetId` requires both members (yaml:3774-3776).
    if target_id.get("ranNodeId").is_none() {
        return mandatory_ie_missing("targetId.ranNodeId");
    }
    if target_id.get("tai").is_none() {
        return mandatory_ie_missing("targetId.tai");
    }
    let Some(source_to_target) = body.get("sourceToTargetData").cloned() else {
        return mandatory_ie_missing("sourceToTargetData");
    };
    let Some(pdu_session_list) = body.get("pduSessionList").and_then(Value::as_array) else {
        return mandatory_ie_missing("pduSessionList");
    };
    // `minItems: 1` (yaml:3653).
    if pdu_session_list.is_empty() {
        return mandatory_ie_incorrect("pduSessionList", "must contain at least one entry");
    }

    // A context already held under this identity is a conflict, not a silent
    // overwrite: overwriting would discard the MM state of a UE this AMF is serving.
    if find_ue_by_context_id(ue_context_id).is_some() {
        return send_error(
            403,
            "Forbidden",
            &format!("A UE context already exists for '{ue_context_id}'"),
            Some("CONTEXT_NOT_FOUND"),
        );
    }

    let (ue, sessions) = match create_transferred_ue_context(ue_context_id, ue_context) {
        Ok(created) => created,
        Err(resp) => return *resp,
    };

    let ue_sessions = {
        let ctx = amf_self();
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_list_for_ue(ue.id)
    };
    let response_body = json!({
        "ueContext": build_ue_context_json(&ue, &ue_sessions),
        "targetToSourceData": source_to_target,
        "pduSessionList": pdu_session_list,
    });

    // #397: the event-subscription takeover of §5.2.2.2.3.1. Done AFTER the context is
    // published, because the subscriptions this creates are keyed to the UE and the
    // first thing a consumer may do on hearing the new ID is GET the resource.
    //
    // Only CreateUEContext, not `/relocate`: §5.2.2.2.5.1's `UeContextRelocateData`
    // carries a `ueContext` for a DIFFERENT purpose — the N26 EPS interworking case,
    // where the peer is an MME with no Namf event subscriptions to hand over — and
    // taking them over there would create subscriptions for a procedure the clause
    // does not describe.
    let subscriptions =
        take_over_transferred_event_subscriptions(ue_context_id, ue.supi.as_deref(), ue_context);

    log::info!(
        "[{ue_context_id}] CreateUEContext: context created (ue_id={}, {sessions} session(s) \
         recorded of {} offered, {subscriptions} event subscription(s) taken over)",
        ue.id,
        pdu_session_list.len()
    );
    let location = format!("/namf-comm/v1/ue-contexts/{ue_context_id}");
    match SbiResponse::with_status(201).with_json_body(&response_body) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/release —
/// Namf_Communication_ReleaseUEContext (TS 29.518 §5.2.2.2.4.1).
///
/// A source AMF that received Handover Cancel from the 5G-AN releases the context it
/// created on this (target) AMF. *"the target AMF shall return '204 No Content' with
/// an empty content in the POST response"* (`29518-k00.txt:2912-2913`).
///
/// `UEContextRelease` has no required member this AMF needs, so a well-formed body is
/// accepted and the release performed; a malformed one is 400 per §5.2.7.
fn handle_release_ue_context(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    // An empty body is permitted (the schema requires nothing this AMF consumes), but
    // a body that is PRESENT and unparseable is a defect and must not be treated as
    // absent — otherwise a garbled release silently succeeds.
    if request
        .http
        .content
        .as_deref()
        .is_some_and(|b| !b.is_empty())
        && parse_json_body(request).is_none()
    {
        return malformed_body();
    }
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };

    let ctx = amf_self();
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        // The RAN UE goes too, or the release would free the NAS state and leave the
        // NGAP identifier allocated — a context that is released and still occupies
        // an AMF-UE-NGAP-ID. `amf_ue_remove` already drops this UE's sessions, N1N2
        // subscriptions and LCS correlation.
        guard.ran_ue_remove(ue.ran_ue_id);
        guard.amf_ue_remove(ue.id);
        // And the LIVE store, which is what `find_ue_by_context_id` resolves through
        // (#341). Removing from `amf_ue_list` alone would leave the Namf surface still
        // answering for a context the peer has released — i.e. acting on a UE another
        // AMF now serves.
        guard.amf_ue_unpublish(ue.id);
    }

    log::info!(
        "[{ue_context_id}] ReleaseUEContext: context released (ue_id={})",
        ue.id
    );
    SbiResponse::no_content()
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/relocate —
/// Namf_Communication_RelocateUEContext (TS 29.518 §5.2.2.2.5.1).
///
/// An initial AMF relocates the UE context to this AMF during EPS-to-5GS handover
/// with AMF re-allocation. Mandatory: `ueContext`, `targetId`, `sourceToTargetData`,
/// `forwardRelocationRequest` (`TS29518_Namf_Communication.yaml:3742-3746`).
///
/// *"the target AMF shall respond with the status code '201 Created'... together with
/// a HTTP Location header"* (`29518-k00.txt:2964-2967`), body a
/// `UeContextRelocatedData` whose only required member is `ueContext` (yaml:3753-3754).
///
/// The `forwardRelocationRequest` binary part is REQUIRED and its presence is
/// enforced, but it is not decoded: it is a GTPv2-C Forward Relocation Request from
/// the source MME over N26, and this AMF has no N26 leg to interpret it against. See
/// [`record_transferred_sessions`] for why that ceiling is declared rather than
/// worked around.
fn handle_relocate_ue_context(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let Some(ue_context) = body.get("ueContext") else {
        return mandatory_ie_missing("ueContext");
    };
    let Some(target_id) = body.get("targetId") else {
        return mandatory_ie_missing("targetId");
    };
    if target_id.get("ranNodeId").is_none() {
        return mandatory_ie_missing("targetId.ranNodeId");
    }
    if target_id.get("tai").is_none() {
        return mandatory_ie_missing("targetId.tai");
    }
    if body.get("sourceToTargetData").is_none() {
        return mandatory_ie_missing("sourceToTargetData");
    }
    // `RefToBinaryData` names a multipart part; a reference with no part behind it is
    // a defect, and accepting it would mean accepting a relocation whose Forward
    // Relocation Request never arrived.
    let Some(fwd_content_id) = body
        .pointer("/forwardRelocationRequest/contentId")
        .and_then(Value::as_str)
    else {
        return mandatory_ie_missing("forwardRelocationRequest");
    };
    if find_binary_part(request, fwd_content_id).is_none() {
        return mandatory_ie_incorrect(
            "forwardRelocationRequest.contentId",
            &format!("no binary part with contentId '{fwd_content_id}'"),
        );
    }

    if find_ue_by_context_id(ue_context_id).is_some() {
        return send_error(
            403,
            "Forbidden",
            &format!("A UE context already exists for '{ue_context_id}'"),
            Some("CONTEXT_NOT_FOUND"),
        );
    }

    let (ue, sessions) = match create_transferred_ue_context(ue_context_id, ue_context) {
        Ok(created) => created,
        Err(resp) => return *resp,
    };

    let ue_sessions = {
        let ctx = amf_self();
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_list_for_ue(ue.id)
    };
    let response_body = json!({
        "ueContext": build_ue_context_json(&ue, &ue_sessions),
    });

    log::info!(
        "[{ue_context_id}] RelocateUEContext: context relocated in (ue_id={}, {sessions} \
         session(s) recorded)",
        ue.id
    );
    let location = format!("/namf-comm/v1/ue-contexts/{ue_context_id}");
    match SbiResponse::with_status(201).with_json_body(&response_body) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/cancel-relocate —
/// Namf_Communication_CancelRelocateUEContext (TS 29.518 §5.2.2.2.6.1).
///
/// The initial AMF received a Forward Cancel Request from the source MME and asks
/// this AMF to release the relocated context. `UeContextCancelRelocateData` requires
/// `relocationCancelRequest` (`TS29518_Namf_Communication.yaml:3764-3765`), a
/// `RefToBinaryData`, and `supi` is optional.
///
/// *"the target AMF shall return '204 No Content' with an empty content"*
/// (`29518-k00.txt:3015-3016`).
fn handle_cancel_relocate_ue_context(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };
    let Some(cancel_content_id) = body
        .pointer("/relocationCancelRequest/contentId")
        .and_then(Value::as_str)
    else {
        return mandatory_ie_missing("relocationCancelRequest");
    };
    if find_binary_part(request, cancel_content_id).is_none() {
        return mandatory_ie_incorrect(
            "relocationCancelRequest.contentId",
            &format!("no binary part with contentId '{cancel_content_id}'"),
        );
    }

    // The optional `supi` is honoured as an additional way to name the context, so a
    // consumer that cancels by SUPI while the resource was created under a GUTI is
    // still served. Path first: it is the resource identifier.
    let found = find_ue_by_context_id(ue_context_id).or_else(|| {
        body.get("supi")
            .and_then(Value::as_str)
            .and_then(find_ue_by_context_id)
    });
    let Some(ue) = found else {
        return context_not_found(ue_context_id);
    };

    let ctx = amf_self();
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.ran_ue_remove(ue.ran_ue_id);
        guard.amf_ue_remove(ue.id);
        // The live store too — same reasoning as `handle_release_ue_context`.
        guard.amf_ue_unpublish(ue.id);
    }

    log::info!(
        "[{ue_context_id}] CancelRelocateUEContext: relocated context released (ue_id={})",
        ue.id
    );
    SbiResponse::no_content()
}

// ============================================================================
// AMFStatusChange subscriptions (TS 29.518 §5.2.2.5, #74)
//
// `/namf-comm/v1/subscriptions` — a consumer asks to be told when this AMF's
// availability or GUAMI service changes. §5.2.2.5.1.1 names the AMF planned-removal
// procedure (TS 23.501 §5.21.2.2) as the reason the service exists, and
// `sbi_path::notify_amf_status_change` is the producer that reads this collection at
// exactly that moment — so these are CRUD over a registry something consumes.
// ============================================================================

/// Rebuild the `SubscriptionData` JSON from a stored subscription.
fn amf_status_subscription_json(sub: &crate::context::AmfStatusSubscription) -> Value {
    let mut body = json!({ "amfStatusUri": sub.amf_status_uri });
    if !sub.guami_list.is_empty() {
        body["guamiList"] = json!(sub.guami_list);
    }
    body
}

/// Parse a `SubscriptionData` body (TS29518_Namf_Communication.yaml:2426-2438).
///
/// `amfStatusUri` is the only required member (yaml:2437-2438). It is additionally
/// checked to be a usable HTTP URI, because the AMF has to DIAL it later and a
/// subscription whose callback cannot be parsed is a notification that will never be
/// delivered — better refused at subscribe time than discovered at removal time.
fn parse_amf_status_subscription_body(
    request: &SbiRequest,
) -> Result<(String, Vec<Value>), Box<SbiResponse>> {
    let Some(body) = parse_json_body(request) else {
        return Err(Box::new(malformed_body()));
    };
    let Some(amf_status_uri) = body.get("amfStatusUri").and_then(Value::as_str) else {
        return Err(Box::new(mandatory_ie_missing("amfStatusUri")));
    };
    if parse_http_uri(amf_status_uri).is_none() {
        return Err(Box::new(mandatory_ie_incorrect(
            "amfStatusUri",
            "not a valid HTTP URI",
        )));
    }
    // `minItems: 1` when present (yaml:2436): an explicitly empty array is a defect,
    // and silently treating it as "all GUAMIs" would widen the subscription.
    let guami_list = match body.get("guamiList") {
        Some(Value::Array(list)) if list.is_empty() => {
            return Err(Box::new(mandatory_ie_incorrect(
                "guamiList",
                "must contain at least one entry when present",
            )))
        }
        Some(Value::Array(list)) => list.clone(),
        Some(_) => {
            return Err(Box::new(mandatory_ie_incorrect(
                "guamiList",
                "must be an array of Guami",
            )))
        }
        None => Vec::new(),
    };
    Ok((amf_status_uri.to_string(), guami_list))
}

/// POST /namf-comm/v1/subscriptions — AMFStatusChangeSubscribe (§5.2.2.5.1.2).
///
/// *"the AMF shall include a HTTP Location header to provide the location of a newly
/// created resource (subscription) together with the status code 201"*
/// (`29518-k00.txt:4570-4573`).
fn handle_amf_status_subscription_create(request: &SbiRequest) -> SbiResponse {
    let (amf_status_uri, guami_list) = match parse_amf_status_subscription_body(request) {
        Ok(parsed) => parsed,
        Err(resp) => return *resp,
    };

    let subscription_id = format!("amfstatus-{}", uuid::Uuid::new_v4());
    let sub = crate::context::AmfStatusSubscription {
        subscription_id: subscription_id.clone(),
        amf_status_uri: amf_status_uri.clone(),
        guami_list,
    };

    {
        let ctx = amf_self();
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        if !guard.amf_status_subscription_add(sub.clone()) {
            return send_error(
                500,
                "Internal Server Error",
                "subscription ID collision",
                None,
            );
        }
    }

    log::info!(
        "AMFStatusChange subscription created: id={subscription_id}, \
         amfStatusUri={amf_status_uri}, {} guami(s)",
        sub.guami_list.len()
    );
    let location = format!("/namf-comm/v1/subscriptions/{subscription_id}");
    match SbiResponse::with_status(201).with_json_body(&amf_status_subscription_json(&sub)) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// GET /namf-comm/v1/subscriptions/{subscriptionId} — read back one subscription.
///
/// NOT a TS 29.518 §5.2.2.5 operation: the spec defines Subscribe (POST), the
/// complete-replacement Modify (PUT) and UnSubscribe (DELETE) only. Provided because
/// #74's acceptance criterion asks for create/read/update/delete, and a CRUD
/// round-trip test needs a read path that goes through the SBI surface rather than
/// reaching into the AMF's own store — which would assert the test's plumbing instead
/// of the producer's. Labelled a local read-back so nobody cites it as conformance.
fn handle_amf_status_subscription_read(subscription_id: &str) -> SbiResponse {
    let found = amf_self()
        .read()
        .ok()
        .and_then(|guard| guard.amf_status_subscription_find(subscription_id));
    let Some(sub) = found else {
        return amf_status_subscription_not_found(subscription_id);
    };
    match SbiResponse::ok().with_json_body(&amf_status_subscription_json(&sub)) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// PUT /namf-comm/v1/subscriptions/{subscriptionId} — AMFStatusChangeSubscribeModfy
/// (§5.2.2.5.1.3).
///
/// *"The update operation shall apply to the whole subscription data (complete
/// replacement of the existing subscription data by a new subscription data)"*
/// (`29518-k00.txt:4590-4593`) — so the request body is validated as a full
/// `SubscriptionData`, not a patch, and members it omits are DROPPED rather than
/// preserved. *"On success, '200 OK' shall be returned, the content of the PUT
/// response shall contain the representation of the replaced resource"* (`:4603-4605`).
///
/// An unknown subscription is 404, never an upsert: the ID space is the AMF's, so
/// creating one under a consumer-chosen ID would hand out a resource name the AMF did
/// not mint.
fn handle_amf_status_subscription_replace(
    subscription_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let (amf_status_uri, guami_list) = match parse_amf_status_subscription_body(request) {
        Ok(parsed) => parsed,
        Err(resp) => return *resp,
    };
    let sub = crate::context::AmfStatusSubscription {
        subscription_id: subscription_id.to_string(),
        amf_status_uri: amf_status_uri.clone(),
        guami_list,
    };

    let replaced = amf_self()
        .read()
        .ok()
        .map(|guard| guard.amf_status_subscription_replace(sub.clone()))
        .unwrap_or(false);
    if !replaced {
        return amf_status_subscription_not_found(subscription_id);
    }

    log::info!(
        "AMFStatusChange subscription replaced: id={subscription_id}, \
         amfStatusUri={amf_status_uri}"
    );
    match SbiResponse::ok().with_json_body(&amf_status_subscription_json(&sub)) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// DELETE /namf-comm/v1/subscriptions/{subscriptionId} — AMFStatusChangeUnSubscribe
/// (§5.2.2.5.2.1). *"On success, '204 No Content' shall be returned. The response
/// body shall be empty."* (`29518-k00.txt:4640-4641`).
fn handle_amf_status_subscription_delete(subscription_id: &str) -> SbiResponse {
    let removed = amf_self()
        .read()
        .ok()
        .and_then(|guard| guard.amf_status_subscription_remove(subscription_id));
    if removed.is_none() {
        return amf_status_subscription_not_found(subscription_id);
    }
    log::info!("AMFStatusChange subscription deleted: id={subscription_id}");
    SbiResponse::no_content()
}

/// 404 for an unknown AMFStatusChange subscription (TS 29.500 §5.2.7).
fn amf_status_subscription_not_found(subscription_id: &str) -> SbiResponse {
    send_error(
        404,
        "Not Found",
        &format!("AMFStatusChange subscription '{subscription_id}' not found"),
        Some("SUBSCRIPTION_NOT_FOUND"),
    )
}

// ============================================================================
// Namf_MT (TS 29.518 §6.3)
// ============================================================================

/// POST /namf-mt/v1/ue-contexts/{ueContextId}/ue-reachind —
/// Namf_MT_EnableUEReachability (TS 29.518 §5.4.2.2). Returns 200 with the
/// reachability when the UE is CM-CONNECTED and 504 UE_NOT_REACHABLE
/// otherwise (per §6.3.7.3).
fn handle_enable_ue_reachability(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attribute per TS 29.518 Table 6.3.6.2.2-1
    let Some(reachability) = body.get("reachability").and_then(Value::as_str) else {
        return mandatory_ie_missing("reachability");
    };
    match reachability {
        "UNREACHABLE" | "REACHABLE" | "REGULATORY_ONLY" => {}
        _ => {
            return mandatory_ie_incorrect(
                "reachability",
                &format!("unknown value '{reachability}'"),
            );
        }
    }

    if ue_ran_context(&ue).is_some() {
        let response_body = json!({ "reachability": "REACHABLE" });
        match SbiResponse::ok().with_json_body(&response_body) {
            Ok(resp) => resp,
            Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
        }
    } else {
        // CM-IDLE and not pageable within the synchronous request: 504
        send_error(
            504,
            "Gateway Timeout",
            &format!("UE '{ue_context_id}' is not reachable"),
            Some("UE_NOT_REACHABLE"),
        )
    }
}

/// GET /namf-mt/v1/ue-contexts/{ueContextId} —
/// Namf_MT_ProvideDomainSelectionInfo (TS 29.518 §5.4.2.3). Returns the
/// UeContextInfo derived from the AMF's view of the UE.
fn handle_mt_ue_context_info(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    // info-class query parameter is mandatory for domain selection info
    if request.http.get_param("info-class").is_none() {
        return mandatory_ie_missing("info-class");
    }

    let connected = ue_ran_context(&ue).is_some();
    let mut response_body = json!({
        "accessType": "3GPP_ACCESS",
        "ratType": "NR",
    });
    if connected && ue.ue_location_timestamp > 0 {
        response_body["lastActTime"] = json!(system_time_to_rfc3339(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(ue.ue_location_timestamp)
        ));
    }
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

// ============================================================================
// Namf_Location (TS 29.518 §6.4)
// ============================================================================

/// The age, in seconds, of the AMF's stored NGAP location estimate for `ue`.
///
/// Clamped to the `AgeOfLocationEstimate` range (TS 29.572: 0..32767).
fn ngap_location_age_secs(ue: &AmfUe) -> Option<u64> {
    if ue.ue_location_timestamp == 0 {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(now.saturating_sub(ue.ue_location_timestamp).min(32_767))
}

/// The `ProvidePosInfo` the AMF can answer from NGAP alone: the serving cell and how
/// old that knowledge is.
///
/// This was the WHOLE of `provide-pos-info` before #74. It is retained as the
/// fallback for a deployment with no reachable LMF, so removing the LMF from a
/// bring-up degrades to the previous behaviour rather than failing the operation.
fn ngap_provide_pos_info(ue: &AmfUe) -> Value {
    let mut body = json!({ "ncgi": ncgi_json(&ue.nr_cgi) });
    if let Some(age) = ngap_location_age_secs(ue) {
        body["ageOfLocationEstimate"] = json!(age);
    }
    body
}

/// POST /namf-loc/v1/{ueContextId}/provide-pos-info —
/// Namf_Location_ProvidePositioningInfo (TS 29.518 §5.5.2.2.1).
///
/// The clause is explicit about what this operation is for: *"The ProvidePositioningInfo
/// service operation shall be invoked by the NF Service Consumer (e.g. GMLC) to request
/// the current or deferred geodetic and optionally local and/or civic location of the UE.
/// **The service operation triggers the AMF to invoke the service towards the LMF.**"*
/// (`29518-k00.txt:6500-6505`), and TS 23.273 §6.1 routes the 5GC-MT-LR through the LMF.
///
/// Before #74 the AMF returned its stored NGAP NCGI and carried an in-code admission
/// that "No LMF client path exists in this AMF" — so a GMLC asking for a position got a
/// radio-cell identity instead. `lmfd` has served
/// `POST /nlmf-loc/v1/determine-location` all along (`lmfd/src/main.rs:376-378`), i.e.
/// the producer existed and had no consumer.
///
/// Now the AMF discovers an LMF and invokes `Nlmf_Location_DetermineLocation`, returning
/// the LMF-derived `locationEstimate` / `ageOfLocationEstimate` / `positioningDataList`.
/// **The NGAP answer is retained as the fallback** when no LMF is reachable, so a
/// deployment without one is unaffected. `AMF_NAMF_LOC_LMF=off` forces the fallback.
///
/// A runtime env switch rather than the cargo feature the issue suggests: a
/// feature-gated path is outside `cargo test --workspace`, which is the CI gate, so
/// the code would ship unexercised. `sbi_path::ue_policy_assoc_enabled` is the in-tree
/// precedent for the form.
async fn handle_provide_positioning_info(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attributes per TS 29.518 Table 6.4.6.2.2-1 (RequestPosInfo)
    if body.get("lcsClientType").and_then(Value::as_str).is_none() {
        return mandatory_ie_missing("lcsClientType");
    }
    if body.get("lcsLocation").and_then(Value::as_str).is_none() {
        return mandatory_ie_missing("lcsLocation");
    }

    if crate::sbi_path::namf_loc_lmf_enabled() {
        match crate::sbi_path::call_lmf_determine_location(&ue, &body).await {
            Ok(mut location_data) => {
                // The serving cell is added to whatever the LMF computed: it is the
                // AMF's own knowledge and `ProvidePosInfo` carries `ncgi` alongside
                // `locationEstimate` (`TS29518_Namf_Location.yaml:373-400`), so a
                // consumer gets both the position and the cell it was taken in.
                if let Value::Object(map) = &mut location_data {
                    map.insert("ncgi".to_string(), ncgi_json(&ue.nr_cgi));
                }
                log::info!(
                    "[{ue_context_id}] ProvidePositioningInfo: LMF-derived position \
                     (TS 23.273 §6.1)"
                );
                return match SbiResponse::ok().with_json_body(&location_data) {
                    Ok(resp) => resp,
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                };
            }
            Err(e) => {
                // Degrade to the pre-#74 answer rather than fail: a consumer that got a
                // cell identity before must not start getting a 5xx because an LMF is
                // absent. The reason is logged so the degradation is visible.
                log::warn!(
                    "[{ue_context_id}] ProvidePositioningInfo: LMF DetermineLocation \
                     unavailable ({e}); answering with the stored NGAP location"
                );
            }
        }
    }

    let response_body = ngap_provide_pos_info(&ue);
    log::info!(
        "[{ue_context_id}] ProvidePositioningInfo: NCGI cell=0x{:09X}",
        ue.nr_cgi.cell_id
    );
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// POST /namf-loc/v1/{ueContextId}/provide-loc-info —
/// Namf_Location_ProvideLocationInfo (TS 29.518 §5.5.2.4.1), #74.
///
/// *"The ProvideLocationInfo service operation allows an NF Service Consumer (e.g. UDM)
/// to request the Network Provided Location Information (NPLI) of a target UE"*
/// (`29518-k00.txt:6657-6660`). Distinct from `provide-pos-info`: that one asks the LMF
/// to POSITION the UE, this one asks the AMF what it already knows about where the UE is
/// attached — which is why it answers from AMF state and does not involve the LMF.
///
/// `RequestLocInfo` has **no required members** (`TS29518_Namf_Location.yaml:552-569`:
/// `req5gsLoc`, `reqCurrentLoc`, `reqRatType`, `reqTimeZone` are all optional with
/// `default: false`), so an empty JSON object is a valid request and must not 400.
/// The response is a `ProvideLocInfo` (`:571-592`).
///
/// # `currentLoc` is always `false`, and that is the spec's own answer
///
/// §5.5.2.4.1 makes `reqCurrentLoc: true` conditional on machinery this AMF does not
/// have: for a CM-IDLE UE *"the AMF shall initiate a paging procedure"*, and for a
/// CM-CONNECTED one *"the AMF shall follow NG-RAN Location reporting procedure... to
/// trigger a single standalone report by setting 'direct' event type in Location
/// Reporting Control"* (`:6689-6702`). Neither exists here — there is no
/// LocationReportingControl anywhere in this tree. The clause then states exactly what
/// to do in that case: *"if the UE does not respond to the paging, the AMF shall provide
/// the last known location and set 'currentLoc' attribute to 'false'"*. So the last
/// known location is returned with `currentLoc: false`, which is a TRUE statement about
/// what was sent. Claiming `true` would be the defect.
fn handle_provide_location_info(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    // A present-but-unparseable body is a defect and must not be read as "no body":
    // otherwise a garbled request is answered as though it asked for the default.
    if request
        .http
        .content
        .as_deref()
        .is_some_and(|b| !b.is_empty())
        && parse_json_body(request).is_none()
    {
        return malformed_body();
    }

    let mut response_body = json!({
        // See the doc comment: the AMF cannot obtain a CURRENT location, so it reports
        // the last known one and says so. This member is what tells the consumer which
        // of the two it received.
        "currentLoc": false,
        "location": nr_location_json(&ue),
    });
    if let Some(age) = ngap_location_age_secs(&ue) {
        response_body["locationAge"] = json!(age);
    }
    // `ratType` only when the UE is genuinely attached over NR. `reqRatType` is a
    // request for it, not a licence to assert one for a UE with no live connection.
    if ue_ran_context(&ue).is_some() {
        response_body["ratType"] = json!("NR");
    }
    // `timezone` is deliberately OMITTED. The AMF never learns a UE time zone —
    // `gmm_build.rs` sends `local_time_zone: None` /
    // `universal_time_and_local_time_zone: None` — so there is no value to report, and
    // the host's own zone is not the UE's.

    log::info!(
        "[{ue_context_id}] ProvideLocationInfo: last known location, NCGI cell=0x{:09X} \
         (currentLoc=false per TS 29.518 §5.5.2.4.1)",
        ue.nr_cgi.cell_id
    );
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// POST /namf-loc/v1/{ueContextId}/cancel-pos-info —
/// Namf_Location_CancelLocation (TS 29.518 §5.5.2.5.1), #74.
///
/// *"invoked by the NF Service Consumer (e.g. GMLC) to cancel reporting periodic or
/// events triggered location"* (`29518-k00.txt:6720-6722`). `CancelPosInfo` requires
/// `supi`, `hgmlcCallBackURI` and `ldrReference`
/// (`TS29518_Namf_Location.yaml:612-615`).
///
/// *"On success, AMF responds with '204 No Content'. If the nrppaPeriodicInd IE with the
/// value true is received, the AMF shall skip the cancel location procedures towards the
/// UE."* (`:6740-6743`) — both halves are honoured: the LDR cancellation is relayed to
/// the LMF, except when `nrppaPeriodicInd` is true, in which case the reporting is the
/// RAN's NRPPa periodic measurement and there is nothing to cancel toward the UE.
///
/// The LMF leg is best-effort: the consumer asked THIS AMF to stop reporting, and the
/// stored correlation is dropped either way. An unreachable LMF is logged, not turned
/// into a 5xx that would leave the consumer believing its cancellation failed while the
/// AMF has in fact stopped.
async fn handle_cancel_location(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let Some(supi) = body.get("supi").and_then(Value::as_str) else {
        return mandatory_ie_missing("supi");
    };
    let Some(hgmlc_callback) = body.get("hgmlcCallBackURI").and_then(Value::as_str) else {
        return mandatory_ie_missing("hgmlcCallBackURI");
    };
    if parse_http_uri(hgmlc_callback).is_none() {
        return mandatory_ie_incorrect("hgmlcCallBackURI", "not a valid HTTP URI");
    }
    let Some(ldr_reference) = body.get("ldrReference").and_then(Value::as_str) else {
        return mandatory_ie_missing("ldrReference");
    };

    let nrppa_periodic = body
        .get("nrppaPeriodicInd")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // The stored LCS correlation goes regardless: the consumer has cancelled, so the
    // AMF must not keep routing this UE's uplink positioning to the old LMF. Keyed by
    // the UE's own context identity, the way `lcs_correlation_set` writes it.
    let correlation_key = ue.supi.clone().unwrap_or_else(|| supi.to_string());
    let serving_lmf = {
        let ctx = amf_self();
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        let record = guard.lcs_correlation_find(&correlation_key);
        guard.lcs_correlation_remove(&correlation_key);
        record.and_then(|r| r.serving_lmf_identification)
    };

    if nrppa_periodic {
        log::info!(
            "[{ue_context_id}] CancelLocation: nrppaPeriodicInd=true, so the cancel-location \
             procedure toward the UE is SKIPPED (TS 29.518 §5.5.2.5.1 step 2a); the LDR \
             [{ldr_reference}] correlation is dropped"
        );
    } else {
        match crate::sbi_path::call_lmf_cancel_location(
            &correlation_key,
            ldr_reference,
            hgmlc_callback,
            serving_lmf.as_deref(),
        )
        .await
        {
            Ok(()) => log::info!(
                "[{ue_context_id}] CancelLocation: LDR [{ldr_reference}] cancelled at the LMF"
            ),
            Err(e) => log::warn!(
                "[{ue_context_id}] CancelLocation: the LMF could not be told to cancel LDR \
                 [{ldr_reference}] ({e}); the AMF's own correlation is dropped regardless, so \
                 this AMF has stopped reporting"
            ),
        }
    }

    SbiResponse::no_content()
}

// ============================================================================
// Namf_MBSCommunication / Namf_MBSBroadcast (TS 29.518 §5.6-5.7, TS 23.247)
// ============================================================================

/// Parse an `MbsSessionId` (TS 29.571) into the NGAP-side [`Tmgi`].
///
/// The schema is `anyOf [tmgi, ssm]`. Only `tmgi` is accepted: an SSM
/// (source-specific multicast address pair) identifies a session by IP, and the
/// NGAP `MBS-SessionID` this AMF sends carries a TMGI. Rejecting an SSM-only
/// request is honest; mapping it to an invented TMGI would not be.
/// Boxed on the error side because `SbiResponse` is large and clippy's
/// `result_large_err` is right that returning it by value costs every caller.
fn parse_mbs_session_id(value: &Value) -> Result<Tmgi, Box<SbiResponse>> {
    let Some(tmgi) = value.get("tmgi") else {
        if value.get("ssm").is_some() {
            return Err(Box::new(send_error(
                501,
                "Not Implemented",
                "mbsSessionId.ssm is not supported: the AMF's NGAP MBS-SessionID carries a \
                 TMGI, and no SSM-to-TMGI mapping is defined for this deployment",
                Some("UNSPECIFIED_NF_FAILURE"),
            )));
        }
        return Err(Box::new(mandatory_ie_missing("mbsSessionId.tmgi")));
    };

    let Some(service_id) = tmgi.get("mbsServiceId").and_then(Value::as_str) else {
        return Err(Box::new(mandatory_ie_missing(
            "mbsSessionId.tmgi.mbsServiceId",
        )));
    };
    // `pattern: '^[A-Fa-f0-9]{6}$'` (TS29571_CommonData.yaml Tmgi)
    let service_bytes = (service_id.len() == 6)
        .then(|| u32::from_str_radix(service_id, 16).ok())
        .flatten();
    let Some(service) = service_bytes else {
        return Err(Box::new(mandatory_ie_incorrect(
            "mbsSessionId.tmgi.mbsServiceId",
            "must be 6 hexadecimal digits",
        )));
    };

    let Some(plmn) = tmgi.get("plmnId") else {
        return Err(Box::new(mandatory_ie_missing("mbsSessionId.tmgi.plmnId")));
    };
    let Some(plmn_bytes) = plmn_id_to_bcd(plmn) else {
        return Err(Box::new(mandatory_ie_incorrect(
            "mbsSessionId.tmgi.plmnId",
            "mcc must be 3 digits and mnc 2 or 3 digits",
        )));
    };

    Ok(Tmgi::new(service, plmn_bytes))
}

/// Encode a `PlmnId { mcc, mnc }` as the 3 BCD octets NGAP carries
/// (TS 24.008 §10.5.1.13: MCC digits then MNC, with a 2-digit MNC padded `0xF`).
fn plmn_id_to_bcd(plmn: &Value) -> Option<[u8; 3]> {
    let mcc = plmn.get("mcc").and_then(Value::as_str)?;
    let mnc = plmn.get("mnc").and_then(Value::as_str)?;
    if mcc.len() != 3 || !(2..=3).contains(&mnc.len()) {
        return None;
    }
    let d: Vec<u8> = mcc
        .chars()
        .chain(mnc.chars())
        .map(|c| c.to_digit(10).map(|v| v as u8))
        .collect::<Option<_>>()?;
    let (mnc1, mnc2, mnc3) = if mnc.len() == 2 {
        (0x0F, d[3], d[4])
    } else {
        (d[5], d[3], d[4])
    };
    Some([d[0] | (d[1] << 4), d[2] | (mnc1 << 4), mnc2 | (mnc3 << 4)])
}

/// `POST /namf-mbs-comm/v1/n2-messages/transfer` — Namf_MBSCommunication
/// N2MessageTransfer (TS 29.518 §5.7, TS 23.247 §7.2.5.2).
///
/// The MB-SMF hands the AMF an MBS SM container to relay to the NG-RAN. The
/// AMF's job here is exactly that relay: it does not interpret the container.
///
/// Responds with `MbsN2MessageTransferRspData`, whose only required member is
/// `result` (TS29518_Namf_MBSCommunication.yaml:188).
async fn handle_mbs_n2_message_transfer(request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let Some(session_value) = body.get("mbsSessionId") else {
        return mandatory_ie_missing("mbsSessionId");
    };
    let tmgi = match parse_mbs_session_id(session_value) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };

    // `n2MbsSmInfo` is required. Its binary half arrives as a multipart part
    // referenced by contentId, the same shape Namf_Communication's N2
    // information uses.
    let Some(n2_info) = body.get("n2MbsSmInfo") else {
        return mandatory_ie_missing("n2MbsSmInfo");
    };
    let content_id = n2_info
        .get("ngapData")
        .and_then(|d| d.get("contentId"))
        .and_then(Value::as_str);
    let ngap_container = content_id.and_then(|cid| find_binary_part(request, cid));

    // The RAN nodes to drive. `ranNodeIdList` is optional: absent means every
    // gNB the AMF serves, per TS 23.247 §7.2.5.2's "the AMF relays to the RAN
    // nodes in the MBS service area".
    let ran_node_count = body
        .get("ranNodeIdList")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    let mcast = crate::context::amf_mcast();
    let session = mcast.session_find_by_tmgi(&tmgi);

    log::info!(
        "Namf_MBSCommunication N2MessageTransfer: tmgi_svc={:#x} ngap_container={} bytes \
         ran_nodes={} known_session={}",
        tmgi.service_id_u32(),
        ngap_container.as_ref().map(|c| c.len()).unwrap_or(0),
        ran_node_count,
        session.is_some(),
    );

    // The N2 relay itself is NOT performed here, and this is the honest ceiling
    // of this increment: the NGAP server owns the SCTP associations and is not
    // reachable from the SBI task, so handing it a PDU needs an AmfEvent variant
    // that does not exist. Answering N2_NOT_SENT reports exactly that to the
    // MB-SMF (N2InformationTransferResult, TS 29.518) rather than claiming a
    // transfer that did not happen.
    let result = "N2_NOT_SENT";
    let response_body = json!({ "result": result });

    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// The three N2 information classes a PWS consumer may subscribe to
/// (TS 29.518 §5.2.2.4.2.2, `29518-k00.txt:4334-4336`: "to subscribe for
/// notifications of N2 PWS information classes ("PWS", "PWS-BCAL" or
/// "PWS-RF")"), all three of them members of `N2InformationClass`
/// (`TS29518_Namf_Communication.yaml:4487-4499`).
///
/// `PWS-BCAL` carries the two RESPONSES and `PWS-RF` the two INDICATIONS
/// (Tables 6.1.6.4.3.3-2 / -3, `29518-k00.txt:19055` / `:19108`); plain `PWS` is
/// the umbrella a consumer may use for both.
pub(crate) const PWS_N2_INFORMATION_CLASSES: [&str; 3] = ["PWS", "PWS-BCAL", "PWS-RF"];

/// `POST /namf-comm/v1/non-ue-n2-messages/subscriptions` —
/// Namf_Communication NonUeN2InfoSubscribe (TS 29.518 §5.2.2.4.2, resource
/// §6.1.3.9, `NonUeN2InfoSubscriptionCreateData` at
/// `TS29518_Namf_Communication.yaml:2570`), #399.
///
/// A CBCF/PWS-IWF creates one of these so the AMF can tell it what each NG-RAN
/// node answered to a warning (§5.2.2.4.4.3). Until this resource existed, the
/// transfer handler below had no subscription to find and returned the spec's
/// `n2PwsSubMissInd: true` unconditionally; that signal is now conditional, which
/// is what §5.2.2.4.1.3 (`29518-k00.txt:4175-4181`) actually prescribes.
///
/// Fail-closed, in the shape [`handle_n1n2_subscription_create`] already uses:
/// both mandatory members must be present and the callback URI must be one the
/// AMF can actually POST to, and only the three PWS classes are accepted —
/// storing a class nothing in this AMF can ever notify would be a subscription
/// that silently never fires.
fn handle_non_ue_n2_info_subscribe(request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // `n2InformationClass` and `n2NotifyCallbackUri` are the two required members
    // (`yaml:2594-2596`; §6.1.6.2.10 marks both "M").
    let Some(n2_information_class) = body.get("n2InformationClass").and_then(Value::as_str) else {
        return mandatory_ie_missing("n2InformationClass");
    };
    let Some(n2_notify_callback_uri) = body.get("n2NotifyCallbackUri").and_then(Value::as_str)
    else {
        return mandatory_ie_missing("n2NotifyCallbackUri");
    };

    // The AMF must be able to POST the notification there, so an unparseable URI
    // is rejected now rather than discovered at notify time when the consumer is
    // no longer listening on an HTTP response.
    if parse_http_uri(n2_notify_callback_uri).is_none() {
        return mandatory_ie_incorrect("n2NotifyCallbackUri", "not a valid HTTP URI");
    }

    // Only the PWS classes are served. The other `N2InformationClass` values
    // (`SM`, `NRPPa`, `RAN`, `V2X`, `PROSE`, `TSS`, `RSPP`, `A2X`) each need their
    // own producer; `NRPPa` in particular is already served by the per-UE
    // `n1-n2-messages/subscriptions` registry, so accepting it here would store a
    // second subscription that nothing reads.
    if !PWS_N2_INFORMATION_CLASSES.contains(&n2_information_class) {
        return send_error(
            403,
            "Forbidden",
            &format!(
                "n2InformationClass '{n2_information_class}' is not served on this resource; \
                 only the PWS classes {PWS_N2_INFORMATION_CLASSES:?} (TS 29.518 §5.2.2.4.2.2) are"
            ),
            Some("UNSPECIFIED"),
        );
    }

    let nf_id = body
        .get("nfId")
        .and_then(Value::as_str)
        .map(String::from)
        .filter(|s| !s.is_empty());

    // `globalRanNodeList` / `anTypeList` are both conditional, and the NOTE at
    // `29518-k00.txt:11913-11915` says absence of BOTH means "N2 information from
    // all connected Access Network node(s) via any access type" — so empty here
    // means "unrestricted", never "no nodes".
    let global_ran_node_gnb_ids: Vec<u32> = body
        .get("globalRanNodeList")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|node| {
                    // `GNbId.gNBValue` is hex (TS 29.571, pattern
                    // `^[A-Fa-f0-9]{6,8}$`), same parse as the transfer handler's.
                    node.get("gNbId")
                        .and_then(|g| g.get("gNBValue"))
                        .and_then(Value::as_str)
                        .and_then(|v| u32::from_str_radix(v, 16).ok())
                })
                .collect()
        })
        .unwrap_or_default();

    let an_type_list: Vec<String> = body
        .get("anTypeList")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let subscription_id = format!("nonuen2sub-{}", uuid::Uuid::new_v4());
    let sub = crate::context::NonUeN2InfoSubscription {
        subscription_id: subscription_id.clone(),
        n2_information_class: n2_information_class.to_string(),
        n2_notify_callback_uri: n2_notify_callback_uri.to_string(),
        nf_id: nf_id.clone(),
        notif_correlation_id: body
            .get("notifCorrelationId")
            .and_then(Value::as_str)
            .map(String::from),
        global_ran_node_gnb_ids,
        an_type_list,
        supported_features: body
            .get("supportedFeatures")
            .and_then(Value::as_str)
            .map(String::from),
    };

    let ctx = amf_self();
    let added = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        // §5.2.2.4.2.2 item 2 (`29518-k00.txt:4351-4356`): "the AMF may remove any
        // duplicated subscription, i.e. an existing subscription from the same NF
        // consumer (identified by the NF instance ID) for notification of the same
        // N2 PWS information class". Taken, because leaving both would make the
        // find-by-class tie-break decide which of a consumer's own duplicates
        // wins. Only done when an nfId identifies the consumer — without one there
        // is no way to know two subscriptions came from the same instance.
        if let Some(nf) = nf_id.as_deref() {
            if let Some(dup) =
                guard.non_ue_n2_subscription_find_by_class_exact(n2_information_class, Some(nf))
            {
                log::info!(
                    "NonUeN2InfoSubscribe: replacing duplicate subscription {} from nfId {nf} \
                     for class {n2_information_class} (TS 29.518 §5.2.2.4.2.2)",
                    dup.subscription_id
                );
                guard.non_ue_n2_subscription_remove(&dup.subscription_id);
            }
        }
        guard.non_ue_n2_subscription_add(sub)
    };
    if !added {
        return send_error(
            500,
            "Internal Server Error",
            "subscription ID collision",
            None,
        );
    }

    log::info!(
        "NonUeN2InfoSubscribe: id={subscription_id} class={n2_information_class} \
         callback={n2_notify_callback_uri} nfId={nf_id:?}"
    );

    // `NonUeN2InfoSubscriptionCreatedData` (`yaml:2597-2607`):
    // `n2NotifySubscriptionId` mandatory, `n2InformationClass` and
    // `supportedFeatures` optional. The class is echoed so the consumer can
    // confirm which of the three the AMF actually registered.
    let mut response_body = json!({
        "n2NotifySubscriptionId": subscription_id,
        "n2InformationClass": n2_information_class,
    });
    if let Some(features) = body.get("supportedFeatures").and_then(Value::as_str) {
        response_body["supportedFeatures"] = json!(features);
    }
    // §6.1.3.9.3.1's 201 requires the Location header, whose structure is spelled
    // out at `yaml:1945`:
    // {apiRoot}/namf-comm/<apiVersion>/non-ue-n2-messages/subscriptions/{n2NotifySubscriptionId}
    let location = format!("/namf-comm/v1/non-ue-n2-messages/subscriptions/{subscription_id}");
    match SbiResponse::with_status(201).with_json_body(&response_body) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// `DELETE /namf-comm/v1/non-ue-n2-messages/subscriptions/{n2NotifySubscriptionId}`
/// — Namf_Communication NonUeN2InfoUnSubscribe (TS 29.518 §5.2.2.4.3, resource
/// §6.1.3.10), #399.
///
/// 204 on success (§5.2.2.4.3.1 step 2, `29518-k00.txt:4378-4380`), or 404 with
/// cause `SUBSCRIPTION_NOT_FOUND` — the cause §6.1.3.10.3.1's response table
/// names for this condition (`:10170-10175`), which is NOT the
/// `CONTEXT_NOT_FOUND` the per-UE unsubscribe uses.
fn handle_non_ue_n2_info_unsubscribe(subscription_id: &str) -> SbiResponse {
    let ctx = amf_self();
    let removed = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.non_ue_n2_subscription_remove(subscription_id)
    };
    match removed {
        Some(sub) => {
            log::info!(
                "NonUeN2InfoUnSubscribe: removed {subscription_id} (class {})",
                sub.n2_information_class
            );
            SbiResponse::no_content()
        }
        None => send_error(
            404,
            "Not Found",
            &format!("Non-UE N2 information subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// `POST /namf-comm/v1/non-ue-n2-messages/transfer` — Namf_Communication
/// NonUeN2MessageTransfer (TS 29.518 §5.2.2.4.1,
/// `TS29518_Namf_Communication.yaml:1718`), for the **PWS** N2 information class
/// (§5.2.2.4.1.3, the Warning Request Transfer Procedure).
///
/// ## The AMF forwards; it does not compose
///
/// `PwsInformation.pwsContainer` is an `N2InfoContent`
/// (`TS29518_Namf_Communication.yaml:3283`), described in the OpenAPI as
/// "Represents a transparent N2 information content to be relayed by AMF"
/// (`:3251`), and §5.2.2.4.1.3 says three times that the AMF *forwards* the N2
/// Message Container (`6g_docs/specs/29518-k00.txt:4152`, `:4155`, `:4158`). So
/// this handler validates the container and relays it verbatim. Decomposing
/// `messageIdentifier`/`serialNumber`/`warningAreaList` out of the JSON and
/// re-encoding a fresh WRITE-REPLACE WARNING REQUEST would be *less* conformant,
/// not more: it would drop every IE the CBCF sent that this build does not model,
/// including the extensions `WriteReplaceWarningRequestIEs`' `...` admits.
///
/// ## The 200 body echoes; it does not collect
///
/// §5.2.2.4.1.3 step 2a (`29518-k00.txt:4169`) has the response carry "the
/// mandatory elements from the Write-Replace-Warning Confirm response (see clause
/// 9.2.17 in TS 23.041)". `PWSResponseData`'s three mandatory members
/// (`yaml:3777-3796`) are `ngapMessageType`, `serialNumber` and
/// `messageIdentifier` — all of them the request's own values. Only the two
/// OPTIONAL members (`unknownTaiList`, `n2PwsSubMissInd`) are RAN-derived. So the
/// 200 reports that the AMF *initiated* the transfer and echoes the identifiers;
/// it is not gated on WRITE-REPLACE WARNING RESPONSEs, which arrive
/// asynchronously on SCTP in the NGAP task long after this response must be
/// written, and which TS 29.518 routes through the separate
/// `non-ue-n2-info-subscriptions` + `n2InfoNotify` surface.
fn handle_non_ue_n2_message_transfer(request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // `n2Information` is the only required member of N2InformationTransferReqData
    // (`TS29518_Namf_Communication.yaml:2570`).
    let Some(n2_information) = body.get("n2Information") else {
        return mandatory_ie_missing("n2Information");
    };
    // `n2InformationClass` is required within N2InfoContainer (`:2707`).
    let Some(info_class) = n2_information
        .get("n2InformationClass")
        .and_then(Value::as_str)
    else {
        return mandatory_ie_missing("n2Information.n2InformationClass");
    };

    // Only PWS is served here. The other classes this service operation carries
    // (NRPPa for §5.2.2.4.1.2, RAN for the Configuration Transfer and RIM
    // procedures, TSS for §5.2.2.4.1.7) each need their own transport, and
    // answering 200 for them would claim a transfer that never happened.
    if info_class != "PWS" {
        return send_error(
            403,
            "Forbidden",
            &format!(
                "n2InformationClass '{info_class}' is not served on this resource; \
                 only 'PWS' (TS 29.518 §5.2.2.4.1.3) is"
            ),
            Some("UNSPECIFIED"),
        );
    }

    let Some(pws_info) = n2_information.get("pwsInfo") else {
        return mandatory_ie_missing("n2Information.pwsInfo");
    };

    // messageIdentifier, serialNumber and pwsContainer are the three required
    // members of PwsInformation (`TS29518_Namf_Communication.yaml:3298-3300`).
    let Some(message_identifier) = pws_info.get("messageIdentifier").and_then(Value::as_u64) else {
        return mandatory_ie_missing("pwsInfo.messageIdentifier");
    };
    let Some(serial_number) = pws_info.get("serialNumber").and_then(Value::as_u64) else {
        return mandatory_ie_missing("pwsInfo.serialNumber");
    };
    let Some(pws_container) = pws_info.get("pwsContainer") else {
        return mandatory_ie_missing("pwsInfo.pwsContainer");
    };
    if message_identifier > u16::MAX as u64 {
        return mandatory_ie_incorrect("pwsInfo.messageIdentifier", "exceeds Uint16");
    }
    if serial_number > u16::MAX as u64 {
        return mandatory_ie_incorrect("pwsInfo.serialNumber", "exceeds Uint16");
    }

    // `ngapData` is the only required member of N2InfoContent (`:3261`); it is a
    // RefToBinaryData, so the bytes ride in a multipart part named by contentId.
    let Some(content_id) = pws_container
        .get("ngapData")
        .and_then(|d| d.get("contentId"))
        .and_then(Value::as_str)
    else {
        return mandatory_ie_missing("pwsInfo.pwsContainer.ngapData.contentId");
    };
    let Some(ngap_pdu) = find_binary_part(request, content_id) else {
        return mandatory_ie_incorrect(
            "pwsInfo.pwsContainer.ngapData.contentId",
            "no multipart part carries that contentId",
        );
    };

    // Validate the container really is a PWS NGAP PDU before enqueueing it. An
    // unvalidated relay would forward whatever the consumer sent to every served
    // gNB, and the gNB would answer an Error Indication the CBCF never sees.
    // `decode_ngap_pdu` is the real APER decoder, so this also rejects a
    // truncated or malformed PDU.
    let decoded = match nextgcore_ngap::parser::decode_ngap_pdu(&ngap_pdu) {
        Ok(msg) => msg,
        Err(e) => {
            return mandatory_ie_incorrect(
                "pwsInfo.pwsContainer.ngapData",
                &format!("not a decodable NGAP PDU: {e}"),
            );
        }
    };
    // TS 38.413 §8.12: the AMF-initiated PWS procedures are WriteReplaceWarning
    // (51) and PWSCancel (32). The two indications are gNB-initiated, so a
    // consumer sending one is confused about the direction.
    let (ngap_message_type, container_mid, container_sn) = match &decoded {
        nextgcore_ngap::NgapMessage::WriteReplaceWarningRequest(req) => (
            nextgcore_asn1c::ngap::types::ProcedureCode::WRITE_REPLACE_WARNING.0,
            req.message_identifier,
            req.serial_number,
        ),
        nextgcore_ngap::NgapMessage::PwsCancelRequest(req) => (
            nextgcore_asn1c::ngap::types::ProcedureCode::PWS_CANCEL.0,
            req.message_identifier,
            req.serial_number,
        ),
        other => {
            return mandatory_ie_incorrect(
                "pwsInfo.pwsContainer.ngapData",
                &format!(
                    "expected a WRITE-REPLACE WARNING REQUEST (procedure 51) or PWS CANCEL \
                     REQUEST (procedure 32); got {other:?}"
                ),
            );
        }
    };

    // The JSON identifiers and the ones inside the container must agree: they are
    // what the CBCF will match the response against (§5.2.2.4.1.3 step 2a), and a
    // mismatch means one of the two is wrong. Echoing the JSON pair while
    // broadcasting the container's pair would make the AMF lie in both directions.
    if container_mid != message_identifier as u16 || container_sn != serial_number as u16 {
        return mandatory_ie_incorrect(
            "pwsInfo",
            &format!(
                "messageIdentifier/serialNumber ({message_identifier:#06x}/{serial_number:#06x}) \
                 disagree with the pwsContainer's ({container_mid:#06x}/{container_sn:#06x})"
            ),
        );
    }

    // Targeting selectors, in the precedence §5.2.2.4.1.3 defines
    // (`29518-k00.txt:4152-4159`). Carried verbatim and resolved by the NGAP
    // task: `gnb_list` in the context has no production writer, so resolving
    // here would match nothing (#341's "production reader, test-only writer").
    let target_gnb_ids: Vec<u32> = body
        .get("globalRanNodeList")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|node| {
                    // GNbId.gNBValue is hex (TS 29.571 `GNbId`, pattern
                    // `^[A-Fa-f0-9]{6,8}$`).
                    node.get("gNbId")
                        .and_then(|g| g.get("gNBValue"))
                        .and_then(Value::as_str)
                        .and_then(|v| u32::from_str_radix(v, 16).ok())
                })
                .collect()
        })
        .unwrap_or_default();

    let target_tais: Vec<(crate::context::PlmnId, u32)> = body
        .get("taiList")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|tai| {
                    let plmn = tai.get("plmnId")?;
                    let mcc = plmn.get("mcc").and_then(Value::as_str)?;
                    let mnc = plmn.get("mnc").and_then(Value::as_str)?;
                    // Tac is a 3- or 6-hex-digit string (TS 29.571 `Tac`).
                    let tac = tai.get("tac").and_then(Value::as_str)?;
                    let tac = u32::from_str_radix(tac, 16).ok()?;
                    Some((crate::context::PlmnId::new(mcc, mnc), tac))
                })
                .collect()
        })
        .unwrap_or_default();

    let rat_selector = match body.get("ratSelector").and_then(Value::as_str) {
        Some("NR") => Some(crate::context::PwsRatSelector::Nr),
        Some("E-UTRA") => Some(crate::context::PwsRatSelector::Eutra),
        Some(other) => {
            return mandatory_ie_incorrect(
                "ratSelector",
                &format!("'{other}' is not one of NR / E-UTRA"),
            );
        }
        None => None,
    };

    let ctx = crate::context::amf_self();
    {
        let Ok(guard) = ctx.read() else {
            return send_error(
                500,
                "Internal Server Error",
                "AMF context unavailable",
                None,
            );
        };
        guard.pws_n2_add(crate::context::PendingPwsN2Transfer {
            ngap_pdu,
            message_identifier: message_identifier as u16,
            serial_number: serial_number as u16,
            target_gnb_ids: target_gnb_ids.clone(),
            target_tais: target_tais.clone(),
            rat_selector,
        });
    }

    log::info!(
        "Namf NonUeN2MessageTransfer (PWS): NGAP procedure {ngap_message_type} enqueued for \
         relay (message_identifier={message_identifier:#06x} serial_number={serial_number:#06x} \
         gnb_targets={} tai_targets={} rat={rat_selector:?})",
        target_gnb_ids.len(),
        target_tais.len(),
    );

    // `sendRanResponse: true` asks the AMF to report the per-RAN-node outcome
    // through the consumer's PWS N2 information subscription
    // (`29518-k00.txt:14712-14716`: "This IE shall be present to request the AMF
    // to send the N2 response information it has received from the RAN nodes to
    // the NF Service Consumer"). Default is false (`yaml:3291-3292`).
    let send_ran_response = pws_info
        .get("sendRanResponse")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // `pwsInfo.nfId` identifies WHICH CBCF/PWS-IWF instance asked, so the response
    // goes to that instance's own subscription when several are deployed
    // (`29518-k00.txt:14747-14760`).
    let consumer_nf_id = pws_info
        .get("nfId")
        .and_then(Value::as_str)
        .map(String::from)
        .filter(|s| !s.is_empty());

    // §5.2.2.4.4.3 item 1 makes the RESPONSE notification conditional on the
    // originating request having asked for it, and the WRITE-REPLACE WARNING
    // RESPONSE that arrives minutes later on SCTP carries no trace of that ask
    // (its IE table is Message Type / Message Identifier / Serial Number / the
    // optional area list / Criticality Diagnostics — `38413-j30.txt:15916`). So
    // record it against the warning's identity now. Only `true` is recorded:
    // fail-closed, so a transfer that asked for nothing can never cause a notify.
    let matched_subscription = if send_ran_response {
        let Ok(guard) = ctx.read() else {
            return send_error(
                500,
                "Internal Server Error",
                "AMF context unavailable",
                None,
            );
        };
        guard.pws_response_request_set(
            message_identifier as u16,
            serial_number as u16,
            crate::context::PwsResponseRequest {
                send_ran_response: true,
                nf_id: consumer_nf_id.clone(),
                procedure_code: ngap_message_type,
            },
        );
        // §6.1.6.4.3.3 routes the two RESPONSES through the `PWS-BCAL` class
        // (Table 6.1.6.4.3.3-2, `29518-k00.txt:19055-19062`), with plain `PWS` as
        // the umbrella.
        guard
            .non_ue_n2_subscription_find_by_class("PWS-BCAL", consumer_nf_id.as_deref())
            .is_some()
    } else {
        false
    };

    // `omcId` asks the AMF to "write the n2Information it has received from the
    // RAN nodes into trace records on the OMC" (`29518-k00.txt:14735-14742`).
    // This deployment has no OMC and no trace-record writer, so the IE cannot be
    // honoured. Said out loud rather than accepted silently: accepting it and not
    // tracing would be the quieter lie of the two.
    if let Some(omc_id) = pws_info.get("omcId").and_then(Value::as_str) {
        log::warn!(
            "Namf NonUeN2MessageTransfer (PWS): omcId '{omc_id}' received but NOT honoured — \
             this AMF has no OMC trace-record writer (TS 29.518 §6.1.6.2.x omcId)"
        );
    }

    // `result` is the only required member of N2InformationTransferRspData
    // (`yaml:3359`). N2_INFO_TRANSFER_INITIATED is exactly what happened: the
    // transfer was initiated toward the RAN.
    let mut pws_rsp_data = json!({
        "ngapMessageType": ngap_message_type,
        "serialNumber": serial_number,
        "messageIdentifier": message_identifier,
    });

    // §5.2.2.4.1.3 (`29518-k00.txt:4175-4181`): "If the sendRanResponse IE with
    // the value "true" was received in the request, BUT the corresponding N2
    // information subscription for PWS information from the NF service consumer is
    // not available in the AMF, the AMF should include the n2PwsSubMissInd IE with
    // the value "true"". BOTH halves of that condition — which is why this is no
    // longer unconditional on `sendRanResponse` as it was before #399: the AMF now
    // serves `non-ue-n2-messages/subscriptions`, so the subscription CAN exist,
    // and claiming it is missing when it is not would make a conformant consumer
    // needlessly re-create a live subscription.
    if send_ran_response && !matched_subscription {
        pws_rsp_data["n2PwsSubMissInd"] = Value::Bool(true);
    }

    // `unknownTaiList` (§6.1.6.2.46, `yaml:3786-3791`). Scoped to the PWS Cancel
    // branch: §5.2.2.4.1.3 step 2a (`29518-k00.txt:4169-4173`) hangs the
    // "optionally the unknown TAI List IE" option off the *Stop-Warning* Confirm
    // response, not off the Write-Replace-Warning Confirm response.
    //
    // What it can honestly carry: the TAIs in `taiList` that this AMF does not
    // SERVE AT ALL, read from the config-loaded `served_tai` (which, unlike
    // `gnb_list`, has a real production writer at `lib.rs:520`). It deliberately
    // does NOT try to report "TAIs no connected node served": that fact lives in
    // the NGAP pump, which runs after this 200 is already on the wire, and
    // `unknownTaiList` is a member of the SYNCHRONOUS response body
    // (`PWSResponseData` has exactly one referent, `N2InformationTransferRspData.
    // pwsRspData` at `yaml:3348`) — it is absent from `N2InformationNotification`
    // (`yaml:2637-2679`), so it cannot ride the asynchronous notify either.
    // Blocking the response on SCTP progress is what §5.2.2.4.1.3's echo
    // semantics exist to avoid. A TAI the AMF does not serve can never match a
    // served node, so it is an unknown TAI under any reading, and it IS knowable
    // here.
    if ngap_message_type == nextgcore_asn1c::ngap::types::ProcedureCode::PWS_CANCEL.0 {
        let unknown: Vec<Value> = {
            let Ok(guard) = ctx.read() else {
                return send_error(
                    500,
                    "Internal Server Error",
                    "AMF context unavailable",
                    None,
                );
            };
            target_tais
                .iter()
                .filter(|(plmn, tac)| {
                    guard
                        .find_served_tai(&crate::context::Tai5gs {
                            plmn_id: plmn.clone(),
                            tac: *tac,
                        })
                        .is_none()
                })
                .map(|(plmn, tac)| {
                    // TS 29.571 `Tai`: `plmnId` + `tac`, where `Tac` is a 3- or
                    // 6-hex-digit string. Rendered back in the same 6-digit hex
                    // form the request's `tac` was parsed from.
                    json!({
                        "plmnId": { "mcc": plmn.mcc(), "mnc": plmn.mnc() },
                        "tac": format!("{tac:06X}"),
                    })
                })
                .collect()
        };
        if !unknown.is_empty() {
            log::info!(
                "Namf NonUeN2MessageTransfer (PWS Cancel): {} of {} taiList entries name TAIs \
                 this AMF does not serve; reported as unknownTaiList",
                unknown.len(),
                target_tais.len(),
            );
            // `minItems: 1` (`yaml:3791`), so the IE is omitted rather than sent
            // empty when every TAI was served.
            pws_rsp_data["unknownTaiList"] = Value::Array(unknown);
        }
    }
    let response_body = json!({
        "result": "N2_INFO_TRANSFER_INITIATED",
        "pwsRspData": pws_rsp_data,
    });

    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// `POST /namf-mbs-bc/v1/mbs-contexts` — Namf_MBSBroadcast ContextCreate
/// (TS 29.518 §5.6, TS 23.247 §7.3.1).
///
/// The MB-SMF asks the AMF to create a broadcast MBS context, which the AMF
/// then drives toward the NG-RAN with BroadcastSessionSetup (procedure 68).
async fn handle_mbs_context_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let Some(session_value) = body.get("mbsSessionId") else {
        return mandatory_ie_missing("mbsSessionId");
    };
    let tmgi = match parse_mbs_session_id(session_value) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };

    let mcast = crate::context::amf_mcast();
    // Idempotent on the TMGI: a repeated ContextCreate returns the existing
    // context rather than allocating a second one for the same session.
    let session = match mcast.session_find_by_tmgi(&tmgi) {
        Some(existing) => existing,
        None => {
            let Some(created) = mcast.session_create(tmgi.clone(), 1, None, Vec::new()) else {
                return send_error(
                    500,
                    "Internal Server Error",
                    "could not create the MBS session context",
                    None,
                );
            };
            created
        }
    };

    log::info!(
        "Namf_MBSBroadcast ContextCreate: tmgi_svc={:#x} ref={}",
        tmgi.service_id_u32(),
        session.mbs_session_id,
    );

    let context_ref = format!("{}", session.mbs_session_id);
    let response_body = json!({ "mbsContextRef": context_ref });

    // 201 with a Location header naming the created resource (TS 29.518 §6.5).
    match SbiResponse::created().with_json_body(&response_body) {
        Ok(resp) => resp.with_header(
            "Location",
            format!("/namf-mbs-bc/v1/mbs-contexts/{context_ref}"),
        ),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

// ============================================================================
// Tests
// ============================================================================

/// WSB-4: shared serialize lock for tests that DESTRUCTIVELY drain the
/// process-global `network_dereg_queue` — the router-arm tests in this module
/// AND the NGAP `process_network_deregs` pump test in `ngap_path`. Same
/// rationale as the positioning queue's `UPDP_QUEUE_TEST_LOCK`; module-level +
/// `pub(crate)` so both test modules serialize against one lock.
#[cfg(test)]
pub(crate) fn dereg_queue_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// #396: shared serialize lock for tests that DESTRUCTIVELY drain the
/// process-global `pws_n2_queue` — the router-arm tests in this module AND the
/// NGAP `process_pws_n2_transfers` pump test in `ngap_path`. Declared here beside
/// the queue's other test lock, module-level and `pub(crate)`, so both test
/// modules serialize against ONE lock: a second lock declared inside a
/// `mod tests` is what hung this suite once.
#[cfg(test)]
pub(crate) fn pws_queue_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::amf_context_init;
    use nextgcore_sbi::message::SbiPart;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Unique RAN-UE-NGAP-ID source so tests never collide on the shared
    /// global context
    static NEXT_NGAP_ID: AtomicU64 = AtomicU64::new(50_000);

    /// Create a UE in the global context with the given SUPI.
    /// `connected` controls whether a live RAN UE context is associated
    /// (CM-CONNECTED); `security` sets security_context_available.
    fn setup_ue(supi: &str, connected: bool, security: bool) -> AmfUe {
        amf_context_init(64, 1024, 4096);
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let ngap_id = NEXT_NGAP_ID.fetch_add(1, Ordering::SeqCst);
        let ran_ue = guard
            .ran_ue_add(900_100, ngap_id)
            .expect("ran_ue_add failed");
        let mut ue = guard.amf_ue_add(ran_ue.id).expect("amf_ue_add failed");
        // #341: `amf_ue_set_supi` is gone; `amf_ue_publish` below is the seam.
        ue.supi = Some(supi.to_string());
        ue.security_context_available = security;
        ue.nr_tai.tac = 100;
        ue.nr_cgi.cell_id = 0x12345;
        if connected {
            guard.amf_ue_associate_ran_ue(ue.id, ran_ue.id);
            ue.ran_ue_id = ran_ue.id;
        } else {
            ue.ran_ue_id = NEXTGCORE_INVALID_POOL_ID;
        }
        guard.amf_ue_update(&ue);
        // #341: publish into the LIVE store too, which is what the handlers now
        // resolve against. Before #341 this helper wrote only `amf_ue_list`, and
        // that was the defect: the Namf surface read a store nothing in production
        // ever wrote, so these tests passed while a really-registered UE got a 404.
        // A `ran_ue_ngap_id` of 0 for a CM-IDLE UE matches what the resolver does
        // with it -- nothing; only the SUPI/GUTI lookups are exercised here.
        guard.amf_ue_publish(&ue, ngap_id as u32, 1);
        ue
    }

    /// Add a session with an SM context ref + DNN for the UE
    fn setup_sess(ue: &AmfUe, psi: u8) -> AmfSess {
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let mut sess = guard.sess_add(ue.id, psi).expect("sess_add failed");
        sess.sm_context_ref = Some(format!("smctx-{psi}"));
        sess.dnn = Some("internet".to_string());
        sess.s_nssai.sst = 1;
        guard.sess_update(&sess);
        sess
    }

    fn body_json(resp: &SbiResponse) -> Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}"))
            .expect("response body is not JSON")
    }

    fn problem_cause(resp: &SbiResponse) -> String {
        body_json(resp)["cause"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// Start a capture server on an ephemeral port; returns (server, port, rx)
    async fn start_capture_server() -> (
        SbiServer,
        u16,
        tokio::sync::mpsc::Receiver<(String, String)>,
    ) {
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let (tx, rx) = tokio::sync::mpsc::channel::<(String, String)>(16);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), port_listener);
        server
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let _ = tx
                        .send((
                            req.header.uri.clone(),
                            req.http.content.clone().unwrap_or_default(),
                        ))
                        .await;
                    SbiResponse::no_content()
                }
            })
            .await
            .expect("capture server start");
        (server, port, rx)
    }

    fn subscription_body(supi: &str, notify_uri: &str, event_type: &str) -> Value {
        json!({
            "subscription": {
                "eventList": [{ "type": event_type }],
                "eventNotifyUri": notify_uri,
                "notifyCorrelationId": format!("corr-{supi}"),
                "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "supi": supi,
            }
        })
    }

    // ------------------------------------------------------------------
    // RFC 3339 + URI helpers
    // ------------------------------------------------------------------

    #[test]
    fn test_rfc3339_roundtrip() {
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let s = system_time_to_rfc3339(t);
        assert_eq!(s, "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_to_system_time(&s), Some(t));

        // Offsets and fractional seconds
        let with_offset = rfc3339_to_system_time("2023-11-14T23:13:20+01:00");
        assert_eq!(with_offset, Some(t));
        let with_frac = rfc3339_to_system_time("2023-11-14T22:13:20.500Z");
        assert_eq!(with_frac, Some(t));

        // Malformed inputs never panic
        assert_eq!(rfc3339_to_system_time("not-a-date"), None);
        assert_eq!(rfc3339_to_system_time("2023-13-99T99:99:99Z"), None);
        assert_eq!(rfc3339_to_system_time(""), None);
    }

    #[test]
    fn test_parse_http_uri() {
        assert_eq!(
            parse_http_uri("http://1.2.3.4:8080/a/b"),
            Some(("1.2.3.4".to_string(), 8080, "/a/b".to_string()))
        );
        assert_eq!(
            parse_http_uri("http://host/cb"),
            Some(("host".to_string(), 80, "/cb".to_string()))
        );
        assert_eq!(
            parse_http_uri("https://host"),
            Some(("host".to_string(), 443, "/".to_string()))
        );
        assert_eq!(parse_http_uri("ftp://host/x"), None);
        assert_eq!(parse_http_uri("http://:80/x"), None);
        assert_eq!(parse_http_uri(""), None);
    }

    // ------------------------------------------------------------------
    // Namf_EventExposure — handler round-trips + strict mandatory attrs
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_subscription_create_delete_roundtrip() {
        amf_context_init(64, 1024, 4096);
        let body = subscription_body(
            "imsi-001010000060001",
            "http://127.0.0.1:9/notify",
            "REGISTRATION_STATE_REPORT",
        );
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let rsp_body = body_json(&resp);
        let sub_id = rsp_body["subscriptionId"].as_str().expect("subscriptionId");
        assert!(sub_id.starts_with("sub-"));
        assert!(resp
            .http
            .get_header("location")
            .expect("location header")
            .ends_with(sub_id));
        // Echoed subscription carries the mandatory attributes
        assert_eq!(
            rsp_body["subscription"]["eventNotifyUri"].as_str(),
            Some("http://127.0.0.1:9/notify")
        );

        // Persisted in the context store
        let ctx = amf_self();
        assert!(ctx
            .read()
            .unwrap()
            .event_subscription_find(sub_id)
            .is_some());

        // DELETE removes it; second DELETE is 404 SUBSCRIPTION_NOT_FOUND
        let del = SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{sub_id}"));
        let resp = namf_request_handler(del).await;
        assert_eq!(resp.status, 204);
        let del = SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{sub_id}"));
        let resp = namf_request_handler(del).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "SUBSCRIPTION_NOT_FOUND");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_subscription_missing_mandatory_attrs() {
        amf_context_init(64, 1024, 4096);
        // Strict peer: each missing mandatory attribute is rejected with 400
        let cases = vec![
            json!({}),
            json!({ "subscription": {} }),
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "notifyCorrelationId": "c", "nfId": "n", "anyUE": true } }),
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "nfId": "n", "anyUE": true } }),
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "anyUE": true } }),
            json!({ "subscription": {
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "nfId": "n", "anyUE": true } }),
            // eventList entry without mandatory `type`
            json!({ "subscription": {
                "eventList": [{}],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "nfId": "n", "anyUE": true } }),
            // no UE target at all (neither supi nor anyUE)
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "nfId": "n" } }),
        ];
        for body in cases {
            let req = SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&body)
                .expect("json");
            let resp = namf_request_handler(req).await;
            assert_eq!(resp.status, 400, "body should be rejected: {body}");
            assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");
        }

        // Malformed (non-JSON) body: 400, no panic
        let mut req = SbiRequest::post("/namf-evts/v1/subscriptions");
        req.http.set_content("this is not json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_subscription_modify() {
        amf_context_init(64, 1024, 4096);
        let body = subscription_body(
            "imsi-001010000060002",
            "http://127.0.0.1:9/notify-old",
            "LOCATION_REPORT",
        );
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // PATCH replace of the notify URI
        let patch = json!([{
            "op": "replace",
            "path": "/subscription/eventNotifyUri",
            "value": "http://127.0.0.1:9/notify-new",
        }]);
        let req = SbiRequest::patch(format!("/namf-evts/v1/subscriptions/{sub_id}"))
            .with_json_body(&patch)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        let ctx = amf_self();
        let stored = ctx
            .read()
            .unwrap()
            .event_subscription_find(&sub_id)
            .unwrap();
        assert_eq!(stored.notify_uri, "http://127.0.0.1:9/notify-new");

        // Unsupported patch op rejected with 400
        let patch = json!([{ "op": "remove", "path": "/subscription/nfId" }]);
        let req = SbiRequest::patch(format!("/namf-evts/v1/subscriptions/{sub_id}"))
            .with_json_body(&patch)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // PATCH on unknown subscription is 404
        let patch = json!([{
            "op": "replace", "path": "/subscription/eventNotifyUri",
            "value": "http://127.0.0.1:9/x" }]);
        let req = SbiRequest::patch("/namf-evts/v1/subscriptions/sub-unknown")
            .with_json_body(&patch)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);

        let _ = namf_request_handler(SbiRequest::delete(format!(
            "/namf-evts/v1/subscriptions/{sub_id}"
        )))
        .await;
    }

    #[test]
    fn test_expired_subscription_is_skipped_and_swept() {
        amf_context_init(64, 1024, 4096);
        let ctx = amf_self();
        let guard = ctx.read().unwrap();
        let supi = "imsi-001010000060003";
        let sub = EventSubscription {
            subscription_id: "sub-expired-test".to_string(),
            notify_uri: "http://127.0.0.1:9/cb".to_string(),
            notify_correlation_id: "c".to_string(),
            nf_id: "n".to_string(),
            event_types: vec!["LOCATION_REPORT".to_string()],
            supi: Some(supi.to_string()),
            // SUPI-targeted, so the #74 external-identity keys are absent: this test is
            // about expiry, and adding them would give it a second reason to match.
            gpsi: None,
            pei: None,
            group_id: None,
            any_ue: false,
            expiry: Some(std::time::UNIX_EPOCH), // long expired
            // No subscription-change callback (#397) for the same reason: this test is
            // about expiry.
            subs_change_notify_uri: None,
            subs_change_notify_correlation_id: None,
        };
        assert!(guard.event_subscription_add(sub));
        // Expired subscriptions never match (other tests may add unrelated
        // subscriptions to the shared global context, so scope by ID)
        assert!(!guard
            .event_subscriptions_matching("LOCATION_REPORT", Some(supi))
            .iter()
            .any(|s| s.subscription_id == "sub-expired-test"));
        // ... and the sweep removes them
        guard.event_subscriptions_remove_expired();
        assert!(guard.event_subscription_find("sub-expired-test").is_none());
    }

    // ------------------------------------------------------------------
    // Namf_EventExposure — HTTP-level notification POST delivery
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_notification_post_delivery() {
        // This test drives production code against a loopback PLAINTEXT peer, i.e.
        // it describes a dev-profile deployment (issue #63). Declared explicitly
        // rather than inherited from the environment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        amf_context_init(64, 1024, 4096);
        let supi = "imsi-001010000060010";
        let (server, port, mut rx) = start_capture_server().await;

        // Subscribe with the capture server as the notify endpoint
        let notify_uri = format!("http://127.0.0.1:{port}/amf-event-notify");
        let body = subscription_body(supi, &notify_uri, "REACHABILITY_REPORT");
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // Fire the event the AMF tracks; delivery happens on a spawned task
        fire_amf_event(
            "REACHABILITY_REPORT",
            Some(supi),
            json!({ "reachability": "REACHABLE" }),
        );

        let (uri, posted) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("notification not delivered within 3s")
            .expect("capture channel closed");
        assert_eq!(uri, "/amf-event-notify");
        let posted: Value = serde_json::from_str(&posted).expect("notification body JSON");
        assert_eq!(
            posted["notifyCorrelationId"].as_str(),
            Some(format!("corr-{supi}").as_str())
        );
        let report = &posted["reportList"][0];
        assert_eq!(report["type"].as_str(), Some("REACHABILITY_REPORT"));
        assert_eq!(report["supi"].as_str(), Some(supi));
        assert_eq!(report["reachability"].as_str(), Some("REACHABLE"));
        assert!(report["timeStamp"].as_str().is_some());
        assert_eq!(report["state"]["active"].as_bool(), Some(true));

        let _ = namf_request_handler(SbiRequest::delete(format!(
            "/namf-evts/v1/subscriptions/{sub_id}"
        )))
        .await;
        server.stop().await.expect("server stop");
    }

    // ------------------------------------------------------------------
    // Namf_Communication — N1N2MessageTransfer
    // ------------------------------------------------------------------

    fn n1n2_body(psi: u8, with_n1: bool, skip_ind: bool, failure_uri: Option<&str>) -> Value {
        let mut body = json!({
            "pduSessionId": psi,
            "n2InfoContainer": {
                "n2InformationClass": "SM",
                "smInfo": {
                    "pduSessionId": psi,
                    "n2InfoContent": {
                        "ngapIeType": "PDU_RES_SETUP_REQ",
                        "ngapData": { "contentId": "ngap-sm" },
                    },
                },
            },
        });
        if with_n1 {
            body["n1MessageContainer"] = json!({
                "n1MessageClass": "SM",
                "n1MessageContent": { "contentId": "5gnas-sm" },
            });
        }
        if skip_ind {
            body["skipInd"] = json!(true);
        }
        if let Some(uri) = failure_uri {
            body["n1n2FailureTxfNotifURI"] = json!(uri);
        }
        body
    }

    fn n1n2_request(ue_context_id: &str, body: &Value, with_n1: bool) -> SbiRequest {
        let mut req = SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"
        ))
        .with_json_body(body)
        .expect("json")
        .with_part(SbiPart::with_content(
            "ngap-sm",
            "application/vnd.3gpp.ngap",
            bytes::Bytes::from_static(&[0x00, 0x1d, 0x00, 0x03]),
        ));
        if with_n1 {
            req = req.with_part(SbiPart::with_content(
                "5gnas-sm",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::from_static(&[0x2e, 0x01, 0x01, 0xc1]),
            ));
        }
        req
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_connected_ue() {
        let supi = "imsi-001010000060020";
        let ue = setup_ue(supi, true, true);
        setup_sess(&ue, 5);

        let body = n1n2_body(5, true, false, None);
        let resp = namf_request_handler(n1n2_request(supi, &body, true)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );
    }

    /// LCS: an LMF push of LPP (n1MessageClass "LPP", no PDU session) to a
    /// connected UE is recognised by the positioning relay, the DL NAS Transport
    /// is built, and the transfer is accepted (200) — the SM path is skipped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_lpp_to_connected_ue_relays() {
        // Unique SUPI: test_ue_context_transfer_roundtrip also registered
        // imsi-001010000060030 in the shared process-global supi_hash.
        let supi = "imsi-001010000060036";
        setup_ue(supi, true, true);

        let body = json!({
            "n1MessageContainer": {
                "n1MessageClass": "LPP",
                "n1MessageContent": { "contentId": "lpp-pdu" }
            }
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "lpp-pdu",
                "application/vnd.3gpp.lpp",
                bytes::Bytes::from_static(&[0x90, 0x01, 0x20, 0x09, 0x30]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );
    }

    /// LCS: an LMF push of NRPPa (n2InfoContainer.nrppaInfo, ngapIeType
    /// NRPPA_PDU, no PDU session) to a connected UE is recognised, the
    /// UE-associated NRPPa DL transport is built, and the transfer is accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_nrppa_to_connected_ue_relays() {
        let supi = "imsi-001010000060031";
        setup_ue(supi, true, true);

        let body = json!({
            "n2InfoContainer": {
                "n2InformationClass": "NRPPa",
                "nrppaInfo": {
                    "nfId": "lmf-0001",
                    "nrppaPdu": {
                        "ngapIeType": "NRPPA_PDU",
                        "ngapData": { "contentId": "nrppa-pdu" }
                    }
                }
            }
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "nrppa-pdu",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from_static(&[0x00, 0x00, 0x01, 0x00, 0x1d, 0x00]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );
    }

    /// Serializes the two UPDP tests that DRAIN the shared global
    /// positioning_dl_queue (drains are destructive; other relay tests only
    /// enqueue and never read the queue, so they are unaffected).
    static UPDP_QUEUE_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    fn updp_queue_test_lock() -> &'static tokio::sync::Mutex<()> {
        UPDP_QUEUE_TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Drain the global downlink queue, keep the items for `ue_id`, re-add
    /// everything else (leave other tests' enqueues untouched).
    fn drain_downlinks_for(ue_id: u64) -> Vec<crate::context::PendingPositioningDl> {
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let (mine, others): (Vec<_>, Vec<_>) = guard
            .positioning_dl_drain()
            .into_iter()
            .partition(|d| d.amf_ue_ngap_id == ue_id);
        for item in others {
            guard.positioning_dl_add(item);
        }
        mine
    }

    /// Wave-6 E5: a PCF push of UPDP (n1MessageClass "UPDP", TS 29.518
    /// yaml:4453, no PDU session) to a CM-CONNECTED UE returns 200 and
    /// enqueues the VERBATIM UPDP bytes as a UePolicyToUe downlink for the
    /// NGAP egress pump — no silent drop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_updp_to_connected_ue_relays_verbatim() {
        let _serial = updp_queue_test_lock().lock().await;
        // Unique SUPI. The queue lock above serialises the DRAIN, but the
        // enqueue in try_ue_policy_relay uses the UE that
        // `amf_ue_find_by_supi` resolves from the process-global supi_hash --
        // which the lock does not cover. test_registration_status_update
        // registered this same SUPI, so whichever test called setup_ue last
        // owned the hash entry; the handler then enqueued under the OTHER
        // test's ue.id and drain_downlinks_for(ue.id) filtered its own item
        // away, failing with "exactly one UPDP downlink enqueued: left 0".
        // See test_ue_context_transfer_error_paths for the same trap.
        let supi = "imsi-001010000060035";
        let ue = setup_ue(supi, true, true);

        // Opaque MANAGE UE POLICY COMMAND-ish bytes (payload is opaque to the
        // AMF; content does not matter, byte-for-byte relay does).
        let updp: &[u8] = &[0x80, 0x01, 0x00, 0x05, 0xAB];
        let body = json!({
            "n1MessageContainer": {
                "n1MessageClass": "UPDP",
                "n1MessageContent": { "contentId": "updp-pdu" }
            }
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "updp-pdu",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::copy_from_slice(updp),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );

        // The queue now holds the verbatim payload for this UE (filter by
        // AMF-UE-NGAP-ID: the queue is global and shared across tests).
        let drained = drain_downlinks_for(ue.id);
        assert_eq!(drained.len(), 1, "exactly one UPDP downlink enqueued");
        match &drained[0].kind {
            crate::context::PositioningDlKind::UePolicyToUe { updp_pdu } => {
                assert_eq!(updp_pdu.as_slice(), updp, "UPDP payload relayed verbatim");
            }
            other => panic!("expected UePolicyToUe, got {other:?}"),
        }
    }

    /// Wave-6 E5 fail-closed assert: the same UPDP transfer against a CM-IDLE
    /// UE gets 504 UE_NOT_REACHABLE (and the n1n2FailureTxfNotifURI callback),
    /// NOT the pre-E5 fake-success 200-and-drop.
    ///
    /// Drives `try_ue_policy_relay` directly with a locally-constructed
    /// CM-IDLE `AmfUe` (its CM check reads the passed UE, not the global
    /// store) so the assert is deterministic: the shared global UE store is
    /// mutated concurrently by other tests (pool-id reuse can flip a stored
    /// idle UE to connected mid-test — the known
    /// `test_ue_context_transfer_error_paths` flake class). The HTTP routing
    /// into the relay is covered by the connected-UE test above.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_updp_to_idle_ue_504_not_fake_200() {
        // This test drives production code against a loopback PLAINTEXT peer, i.e.
        // it describes a dev-profile deployment (issue #63). Declared explicitly
        // rather than inherited from the environment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _serial = updp_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);
        let supi = "imsi-001010000060033";
        // CM-IDLE by construction: no live RAN UE context.
        let mut ue = AmfUe::new(987_654, NEXTGCORE_INVALID_POOL_ID);
        ue.supi = Some(supi.to_string());
        ue.ran_ue_id = NEXTGCORE_INVALID_POOL_ID;

        let (server, port, mut rx) = start_capture_server().await;
        let failure_uri = format!("http://127.0.0.1:{port}/pcf-n1n2-failure");

        let body = json!({
            "n1MessageContainer": {
                "n1MessageClass": "UPDP",
                "n1MessageContent": { "contentId": "updp-pdu" }
            },
            "n1n2FailureTxfNotifURI": failure_uri,
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "updp-pdu",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::from_static(&[0x80, 0x01, 0x00]),
            ));
        let resp = try_ue_policy_relay(supi, &ue, &req, &body)
            .expect("UPDP transfer must be classified as a UE-policy relay");
        assert_eq!(resp.status, 504, "CM-IDLE UPDP must be 504, never 200");
        let err = body_json(&resp);
        assert_eq!(err["error"]["cause"].as_str(), Some("UE_NOT_REACHABLE"));

        // n1n2FailureTxfNotifURI is honored (TS 29.518 §6.1.6.2.8).
        let (uri, posted) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("failure notification not delivered within 3s")
            .expect("capture channel closed");
        assert_eq!(uri, "/pcf-n1n2-failure");
        let posted: Value = serde_json::from_str(&posted).expect("failure body JSON");
        assert_eq!(posted["cause"].as_str(), Some("UE_NOT_REACHABLE"));

        // Nothing was enqueued for this UE (fail-closed).
        let leaked = drain_downlinks_for(ue.id).len();
        assert_eq!(leaked, 0, "no downlink may be enqueued for an idle UE");

        server.stop().await.expect("server stop");
    }

    /// Wave-6 E5: a UPDP transfer whose contentId has no matching binary part
    /// is rejected 400 MANDATORY_IE_INCORRECT (never accepted-and-dropped).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_updp_missing_binary_part_400() {
        let supi = "imsi-001010000060034";
        setup_ue(supi, true, true);

        let body = json!({
            "n1MessageContainer": {
                "n1MessageClass": "UPDP",
                "n1MessageContent": { "contentId": "updp-pdu" }
            }
        });
        // No multipart binary part attached at all.
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");
    }

    // ------------------------------------------------------------------
    // Namf_Communication — N1N2MessageSubscribe / UnSubscribe
    // (TS 29.518 §5.2.2.6/§5.2.2.7)
    // ------------------------------------------------------------------

    /// UeN1N2InfoSubscriptionCreateData shaped per
    /// TS29518_Namf_Communication.yaml:2609-2626 (all fields)
    #[test]
    fn golden_n2_info_notify_multipart_body() {
        // Wave-6 WS-A A1 — hand-derived golden byte-vector for the multipart
        // N2InfoNotify body (TS 29.500 §6.1.2.3 framing; TS 29.518
        // N2InformationNotification, TS29518_Namf_Communication.yaml:2637 —
        // n2NotifySubscriptionId mandatory). The expected bytes below are
        // written out by hand from the multipart/related grammar, NOT
        // round-tripped through the encoder.
        let nrppa = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let req = build_n2_info_notify_request(
            "/nlmf-loc/v1/notify/n2",
            "sub-1",
            Some("corr-9"),
            Some("lmf-1"),
            &nrppa,
        )
        .expect("build N2InfoNotify");

        // JSON root: compared order-insensitively (parsed Value equality) —
        // RFC 8259 object members are unordered and the emitted key order is
        // serializer-dependent (this workspace unifies serde_json with
        // `preserve_order`, so `json!` maps keep insertion order).
        let json = req.http.content.clone().expect("json root part");
        let actual: serde_json::Value = serde_json::from_str(&json).expect("valid JSON root");
        let expected_json: serde_json::Value = serde_json::from_str(
            "{\"lcsCorrelationId\":\"corr-9\",\
             \"n2InfoContainer\":{\"n2InformationClass\":\"NRPPa\",\
             \"nrppaInfo\":{\"nfId\":\"lmf-1\",\
             \"nrppaPdu\":{\"ngapData\":{\"contentId\":\"nrppa\"},\
             \"ngapIeType\":\"NRPPA_PDU\"}}},\
             \"n2NotifySubscriptionId\":\"sub-1\"}",
        )
        .expect("valid expected JSON");
        assert_eq!(actual, expected_json);

        // Full multipart body with a pinned boundary.
        let body = nextgcore_sbi::multipart::encode(Some(json.as_str()), &req.http.parts, "gold");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"--gold\r\nContent-Type: application/json\r\n\r\n");
        expected.extend_from_slice(json.as_bytes());
        expected.extend_from_slice(
            b"\r\n--gold\r\nContent-Id: nrppa\r\nContent-Type: application/vnd.3gpp.ngap\r\n\r\n",
        );
        expected.extend_from_slice(&nrppa);
        expected.extend_from_slice(b"\r\n--gold--\r\n");
        assert_eq!(
            body, expected,
            "multipart body must match the hand-derived vector"
        );

        // Cross-decode with our own multipart decoder (strict-peer property:
        // this is exactly what lmfd's SbiServer layer runs on receipt) — the
        // binary part must be the NRPPa PDU verbatim (transparent relay).
        let decoded = nextgcore_sbi::multipart::decode(
            &nextgcore_sbi::multipart::content_type_with_boundary("gold"),
            &body,
        )
        .expect("multipart decode");
        assert_eq!(decoded.json.as_deref(), Some(json.as_str()));
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].content_id.as_deref(), Some("nrppa"));
        assert_eq!(
            decoded.parts[0].content_type.as_deref(),
            Some("application/vnd.3gpp.ngap")
        );
        assert_eq!(decoded.parts[0].data.as_ref(), &nrppa[..]);
    }

    #[test]
    fn n2_info_notify_optional_fields_omitted() {
        // Absent lcsCorrelationId / nfId must be OMITTED (never null / never
        // fabricated) — fail-closed producer per WS-A A1 step 2.
        let req = build_n2_info_notify_request("/cb", "sub-2", None, None, &[0x01])
            .expect("build N2InfoNotify");
        let v: Value = serde_json::from_str(req.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(v["n2NotifySubscriptionId"], "sub-2");
        assert!(v.get("lcsCorrelationId").is_none());
        assert!(v["n2InfoContainer"]["nrppaInfo"].get("nfId").is_none());
        assert_eq!(
            v["n2InfoContainer"]["nrppaInfo"]["nrppaPdu"]["ngapIeType"],
            "NRPPA_PDU"
        );
    }

    /// Wave-6 A4 — hand-derived golden byte-vector for the multipart
    /// N1MessageNotify body (TS 29.500 §6.1.2.3 framing; TS 29.518
    /// N1MessageNotification, TS29518_Namf_Communication.yaml:2708 —
    /// n1MessageContainer mandatory). The expected bytes are written out by hand
    /// from the multipart/related grammar, NOT round-tripped through the encoder.
    #[test]
    fn golden_n1_message_notify_multipart_body() {
        // A synthetic UPER LPP payload (opaque to the AMF — forwarded verbatim).
        let lpp = [0x08u8, 0x00, 0x11, 0x22];
        let req = build_n1_message_notify_request(
            "/nlmf-loc/v1/notify/n1",
            Some("sub-7"),
            "LPP",
            Some("corr-42"),
            Some("imsi-001010000000001"),
            &lpp,
        )
        .expect("build N1MessageNotify");

        // JSON root: parsed-Value equality (RFC 8259 object members unordered).
        let json = req.http.content.clone().expect("json root part");
        let actual: serde_json::Value = serde_json::from_str(&json).expect("valid JSON root");
        let expected_json: serde_json::Value = serde_json::from_str(
            "{\"n1MessageContainer\":{\"n1MessageClass\":\"LPP\",\
             \"n1MessageContent\":{\"contentId\":\"n1-lpp\"}},\
             \"n1NotifySubscriptionId\":\"sub-7\",\
             \"lcsCorrelationId\":\"corr-42\",\
             \"supi\":\"imsi-001010000000001\"}",
        )
        .expect("valid expected JSON");
        assert_eq!(actual, expected_json);

        // Full multipart body with a pinned boundary — hand-written layout.
        let body = nextgcore_sbi::multipart::encode(Some(json.as_str()), &req.http.parts, "gold");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"--gold\r\nContent-Type: application/json\r\n\r\n");
        expected.extend_from_slice(json.as_bytes());
        expected.extend_from_slice(
            b"\r\n--gold\r\nContent-Id: n1-lpp\r\nContent-Type: application/vnd.3gpp.5gnas\r\n\r\n",
        );
        expected.extend_from_slice(&lpp);
        expected.extend_from_slice(b"\r\n--gold--\r\n");
        assert_eq!(
            body, expected,
            "multipart body must match the hand-derived vector"
        );

        // Cross-decode with our own multipart decoder (this is exactly what
        // lmfd's SbiServer layer runs on receipt) — the binary N1 part must be
        // the LPP PDU verbatim (transparent relay, TS 23.273 §6.11.2).
        let decoded = nextgcore_sbi::multipart::decode(
            &nextgcore_sbi::multipart::content_type_with_boundary("gold"),
            &body,
        )
        .expect("multipart decode");
        assert_eq!(decoded.json.as_deref(), Some(json.as_str()));
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].content_id.as_deref(), Some("n1-lpp"));
        assert_eq!(
            decoded.parts[0].content_type.as_deref(),
            Some("application/vnd.3gpp.5gnas")
        );
        assert_eq!(decoded.parts[0].data.as_ref(), &lpp[..]);
    }

    #[test]
    fn n1_message_notify_optional_fields_omitted() {
        // Absent n1NotifySubscriptionId / lcsCorrelationId / supi must be
        // OMITTED (never null, never fabricated) — fail-closed producer.
        let req = build_n1_message_notify_request("/cb", None, "LPP", None, None, &[0x01])
            .expect("build N1MessageNotify");
        let v: Value = serde_json::from_str(req.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(v["n1MessageContainer"]["n1MessageClass"], "LPP");
        assert_eq!(
            v["n1MessageContainer"]["n1MessageContent"]["contentId"],
            "n1-lpp"
        );
        assert!(v.get("n1NotifySubscriptionId").is_none());
        assert!(v.get("lcsCorrelationId").is_none());
        assert!(v.get("supi").is_none());
    }

    /// Wave-6 A4 canary: the no-LMF-subscription fallback of `forward_ul_lpp_to_lmf`
    /// builds the DL NAS TRANSPORT with 5GMM cause #90 exactly as the pre-A4
    /// code did. Pins the `gmm_build::build_dl_nas_transport` output (the whole
    /// content of that fallback branch) to a hand-derived byte vector so a
    /// regression in the legacy abnormal action is caught (the branch itself is
    /// verbatim-preserved — see `forward_ul_lpp_to_lmf`).
    #[test]
    fn a4_no_subscription_dl_nas_90_is_byte_identical() {
        use crate::gmm_build::GmmCause;
        // container_type 5 = LPP (TS 24.501 §9.11.3.40 payload container type);
        // the LPP payload is echoed back verbatim in the DL NAS TRANSPORT.
        let lpp = [0xAAu8, 0xBB, 0xCC];
        let dl = crate::gmm_build::build_dl_nas_transport(
            None,
            0x05,
            &lpp,
            Some(GmmCause::PayloadWasNotForwarded),
            None,
        )
        .expect("build DL NAS transport");
        // 5GMM header: EPD 0x7E, security-header 0x00, msg-type 0x68 (DL NAS
        // TRANSPORT); spare-half-octet + payload-container-type 0x05; container
        // length 0x0003 + the 3 payload bytes; then the 5GMM-cause IEI 0x58 +
        // value 0x5A (#90, payload not forwarded).
        assert_eq!(
            dl,
            vec![0x7E, 0x00, 0x68, 0x05, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x58, 0x5A],
            "the #90 fallback DL NAS bytes must be byte-identical to the pre-A4 legacy action"
        );
    }

    fn n1n2_subscription_body(port_tag: &str) -> Value {
        json!({
            "n1MessageClass": "LPP",
            "n1NotifyCallbackUri": format!("http://127.0.0.1:7777/nlmf-loc/v1/notify/n1/{port_tag}"),
            "n2InformationClass": "NRPPa",
            "n2NotifyCallbackUri": format!("http://127.0.0.1:7777/nlmf-loc/v1/notify/n2/{port_tag}"),
            "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "supportedFeatures": "0",
        })
    }

    fn n1n2_subscription_request(ue_context_id: &str, body: &Value) -> SbiRequest {
        SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages/subscriptions"
        ))
        .with_json_body(body)
        .expect("json")
    }

    /// Create -> 201 with the yaml:1503 Location structure +
    /// UeN1N2InfoSubscriptionCreatedData; the store serves class-keyed
    /// lookups; DELETE -> 204; second DELETE -> 404.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_subscription_create_201_location_delete_204() {
        let supi = "imsi-001010000060070";
        setup_ue(supi, true, true);

        let body = n1n2_subscription_body("a");
        let resp = namf_request_handler(n1n2_subscription_request(supi, &body)).await;
        assert_eq!(resp.status, 201);

        // UeN1N2InfoSubscriptionCreatedData: n1n2NotifySubscriptionId required
        let created = body_json(&resp);
        let sub_id = created["n1n2NotifySubscriptionId"]
            .as_str()
            .expect("n1n2NotifySubscriptionId missing")
            .to_string();
        assert!(!sub_id.is_empty());

        // Location header structure per yaml:1503:
        // {apiRoot}/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/subscriptions/{subscriptionId}
        let location = resp
            .http
            .get_header("location")
            .expect("Location header missing")
            .to_string();
        assert_eq!(
            location,
            format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions/{sub_id}")
        );

        // The registry serves class-keyed lookups with the stored URIs
        let ctx = amf_self();
        {
            let guard = ctx.read().expect("ctx lock");
            let n1 = guard
                .n1n2_subscription_find_n1(supi, "LPP")
                .expect("LPP subscription not stored");
            assert_eq!(
                n1.n1_notify_callback_uri.as_deref(),
                body["n1NotifyCallbackUri"].as_str()
            );
            let n2 = guard
                .n1n2_subscription_find_n2(supi, "NRPPa")
                .expect("NRPPa subscription not stored");
            assert_eq!(
                n2.n2_notify_callback_uri.as_deref(),
                body["n2NotifyCallbackUri"].as_str()
            );
            // Fail-closed: a class we never stored is never returned
            assert!(guard.n1n2_subscription_find_n1(supi, "SMS").is_none());
        }

        // UnSubscribe: 204, then 404 CONTEXT_NOT_FOUND
        let del = SbiRequest::delete(format!(
            "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions/{sub_id}"
        ));
        let resp = namf_request_handler(del).await;
        assert_eq!(resp.status, 204);

        let del = SbiRequest::delete(format!(
            "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions/{sub_id}"
        ));
        let resp = namf_request_handler(del).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    /// Fail-closed mandatory-IE validation: a body without at least one
    /// complete (class, callback URI) pair is rejected 400
    /// MANDATORY_IE_MISSING — never silently accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_subscription_missing_pair_400() {
        let supi = "imsi-001010000060071";
        setup_ue(supi, true, true);

        // Only n1MessageClass (no callback URI) — the acceptance case
        let resp = namf_request_handler(n1n2_subscription_request(
            supi,
            &json!({ "n1MessageClass": "LPP" }),
        ))
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Only n1NotifyCallbackUri (no class)
        let resp = namf_request_handler(n1n2_subscription_request(
            supi,
            &json!({ "n1NotifyCallbackUri": "http://127.0.0.1:7777/cb" }),
        ))
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Empty body: no pair at all
        let resp = namf_request_handler(n1n2_subscription_request(supi, &json!({}))).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Complete N1 pair but a dangling n2InformationClass half-pair
        let resp = namf_request_handler(n1n2_subscription_request(
            supi,
            &json!({
                "n1MessageClass": "LPP",
                "n1NotifyCallbackUri": "http://127.0.0.1:7777/cb",
                "n2InformationClass": "NRPPa",
            }),
        ))
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Malformed callback URI
        let resp = namf_request_handler(n1n2_subscription_request(
            supi,
            &json!({
                "n1MessageClass": "LPP",
                "n1NotifyCallbackUri": "not-a-uri",
            }),
        ))
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // Malformed body never panics
        let mut req = SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions"
        ));
        req.http.set_content("{{{{");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // Nothing was stored by any of the rejected requests
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        assert_eq!(guard.n1n2_subscription_count(supi), 0);
    }

    /// Unknown ueContextId -> 404 CONTEXT_NOT_FOUND
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_subscription_unknown_ue_404() {
        amf_context_init(64, 1024, 4096);
        let resp = namf_request_handler(n1n2_subscription_request(
            "imsi-999999999999999",
            &n1n2_subscription_body("b"),
        ))
        .await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    /// Two subscriptions on one UE coexist and are independently addressable
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_subscription_two_coexist() {
        let supi = "imsi-001010000060042";
        setup_ue(supi, true, true);

        let resp1 = namf_request_handler(n1n2_subscription_request(
            supi,
            &json!({
                "n1MessageClass": "LPP",
                "n1NotifyCallbackUri": "http://127.0.0.1:7777/notify/n1",
            }),
        ))
        .await;
        assert_eq!(resp1.status, 201);
        let resp2 = namf_request_handler(n1n2_subscription_request(
            supi,
            &json!({
                "n2InformationClass": "NRPPa",
                "n2NotifyCallbackUri": "http://127.0.0.1:7777/notify/n2",
            }),
        ))
        .await;
        assert_eq!(resp2.status, 201);

        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        assert_eq!(guard.n1n2_subscription_count(supi), 2);
        assert_eq!(
            guard
                .n1n2_subscription_find_n1(supi, "LPP")
                .and_then(|s| s.n1_notify_callback_uri),
            Some("http://127.0.0.1:7777/notify/n1".to_string())
        );
        assert_eq!(
            guard
                .n1n2_subscription_find_n2(supi, "NRPPa")
                .and_then(|s| s.n2_notify_callback_uri),
            Some("http://127.0.0.1:7777/notify/n2".to_string())
        );
    }

    /// A positioning N1N2MessageTransfer carrying lcsCorrelationId /
    /// servingLMFIdentification records the fallback correlation on the UE
    /// context (TS 29.518 N1N2MessageTransferReqData, yaml:2771-2774).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_lpp_transfer_captures_lcs_correlation() {
        let supi = "imsi-001010000060043";
        setup_ue(supi, true, true);

        let body = json!({
            "n1MessageContainer": {
                "n1MessageClass": "LPP",
                "n1MessageContent": { "contentId": "lpp-pdu" }
            },
            "lcsCorrelationId": "lcs-corr-0001",
            "servingLMFIdentification": "LMF-0001",
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "lpp-pdu",
                "application/vnd.3gpp.lpp",
                bytes::Bytes::from_static(&[0x90, 0x01, 0x20, 0x09, 0x30]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);

        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let record = guard
            .lcs_correlation_find(supi)
            .expect("fallback LCS correlation not captured");
        assert_eq!(record.lcs_correlation_id, "lcs-corr-0001");
        assert_eq!(
            record.serving_lmf_identification.as_deref(),
            Some("LMF-0001")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_idle_ue_paging_202() {
        let supi = "imsi-001010000060021";
        let ue = setup_ue(supi, false, false);
        setup_sess(&ue, 6);

        // No N1 message, idle UE -> network-triggered service request: 202
        let body = n1n2_body(6, false, false, None);
        let resp = namf_request_handler(n1n2_request(supi, &body, false)).await;
        assert_eq!(resp.status, 202);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("ATTEMPTING_TO_REACH_UE")
        );
        assert!(resp.http.get_header("location").is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_missing_mandatory_attrs() {
        let supi = "imsi-001010000060022";
        let ue = setup_ue(supi, true, true);
        setup_sess(&ue, 7);

        // Neither n1MessageContainer nor n2InfoContainer
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&json!({ "pduSessionId": 7 }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // n2InfoContainer without smInfo.pduSessionId
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&json!({
                "n2InfoContainer": { "n2InformationClass": "SM", "smInfo": {
                    "n2InfoContent": { "ngapIeType": "PDU_RES_SETUP_REQ" } } }
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Referenced binary part missing
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&json!({
                "pduSessionId": 7,
                "n1MessageContainer": {
                    "n1MessageClass": "SM",
                    "n1MessageContent": { "contentId": "no-such-part" },
                },
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // Malformed body never panics
        let mut req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"));
        req.http.set_content("{{{{");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_unknown_ue_404() {
        amf_context_init(64, 1024, 4096);
        let body = n1n2_body(1, false, false, None);
        let resp = namf_request_handler(n1n2_request("imsi-001019999999999", &body, false)).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_failure_callback_http_delivery() {
        // This test drives production code against a loopback PLAINTEXT peer, i.e.
        // it describes a dev-profile deployment (issue #63). Declared explicitly
        // rather than inherited from the environment.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Idle UE + PDU_RES_REL_CMD + skipInd: N1 message is not transferred,
        // the response is 504 UE_NOT_REACHABLE and the failure notification
        // is POSTed to n1n2FailureTxfNotifURI.
        let supi = "imsi-001010000060023";
        let ue = setup_ue(supi, false, false);
        setup_sess(&ue, 8);

        let (server, port, mut rx) = start_capture_server().await;
        let failure_uri = format!("http://127.0.0.1:{port}/smf-n1n2-failure");

        let body = json!({
            "pduSessionId": 8,
            "skipInd": true,
            "n1n2FailureTxfNotifURI": failure_uri,
            "n2InfoContainer": {
                "n2InformationClass": "SM",
                "smInfo": {
                    "pduSessionId": 8,
                    "n2InfoContent": {
                        "ngapIeType": "PDU_RES_REL_CMD",
                        "ngapData": { "contentId": "ngap-sm" },
                    },
                },
            },
        });
        let resp = namf_request_handler(n1n2_request(supi, &body, false)).await;
        assert_eq!(resp.status, 504);
        let err = body_json(&resp);
        assert_eq!(err["error"]["cause"].as_str(), Some("UE_NOT_REACHABLE"));

        let (uri, posted) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("failure notification not delivered within 3s")
            .expect("capture channel closed");
        assert_eq!(uri, "/smf-n1n2-failure");
        let posted: Value = serde_json::from_str(&posted).expect("failure body JSON");
        // Both mandatory attributes of N1N2MsgTxfrFailureNotification
        assert_eq!(posted["cause"].as_str(), Some("UE_NOT_REACHABLE"));
        assert!(posted["n1n2MsgDataUri"]
            .as_str()
            .expect("n1n2MsgDataUri")
            .contains(supi));

        server.stop().await.expect("server stop");
    }

    // ------------------------------------------------------------------
    // Namf_Communication — UEContextTransfer + RegistrationStatusUpdate
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ue_context_transfer_roundtrip() {
        let supi = "imsi-001010000060030";
        let ue = setup_ue(supi, true, true);
        setup_sess(&ue, 9);

        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "reason": "INIT_REG", "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        let ue_context = &body["ueContext"];
        assert_eq!(ue_context["supi"].as_str(), Some(supi));
        // mmContextList mandatory attrs are encoded
        let mm = &ue_context["mmContextList"][0];
        assert_eq!(mm["accessType"].as_str(), Some("3GPP_ACCESS"));
        assert!(mm["nasSecurityMode"]["integrityAlgorithm"]
            .as_str()
            .is_some());
        // session context carries its mandatory attrs
        let sess_ctx = &ue_context["sessionContextList"][0];
        assert_eq!(sess_ctx["pduSessionId"].as_u64(), Some(9));
        assert_eq!(sess_ctx["smContextRef"].as_str(), Some("smctx-9"));
        assert_eq!(sess_ctx["dnn"].as_str(), Some("internet"));
        assert!(sess_ctx["sNssai"]["sst"].as_u64().is_some());

        // Transfer state moved to old-AMF side
        let ctx = amf_self();
        let stored = ctx.read().unwrap().amf_ue_find_by_supi(supi).unwrap();
        assert_eq!(
            stored.amf_ue_context_transfer_state,
            UeContextTransferState::TransferOldAmf
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ue_context_transfer_error_paths() {
        // Unique SUPI: the process-global AMF context (supi_hash) is shared by
        // every test in this binary and amf_context_init is a one-shot OnceLock
        // that never clears it. `imsi-001010000060031` is also registered by
        // test_n1n2_nrppa_to_connected_ue_relays with security_context_available
        // = true; reusing it raced that UE into supi_hash, so this MOBI_REG
        // integrity check found a UE *with* a security context and passed (200)
        // instead of failing (403). A SUPI no other test registers keeps this
        // error path deterministic.
        let supi = "imsi-001010000060033";
        setup_ue(supi, true, false); // no security context

        // 404 for unknown UE (CONTEXT_NOT_FOUND per TS 29.518 §6.1.7.3)
        let req = SbiRequest::post("/namf-comm/v1/ue-contexts/imsi-00101888/transfer")
            .with_json_body(&json!({ "reason": "INIT_REG", "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");

        // Missing mandatory `reason`
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Missing mandatory `accessType`
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "reason": "INIT_REG" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // MOBI_REG without regRequest is rejected
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "reason": "MOBI_REG", "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // MOBI_REG with regRequest but no valid security context: 403
        // INTEGRITY_CHECK_FAIL (TS 29.518 §5.2.2.2.1.1)
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({
                "reason": "MOBI_REG",
                "accessType": "3GPP_ACCESS",
                "regRequest": { "n1MessageContent": { "contentId": "reg-req" } },
            }))
            .expect("json")
            .with_part(SbiPart::with_content(
                "reg-req",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::from_static(&[0x7e, 0x00, 0x41]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 403);
        assert_eq!(problem_cause(&resp), "INTEGRITY_CHECK_FAIL");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_registration_status_update() {
        let supi = "imsi-001010000060032";
        let ue = setup_ue(supi, true, true);
        let _sess = setup_sess(&ue, 10);

        // TRANSFERRED with a session to release
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer-update"))
            .with_json_body(&json!({
                "transferStatus": "TRANSFERRED",
                "toReleaseSessionList": [10],
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["regStatusTransferComplete"].as_bool(),
            Some(true)
        );
        let ctx = amf_self();
        {
            let guard = ctx.read().unwrap();
            let stored = guard.amf_ue_find_by_supi(supi).unwrap();
            assert_eq!(
                stored.amf_ue_context_transfer_state,
                UeContextTransferState::RegistrationStatusUpdateOldAmf
            );
            let sess = guard.sess_find_by_psi(ue.id, 10).unwrap();
            assert!(sess.n1_released && sess.n2_released);
        }

        // Missing mandatory transferStatus
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer-update"))
            .with_json_body(&json!({}))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Invalid enum value
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer-update"))
            .with_json_body(&json!({ "transferStatus": "MAYBE" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // Unknown UE
        let req = SbiRequest::post("/namf-comm/v1/ue-contexts/imsi-00101777/transfer-update")
            .with_json_body(&json!({ "transferStatus": "TRANSFERRED" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
    }

    /// #352 criterion 5: a `UEContextTransfer` addressed by **5G-GUTI** reaches the
    /// UE, through the real HTTP router.
    ///
    /// This is the shape every conformant consumer uses and the only shape a real
    /// one *can* use: TS 29.518 §5.2.2.2.1.1 has the target AMF invoke `transfer`
    /// on the resource "identified by UE's 5G-GUTI", and at that point in TS 23.502
    /// §4.2.2.2.2 the target AMF has no SUPI — obtaining it is the point of the
    /// call. Before this, `find_ue_by_context_id` handled `imsi-`/`nai-` only, so
    /// every such request became `404 CONTEXT_NOT_FOUND` and the producer was
    /// unreachable in its only real use.
    ///
    /// The assertion is POSITIVE and on state reachable only through the GUTI
    /// lookup: the response body must carry the SUPI this AMF holds for that GUTI.
    /// A consumer supplies the GUTI and nothing else, so returning the right SUPI
    /// is only possible if the GUTI resolved to the right UE. An
    /// `assert_ne!(status, 404)` would also be satisfied by a 400 or a 500.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_ue_context_transfer_addressed_by_5g_guti_resolves_the_ue() {
        // A SUPI and a 5G-TMSI no sibling test uses. The AMF context is
        // process-global and `amf_context_init` is a one-shot `OnceLock` that never
        // clears, so a shared SUPI or GUTI would have two tests resolve each
        // other's UE -- the `test_ue_context_transfer_error_paths` flake class.
        let supi = "imsi-001010000060352";
        let mut ue = setup_ue(supi, true, true);

        let guti = crate::context::Guti5gs {
            plmn_id: crate::context::PlmnId::new("001", "01"),
            amf_region_id: 0x02,
            amf_set_id: 0x001,
            amf_pointer: 0x00,
            tmsi: 0x0352_0001,
        };
        ue.current_guti = guti.clone();
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.amf_ue_update(&ue);
            // Republish so the LIVE store (#341) carries the GUTI: the derived
            // resolver reads the store, and `amf_ue_update` alone writes the record
            // the store already holds without re-keying anything.
            guard.amf_ue_publish(&ue, 900_352, 1);
        }

        let ue_context_id = guti.to_context_id();
        assert!(
            ue_context_id.starts_with("5g-guti-"),
            "precondition: the path component is the 5G-GUTI form, got {ue_context_id}"
        );

        let req = SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{ue_context_id}/transfer"
        ))
        .with_json_body(&json!({ "reason": "INIT_REG", "accessType": "3GPP_ACCESS" }))
        .expect("json");
        let resp = namf_request_handler(req).await;

        assert_eq!(
            resp.status, 200,
            "a 5g-guti ueContextId must address the UE (TS 29.518 §6.1.3.2.2)"
        );
        assert_eq!(
            body_json(&resp)["ueContext"]["supi"].as_str(),
            Some(supi),
            "the transferred context must be the UE holding that GUTI -- this is the \
             SUPI the consumer called to obtain, and it had only the GUTI to ask with"
        );

        // A well-formed GUTI that matches no UE is a 404, not a mis-resolve to
        // whichever UE happens to be first in the store.
        let unknown = crate::context::Guti5gs {
            tmsi: 0x0352_9999,
            ..guti.clone()
        };
        let req = SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{}/transfer",
            unknown.to_context_id()
        ))
        .with_json_body(&json!({ "reason": "INIT_REG", "accessType": "3GPP_ACCESS" }))
        .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    /// The consumer's `RegistrationStatusUpdate` is also GUTI-addressed, because it
    /// closes the procedure the GUTI-addressed transfer opened (TS 29.518
    /// §5.2.2.2.2). Asserted separately from the transfer: the two are different
    /// router arms, and `transfer-update` working by SUPI proves nothing about the
    /// path a real consumer takes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_registration_status_update_addressed_by_5g_guti_resolves_the_ue() {
        // Distinct SUPI and 5G-TMSI from every sibling, for the process-global
        // reason documented on the transfer test above.
        let supi = "imsi-001010000060353";
        let mut ue = setup_ue(supi, true, true);
        let guti = crate::context::Guti5gs {
            plmn_id: crate::context::PlmnId::new("001", "01"),
            amf_region_id: 0x02,
            amf_set_id: 0x001,
            amf_pointer: 0x00,
            tmsi: 0x0353_0001,
        };
        ue.current_guti = guti.clone();
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.amf_ue_update(&ue);
            guard.amf_ue_publish(&ue, 900_353, 1);
        }

        let req = SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{}/transfer-update",
            guti.to_context_id()
        ))
        .with_json_body(&json!({ "transferStatus": "TRANSFERRED" }))
        .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);

        // Positive assertion on state only the GUTI lookup could have reached: the
        // old-AMF-side transfer state is recorded against the UE that holds the
        // GUTI, keyed here by SUPI so the read does not reuse the write's path.
        let ctx = amf_self();
        let stored = ctx
            .read()
            .expect("ctx lock")
            .amf_ue_find_by_supi(supi)
            .expect("the UE is present");
        assert_eq!(
            stored.amf_ue_context_transfer_state,
            UeContextTransferState::RegistrationStatusUpdateOldAmf,
            "the GUTI must have resolved to THIS UE for its transfer state to move"
        );
    }

    // ------------------------------------------------------------------
    // Namf_MT — EnableUeReachability
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mt_enable_ue_reachability() {
        let connected_supi = "imsi-001010000060040";
        setup_ue(connected_supi, true, true);
        let idle_supi = "imsi-001010000060041";
        setup_ue(idle_supi, false, true);

        // CM-CONNECTED UE: 200 with mandatory reachability attribute
        let req = SbiRequest::post(format!(
            "/namf-mt/v1/ue-contexts/{connected_supi}/ue-reachind"
        ))
        .with_json_body(&json!({ "reachability": "REACHABLE" }))
        .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(body_json(&resp)["reachability"].as_str(), Some("REACHABLE"));

        // CM-IDLE UE: 504 UE_NOT_REACHABLE per TS 29.518 §6.3.7.3
        let req = SbiRequest::post(format!("/namf-mt/v1/ue-contexts/{idle_supi}/ue-reachind"))
            .with_json_body(&json!({ "reachability": "REACHABLE" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 504);
        assert_eq!(problem_cause(&resp), "UE_NOT_REACHABLE");

        // Missing mandatory reachability
        let req = SbiRequest::post(format!(
            "/namf-mt/v1/ue-contexts/{connected_supi}/ue-reachind"
        ))
        .with_json_body(&json!({}))
        .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Unknown UE
        let req = SbiRequest::post("/namf-mt/v1/ue-contexts/imsi-00101666/ue-reachind")
            .with_json_body(&json!({ "reachability": "REACHABLE" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    // ------------------------------------------------------------------
    // Namf_Location — ProvidePositioningInfo
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_loc_provide_pos_info() {
        let supi = "imsi-001010000060050";
        setup_ue(supi, true, true);

        let req = SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
            .with_json_body(&json!({
                "lcsClientType": "EXTERNAL",
                "lcsLocation": "CURRENT_LOCATION",
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        // The AMF returns what it knows: the serving cell (NCGI from NGAP)
        assert_eq!(body["ncgi"]["nrCellId"].as_str(), Some("000012345"));
        assert!(body["ncgi"]["plmnId"]["mcc"].as_str().is_some());

        // Missing mandatory lcsClientType
        let req = SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
            .with_json_body(&json!({ "lcsLocation": "CURRENT_LOCATION" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Missing mandatory lcsLocation
        let req = SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
            .with_json_body(&json!({ "lcsClientType": "EXTERNAL" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // Unknown UE
        let req = SbiRequest::post("/namf-loc/v1/imsi-00101555/provide-pos-info")
            .with_json_body(&json!({
                "lcsClientType": "EXTERNAL", "lcsLocation": "CURRENT_LOCATION" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    // ------------------------------------------------------------------
    // Full HTTP/2 round-trip through the real server
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_namf_server_http_roundtrip() {
        amf_context_init(64, 1024, 4096);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let server = SbiServer::on_listener(SbiServerConfig::new(addr), port_listener);
        server
            .start(namf_request_handler)
            .await
            .expect("namf server start");

        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Strict peer over real HTTP/2: missing mandatory attr -> 400
        let bad = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&json!({ "subscription": { "anyUE": true } }))
            .expect("json");
        let resp = tokio::time::timeout(Duration::from_secs(3), client.send_request(bad))
            .await
            .expect("request timed out")
            .expect("request failed");
        assert_eq!(resp.status, 400);
        assert_eq!(
            resp.http.get_header("content-type").map(String::as_str),
            Some("application/problem+json")
        );

        // Valid subscription -> 201 over the wire
        let good = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&subscription_body(
                "imsi-001010000060060",
                "http://127.0.0.1:9/cb",
                "LOCATION_REPORT",
            ))
            .expect("json");
        let resp = tokio::time::timeout(Duration::from_secs(3), client.send_request(good))
            .await
            .expect("request timed out")
            .expect("request failed");
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // DELETE over the wire -> 204
        let del = SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{sub_id}"));
        let resp = tokio::time::timeout(Duration::from_secs(3), client.send_request(del))
            .await
            .expect("request timed out")
            .expect("request failed");
        assert_eq!(resp.status, 204);

        server.stop().await.expect("server stop");
    }

    // ======================================================================
    // WSB-4: Namf_Callback dereg-notify router arm (TS 29.503 §5.3.2.3.2)
    // ======================================================================

    use super::dereg_queue_test_lock;

    /// Drain the process-global network-dereg queue, keep only this UE's items
    /// and re-add the rest (queue is process-global; parallel tests must not
    /// steal each other's enqueues).
    fn drain_network_deregs_for(ue_id: u64) -> Vec<crate::context::PendingNetworkDereg> {
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let (mine, others): (Vec<_>, Vec<_>) = guard
            .network_dereg_drain()
            .into_iter()
            .partition(|d| d.amf_ue_ngap_id == ue_id);
        for item in others {
            guard.network_dereg_add(item);
        }
        mine
    }

    /// A known SUPI + a full DeregistrationData (UE_INITIAL_REGISTRATION,
    /// 3GPP_ACCESS) POSTed through the real router -> 204 and exactly one
    /// network-initiated dereg enqueued with reregistration_required=true.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dereg_notify_callback_204_enqueues_event() {
        let _serial = dereg_queue_test_lock().lock().await;
        let supi = "imsi-001010000070401";
        let ue = setup_ue(supi, true, true);

        let body = json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "3GPP_ACCESS" });
        let req = SbiRequest::post(format!("/namf-callback/v1/{supi}/dereg-notify"))
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 204, "known SUPI + full body -> 204");

        let queued = drain_network_deregs_for(ue.id);
        assert_eq!(queued.len(), 1, "exactly one dereg event enqueued");
        assert_eq!(queued[0].amf_ue_ngap_id, ue.id);
        assert!(queued[0].reregistration_required);
        assert_eq!(queued[0].gmm_cause, None);
    }

    /// SUBSCRIPTION_WITHDRAWN -> reregistration_required=false.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dereg_notify_callback_subscription_withdrawn_no_rereg() {
        let _serial = dereg_queue_test_lock().lock().await;
        let supi = "imsi-001010000070405";
        let ue = setup_ue(supi, true, true);

        let body = json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN", "accessType": "3GPP_ACCESS" });
        let req = SbiRequest::post(format!("/namf-callback/v1/{supi}/dereg-notify"))
            .with_json_body(&body)
            .expect("json");
        assert_eq!(namf_request_handler(req).await.status, 204);

        let queued = drain_network_deregs_for(ue.id);
        assert_eq!(queued.len(), 1);
        assert!(!queued[0].reregistration_required);
    }

    /// Unknown SUPI -> 404 CONTEXT_NOT_FOUND.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dereg_notify_callback_404_unknown_supi() {
        amf_context_init(64, 1024, 4096);
        let supi = "imsi-001010000079999"; // never added
        let body = json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "3GPP_ACCESS" });
        let req = SbiRequest::post(format!("/namf-callback/v1/{supi}/dereg-notify"))
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(body_json(&resp)["cause"], "CONTEXT_NOT_FOUND");
    }

    /// Missing mandatory accessType -> 400 (fail-closed), no event enqueued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dereg_notify_callback_400_missing_access_type() {
        let _serial = dereg_queue_test_lock().lock().await;
        let supi = "imsi-001010000070402";
        let ue = setup_ue(supi, true, true);

        let body = json!({ "deregReason": "UE_INITIAL_REGISTRATION" });
        let req = SbiRequest::post(format!("/namf-callback/v1/{supi}/dereg-notify"))
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400, "missing accessType must fail closed");
        assert!(drain_network_deregs_for(ue.id).is_empty());
    }

    /// Missing mandatory deregReason -> 400 (fail-closed).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dereg_notify_callback_400_missing_reason() {
        let supi = "imsi-001010000070403";
        setup_ue(supi, true, true);
        let body = json!({ "accessType": "3GPP_ACCESS" });
        let req = SbiRequest::post(format!("/namf-callback/v1/{supi}/dereg-notify"))
            .with_json_body(&body)
            .expect("json");
        assert_eq!(namf_request_handler(req).await.status, 400);
    }

    /// Non-3GPP access -> 204 accepted but no 3GPP dereg enqueued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dereg_notify_callback_non_3gpp_no_enqueue() {
        let _serial = dereg_queue_test_lock().lock().await;
        let supi = "imsi-001010000070404";
        let ue = setup_ue(supi, true, true);
        let body =
            json!({ "deregReason": "UE_INITIAL_REGISTRATION", "accessType": "NON_3GPP_ACCESS" });
        let req = SbiRequest::post(format!("/namf-callback/v1/{supi}/dereg-notify"))
            .with_json_body(&body)
            .expect("json");
        assert_eq!(namf_request_handler(req).await.status, 204);
        assert!(drain_network_deregs_for(ue.id).is_empty());
    }
    // ---- #117: EBIAssignment (TS 29.518 §6.1.6.2.5) --------------------------

    /// Through the ROUTER, not by calling the handler directly: the routing arm
    /// is half of criterion 1, and a test that called `handle_assign_ebi` would
    /// pass with the arm absent (a 405, in production).
    fn assign_ebi_request(supi: &str, body: Value) -> SbiResponse {
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/assign-ebi"))
            .with_body(body.to_string(), "application/json");
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(namf_request_handler(req))
    }

    fn arp(priority: u8) -> Value {
        json!({
            "priorityLevel": priority,
            "preemptCap": "NOT_PREEMPT",
            "preemptVuln": "PREEMPTABLE",
        })
    }

    /// #117 criterion 1: the operation is routed, allocates from a per-UE pool,
    /// and answers an `AssignedEbiData` of the shape TS 29.518 declares.
    ///
    /// The shape assertions are against the yaml, not against what this
    /// implementation happens to emit: `pduSessionId` and `assignedEbiList` are
    /// the two `required` members, `assignedEbiList` items are `EbiArpMapping`
    /// (`epsBearerId` + `arp`, both required), and the three optional lists are
    /// `minItems: 1` — so each must be ABSENT rather than empty, which is the part
    /// a "just serialise the struct" implementation gets wrong.
    #[test]
    fn assign_ebi_allocates_from_a_per_ue_pool_and_answers_assigned_ebi_data() {
        let supi = "imsi-001010000000117";
        setup_ue(supi, true, true);

        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "arpList": [arp(1), arp(8)],
            }),
        );
        assert_eq!(resp.status, 200, "body: {:?}", resp.http.content);
        let body = body_json(&resp);

        assert_eq!(body["pduSessionId"], json!(5));
        let assigned = body["assignedEbiList"]
            .as_array()
            .expect("assignedEbiList is a required member of AssignedEbiData");
        assert_eq!(assigned.len(), 2, "one EBI per ARP entry");

        // TS 24.301 §9.3.2: 0..=4 are reserved, so an assignment inside them would
        // collide with the EPS reserved space.
        for (i, entry) in assigned.iter().enumerate() {
            let ebi = entry["epsBearerId"].as_u64().expect("epsBearerId required");
            assert!(
                (5..=15).contains(&ebi),
                "EBI {ebi} is outside the assignable range 5..=15"
            );
            assert_eq!(
                entry["arp"]["priorityLevel"],
                json!(if i == 0 { 1 } else { 8 }),
                "each mapping must carry back the ARP it was requested with"
            );
            assert_eq!(entry["arp"]["preemptCap"], json!("NOT_PREEMPT"));
            assert_eq!(entry["arp"]["preemptVuln"], json!("PREEMPTABLE"));
        }
        let first = assigned[0]["epsBearerId"].as_u64().expect("ebi");
        let second = assigned[1]["epsBearerId"].as_u64().expect("ebi");
        assert_ne!(first, second, "two flows must not share one EBI");

        // minItems: 1 on all three, so an empty array is not a legal value.
        for optional in ["failedArpList", "releasedEbiList", "modifiedEbiList"] {
            assert!(
                body.get(optional).is_none(),
                "{optional} is minItems:1, so it must be absent rather than empty"
            );
        }

        // A SECOND request for the same UE must not hand out the same EBIs: the
        // pool is per-UE and spans every one of its PDU sessions.
        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 6,
                "arpList": [arp(2)],
            }),
        );
        assert_eq!(resp.status, 200);
        let third = body_json(&resp)["assignedEbiList"][0]["epsBearerId"]
            .as_u64()
            .expect("ebi");
        assert!(
            third != first && third != second,
            "EBI {third} was already assigned to another session of this UE"
        );
    }

    /// Release frees an EBI for reuse, and it happens BEFORE assignment inside one
    /// request — a request that releases 5 and asks for one more must be able to
    /// hand 5 straight back out.
    #[test]
    fn assign_ebi_releases_before_it_assigns_so_a_freed_ebi_is_reusable() {
        let supi = "imsi-001010000000118";
        setup_ue(supi, true, true);

        let first = body_json(&assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "arpList": [arp(1)],
            }),
        ))["assignedEbiList"][0]["epsBearerId"]
            .as_u64()
            .expect("ebi");

        let body = body_json(&assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "releasedEbiList": [first],
                "arpList": [arp(3)],
            }),
        ));
        assert_eq!(
            body["releasedEbiList"],
            json!([first]),
            "the release must be reported back"
        );
        assert_eq!(
            body["assignedEbiList"][0]["epsBearerId"],
            json!(first),
            "the EBI freed in this same request must be reassignable within it"
        );
    }

    /// Pool exhaustion is a modelled outcome. Eleven EBIs is also the most EPS
    /// bearers a UE can hold, so a twelfth is a request for something that cannot
    /// exist — and the SMF has to be told WHICH flows went without one, which is
    /// what `failedArpList` is for.
    #[test]
    fn assign_ebi_reports_exhaustion_rather_than_inventing_an_ebi() {
        let supi = "imsi-001010000000119";
        setup_ue(supi, true, true);

        // Eleven assignable identities: 5..=15.
        let eleven: Vec<Value> = (1..=11).map(|i| arp((i % 15) + 1)).collect();
        let body = body_json(&assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "arpList": eleven,
            }),
        ));
        assert_eq!(
            body["assignedEbiList"].as_array().expect("list").len(),
            11,
            "all eleven assignable EBIs must be usable"
        );
        assert!(body.get("failedArpList").is_none());

        // Partial: one more ARP with nothing left. Every ARP failed and none was
        // assigned, so TS 29.518's 403 + AssignEbiError applies.
        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 6,
                "arpList": [arp(4)],
            }),
        );
        assert_eq!(resp.status, 403, "body: {:?}", resp.http.content);
        let body = body_json(&resp);
        assert_eq!(
            body["error"]["cause"],
            json!("INSUFFICIENT_RESOURCES"),
            "AssignEbiError.error is required and carries the ProblemDetails"
        );
        assert_eq!(
            body["failureDetails"]["pduSessionId"],
            json!(6),
            "AssignEbiError.failureDetails is required"
        );
        assert_eq!(
            body["failureDetails"]["failedArpList"][0]["priorityLevel"],
            json!(4),
            "the SMF must learn WHICH flow got no EBI"
        );

        // Partial success: free two, ask for three. Two are assigned and one fails,
        // which is a 200 carrying both lists -- not a 403.
        let held: Vec<u64> = body_json(&assign_ebi_request(supi, json!({"pduSessionId": 5})))
            .get("assignedEbiList")
            .and_then(Value::as_array)
            .map(|_| Vec::new())
            .unwrap_or_default();
        assert!(held.is_empty(), "a request with no arpList assigns nothing");

        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "releasedEbiList": [5, 6],
                "arpList": [arp(1), arp(2), arp(3)],
            }),
        );
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        assert_eq!(body["assignedEbiList"].as_array().expect("list").len(), 2);
        assert_eq!(
            body["failedArpList"]
                .as_array()
                .expect("failedArpList")
                .len(),
            1,
            "a partial failure is a 200 carrying both lists, not a 403"
        );
    }

    /// #291 criterion 2: twelve sequential establish/release cycles for one UE keep
    /// succeeding — and the same twelve WITHOUT the release do not.
    ///
    /// Both halves are the point. The first proves the SMF's `releasedEbiList`
    /// (#291) makes the space reusable; the second pins what the leak actually did,
    /// so a future change that stops honouring the release fails here rather than in
    /// a deployment eleven session-lifetimes later. Eleven cycles is nothing: a UE
    /// that re-attaches on the way to work reaches it inside a week.
    #[test]
    fn twelve_establish_release_cycles_keep_getting_an_ebi_and_twelve_without_release_do_not() {
        let supi = "imsi-001010000000291";
        setup_ue(supi, true, true);

        let mut assigned = Vec::new();
        for cycle in 1..=12u8 {
            let resp = assign_ebi_request(supi, json!({ "pduSessionId": 5, "arpList": [arp(8)] }));
            assert_eq!(
                resp.status, 200,
                "cycle {cycle}: a session whose predecessor released its EBI must \
                 get one, not a 403 for a UE with no live bearers"
            );
            let body = body_json(&resp);
            let ebi = body["assignedEbiList"][0]["epsBearerId"]
                .as_u64()
                .unwrap_or_else(|| panic!("cycle {cycle}: no EBI assigned: {body}"));
            assigned.push(ebi);

            // What the SMF now does when the session is released.
            let released =
                assign_ebi_request(supi, json!({ "pduSessionId": 5, "releasedEbiList": [ebi] }));
            assert_eq!(
                released.status, 200,
                "cycle {cycle}: the release must succeed"
            );
        }
        assert_eq!(
            assigned,
            vec![5u64; 12],
            "lowest-free reuse means every cycle gets the same identity back; \
             a climbing allocator would exhaust the space instead"
        );

        // The other half: eleven sessions that never release exhaust the space, and
        // the twelfth is refused. This is the state #291 found in the tree.
        let leaky = "imsi-001010000000292";
        setup_ue(leaky, true, true);
        for cycle in 1..=11u8 {
            let resp = assign_ebi_request(leaky, json!({ "pduSessionId": 5, "arpList": [arp(8)] }));
            assert_eq!(resp.status, 200, "cycle {cycle} of eleven must fit");
        }
        let twelfth = assign_ebi_request(leaky, json!({ "pduSessionId": 5, "arpList": [arp(8)] }));
        assert_eq!(
            twelfth.status, 403,
            "the twelfth unreleased session must be refused: eleven is the whole \
             assignable space (TS 24.301 §9.3.2 reserves 0..=4)"
        );
        // AssignEbiError nests its cause under `error` rather than carrying a
        // top-level ProblemDetails one (TS 29.518 §6.1.6.2.5).
        assert_eq!(
            body_json(&twelfth)["error"]["cause"],
            json!("INSUFFICIENT_RESOURCES")
        );
        assert_eq!(
            body_json(&twelfth)["failureDetails"]["failedArpList"]
                .as_array()
                .map(Vec::len),
            Some(1),
            "the SMF must learn WHICH flow got no EBI"
        );
    }

    /// #291 criterion 4: deregistration frees the UE's EBIs.
    ///
    /// The issue asked whether this already happened because the context is dropped.
    /// It did not, and the reason is worth pinning: nothing in production removes an
    /// `AmfUe` (`amf_ue_remove` has only test callers), so the context — and every
    /// identity recorded on it — outlives every deregistration. Without this
    /// backstop the only path that frees an EBI is the SMF's release, and an SMF
    /// whose release never arrives leaks one for the life of the process.
    #[test]
    fn deregistration_frees_the_ues_eps_bearer_identities() {
        let supi = "imsi-001010000000293";
        setup_ue(supi, true, true);

        // Two sessions of one UE, both holding an identity.
        for psi in [5u8, 6u8] {
            let resp =
                assign_ebi_request(supi, json!({ "pduSessionId": psi, "arpList": [arp(8)] }));
            assert_eq!(resp.status, 200);
        }
        assert_eq!(
            find_ue_by_context_id(supi)
                .map(|ue| ue.assigned_ebis.len())
                .unwrap_or(0),
            2,
            "both identities are held before the deregistration"
        );

        assert_eq!(
            release_all_ebis_on_deregistration(supi),
            2,
            "deregistration frees every identity the UE holds"
        );
        assert!(
            find_ue_by_context_id(supi)
                .map(|ue| ue.assigned_ebis.is_empty())
                .unwrap_or(false),
            "the freed identities must be gone from the STORED context, not just \
             from a local copy — an unpersisted clear frees nothing"
        );

        // And the space is genuinely reusable afterwards.
        let after = assign_ebi_request(supi, json!({ "pduSessionId": 7, "arpList": [arp(8)] }));
        assert_eq!(after.status, 200);
        assert_eq!(
            body_json(&after)["assignedEbiList"][0]["epsBearerId"],
            json!(5),
            "the lowest identity is free again"
        );

        // A UE holding none, and an unknown UE, are both no-ops rather than errors.
        let empty = "imsi-001010000000294";
        setup_ue(empty, true, true);
        assert_eq!(release_all_ebis_on_deregistration(empty), 0);
        assert_eq!(
            release_all_ebis_on_deregistration("imsi-999999999999999"),
            0
        );
    }

    /// The request-validation surface: the one required member, the ARP members,
    /// and an unknown UE.
    #[test]
    fn assign_ebi_rejects_a_malformed_request_and_an_unknown_ue() {
        let supi = "imsi-001010000000120";
        setup_ue(supi, true, true);

        // pduSessionId is the ONLY required member of AssignEbiData.
        let resp = assign_ebi_request(supi, json!({ "arpList": [arp(1)] }));
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // ...and a request with ONLY it is legal: it assigns nothing and answers
        // an empty assignedEbiList, which minItems:0 permits.
        let resp = assign_ebi_request(supi, json!({ "pduSessionId": 5 }));
        assert_eq!(resp.status, 200);
        assert_eq!(body_json(&resp)["assignedEbiList"], json!([]));

        // Arp's three members are all required.
        for missing in ["priorityLevel", "preemptCap", "preemptVuln"] {
            let mut a = arp(1);
            a.as_object_mut().expect("obj").remove(missing);
            let resp = assign_ebi_request(supi, json!({"pduSessionId": 5, "arpList": [a]}));
            assert_eq!(resp.status, 400, "missing Arp.{missing} must be refused");
            assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");
        }

        // ArpPriorityLevel is 1..=15 and is a plain integer, so its value IS
        // checked -- unlike the two pre-emption members, which are extensible
        // enums and are checked for presence only.
        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "arpList": [json!({"priorityLevel": 0, "preemptCap": "x", "preemptVuln": "y"})],
            }),
        );
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "arpList": [json!({
                    "priorityLevel": 9,
                    "preemptCap": "SOME_FUTURE_VALUE",
                    "preemptVuln": "ANOTHER",
                })],
            }),
        );
        assert_eq!(
            resp.status, 200,
            "PreemptionCapability is anyOf[enum, string]; an unlisted value is \
             permitted by the schema and must not be refused"
        );

        // A UE this AMF does not hold.
        let resp = assign_ebi_request("imsi-999990000000000", json!({"pduSessionId": 5}));
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    /// Modifying an EBI the AMF never assigned is a state disagreement, and 409 is
    /// what the operation defines for it. Answering 200 while ignoring the entry
    /// would leave the SMF believing an ARP change took effect.
    #[test]
    fn assign_ebi_modifies_a_held_ebi_and_409s_one_it_does_not_hold() {
        let supi = "imsi-001010000000121";
        setup_ue(supi, true, true);

        let ebi = body_json(&assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "arpList": [arp(1)],
            }),
        ))["assignedEbiList"][0]["epsBearerId"]
            .as_u64()
            .expect("ebi");

        let body = body_json(&assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "modifiedEbiList": [{"epsBearerId": ebi, "arp": arp(12)}],
            }),
        ));
        assert_eq!(body["modifiedEbiList"], json!([ebi]));

        // The new ARP is what is held now, not the old one. Read back through a
        // fresh assignment's echo of the stored state.
        let stored = amf_self()
            .read()
            .expect("ctx")
            .amf_ue_find_by_supi(supi)
            .expect("ue");
        let held = stored
            .assigned_ebis
            .iter()
            .find(|a| a.ebi as u64 == ebi)
            .expect("the EBI is still held");
        assert_eq!(
            held.arp.priority_level, 12,
            "the modify must replace the stored ARP, not just be reported"
        );

        let resp = assign_ebi_request(
            supi,
            json!({
                "pduSessionId": 5,
                "modifiedEbiList": [{"epsBearerId": 15, "arp": arp(3)}],
            }),
        );
        assert_eq!(resp.status, 409, "body: {:?}", resp.http.content);
        assert_eq!(
            body_json(&resp)["error"]["cause"],
            json!("EBI_NOT_ASSIGNED")
        );
    }

    // ========================================================================
    // MBS: Namf_MBSCommunication / Namf_MBSBroadcast (#75)
    // ========================================================================
    //
    // WHAT THESE DO NOT PROVE: nothing here involves the real nextgsim gNB.
    // `nextgsim-gnb/src/mbs_ngap.rs` is a session state machine with NO NGAP
    // codec and no socket path (zero `encode`/`decode`/`Aper` occurrences in
    // its 233 lines), so no MBS PDU can reach it today. The cross-repo half of
    // #75's criterion 6 belongs to the nightly `Docker E2E` job (#349) and
    // cannot pass until that gNB gains a wire path; it is struck on the issue
    // with the blocker named rather than claimed here.
    //
    // What they DO prove: the resources answer 2xx rather than the 404 they
    // used to, the TMGI survives the JSON->NGAP boundary intact, and the
    // spec-mandated refusals happen.

    fn mbs_tmgi_body(mcc: &str, mnc: &str, service: &str) -> Value {
        json!({
            "mbsSessionId": {
                "tmgi": { "mbsServiceId": service, "plmnId": { "mcc": mcc, "mnc": mnc } }
            },
            "n2MbsSmInfo": { "ngapData": { "contentId": "mbs-sm" } },
        })
    }

    /// The resource is served and reports an HONEST result. Before #75 an
    /// MB-SMF consumer got 404 RESOURCE_URI_STRUCTURE_NOT_FOUND here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mbs_n2_message_transfer_is_served_rather_than_404() {
        let req = SbiRequest::post("/namf-mbs-comm/v1/n2-messages/transfer")
            .with_json_body(&mbs_tmgi_body("001", "01", "0000AB"))
            .expect("json")
            .with_part(SbiPart::with_content(
                "mbs-sm",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from_static(&[0x00, 0x47, 0x00, 0x08]),
            ));
        let resp = namf_request_handler(req).await;

        assert_eq!(resp.status, 200, "must not be the old 404");
        // N2_NOT_SENT rather than a claimed success: the SBI task cannot reach
        // the NGAP server's SCTP associations yet, and SUCCESS would be a lie.
        assert_eq!(body_json(&resp)["result"], json!("N2_NOT_SENT"));
    }

    /// ContextCreate allocates a context, and a REPEAT for the same TMGI returns
    /// the SAME ref rather than leaking a second session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mbs_context_create_is_idempotent_on_the_tmgi() {
        let body = mbs_tmgi_body("001", "01", "00CAFE");
        let post = || {
            SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
                .with_json_body(&body)
                .expect("json")
        };

        let first = namf_request_handler(post()).await;
        assert_eq!(first.status, 201);
        let first_ref = body_json(&first)["mbsContextRef"].clone();
        assert_ne!(first_ref, Value::Null, "201 must name the created resource");

        let second = namf_request_handler(post()).await;
        assert_eq!(
            body_json(&second)["mbsContextRef"],
            first_ref,
            "a repeated ContextCreate for one TMGI must not allocate a second session"
        );
    }

    /// The TMGI reaches the NGAP layer intact: the context the SBI created is
    /// findable by the SAME `Tmgi` the NGAP builders encode, with the PLMN
    /// BCD-packed per TS 24.008 §10.5.1.13 (mcc=001 mnc=01 -> 00 F1 10).
    ///
    /// This is the assertion that would catch a JSON->NGAP boundary bug, which a
    /// 201 status alone cannot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_created_mbs_context_is_reachable_by_its_ngap_tmgi() {
        let req = SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
            .with_json_body(&mbs_tmgi_body("001", "01", "00BEEF"))
            .expect("json");
        assert_eq!(namf_request_handler(req).await.status, 201);

        let expected = Tmgi::new(0x00BEEF, [0x00, 0xF1, 0x10]);
        assert!(
            crate::context::amf_mcast()
                .session_find_by_tmgi(&expected)
                .is_some(),
            "the SBI-created context must be findable by the TMGI the NGAP \
             builders encode; a miss here means the boundary mangled the PLMN \
             or the service id"
        );
    }

    /// An SSM-only `mbsSessionId` is REFUSED, not silently mapped. The schema is
    /// `anyOf [tmgi, ssm]`, but the AMF's NGAP `MBS-SessionID` carries a TMGI and
    /// no SSM-to-TMGI mapping is defined -- inventing one would drive the wrong
    /// session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ssm_only_mbs_session_id_is_refused_rather_than_mapped() {
        let req = SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
            .with_json_body(&json!({
                "mbsSessionId": {
                    "ssm": {
                        "sourceIpAddr": { "ipv4Addr": "10.0.0.1" },
                        "destIpAddr": { "ipv4Addr": "239.0.0.1" }
                    }
                }
            }))
            .expect("json");
        assert_eq!(namf_request_handler(req).await.status, 501);
    }

    /// A malformed `mbsServiceId` is a 400, not a panic and not a zero TMGI.
    /// The OpenAPI pins `pattern: '^[A-Fa-f0-9]{6}$'`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_malformed_mbs_service_id_is_a_400() {
        for bad in ["ZZZZZZ", "ABC", "0000ABCD"] {
            let req = SbiRequest::post("/namf-mbs-bc/v1/mbs-contexts")
                .with_json_body(&json!({
                    "mbsSessionId": {
                        "tmgi": {
                            "mbsServiceId": bad,
                            "plmnId": { "mcc": "001", "mnc": "01" }
                        }
                    }
                }))
                .expect("json");
            assert_eq!(
                namf_request_handler(req).await.status,
                400,
                "mbsServiceId {bad:?} must be refused"
            );
        }
    }

    /// A 3-digit MNC packs differently from a 2-digit one (TS 24.008
    /// §10.5.1.13): mcc=310 mnc=260 -> 13 00 62, where the 2-digit form leaves
    /// the high nibble of octet 2 as the 0xF filler.
    #[test]
    fn a_three_digit_mnc_is_bcd_packed_without_the_filler_nibble() {
        let two = plmn_id_to_bcd(&json!({ "mcc": "001", "mnc": "01" })).expect("2-digit mnc");
        assert_eq!(two, [0x00, 0xF1, 0x10]);

        let three = plmn_id_to_bcd(&json!({ "mcc": "310", "mnc": "260" })).expect("3-digit mnc");
        assert_eq!(three, [0x13, 0x00, 0x62]);
        assert_ne!(
            three[1] & 0xF0,
            0xF0,
            "a 3-digit MNC must not carry the 0xF filler nibble"
        );

        assert!(plmn_id_to_bcd(&json!({ "mcc": "01", "mnc": "01" })).is_none());
        assert!(plmn_id_to_bcd(&json!({ "mcc": "001", "mnc": "0" })).is_none());
    }

    // ==================================================================
    // #74: inter-AMF UE-context PRODUCER operations (TS 29.518 §5.2.2.2)
    //
    // Every test here takes `crate::test_support::CONTEXT_GUARD` -- the EXISTING
    // process-wide lock, never a new one. A lock declared inside a `mod tests` is
    // invisible to siblings, so the next test declares a second, and two locks over
    // one process-global has hung this suite before.
    //
    // Literal keys (SUPI, 5G-TMSI, AMF-UE-NGAP-ID) are DISTINCT per test, because
    // `amf_context_init` is a one-shot that never clears: a shared SUPI would have
    // two tests resolve each other's UE, which is the
    // `test_ue_context_transfer_error_paths` flake class.
    // ==================================================================

    /// A `UeContextCreateData` with every member §5.2.2.2.3.1 makes mandatory.
    fn create_ue_context_body(supi: &str, pei: &str) -> Value {
        json!({
            "ueContext": {
                "supi": supi,
                "pei": pei,
                "mmContextList": [{ "accessType": "3GPP_ACCESS" }],
            },
            "targetId": {
                "ranNodeId": { "gNbId": { "bitLength": 24, "gNBValue": "000074" } },
                "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "0074" },
            },
            "sourceToTargetData": { "ngapIeType": "SRC_TO_TAR_CONTAINER",
                                    "ngapData": { "contentId": "n2SrcToTar" } },
            "pduSessionList": [{ "pduSessionId": 5,
                                 "n2InfoContent": { "ngapData": { "contentId": "n2Sm5" } } }],
        })
    }

    /// #74 criterion 1: `PUT /namf-comm/v1/ue-contexts/{id}` (CreateUEContext)
    /// creates a UE context that this AMF can afterwards RESOLVE.
    ///
    /// The router could not reach this operation at all before #74: the `namf-comm`
    /// `ue-contexts` arm was guarded on `parts.len() >= 5` and a
    /// `PUT .../ue-contexts/{id}` has FOUR segments, so every conformant
    /// CreateUEContext fell through to the 404 arm.
    ///
    /// **The assertion is positive and on the store, not on the status code.** A
    /// handler that answers 201 with a `Location` header and records nothing would
    /// pass a routing test and fail every real handover, so what is asserted is that
    /// `find_ue_by_context_id` — the resolver the whole Namf surface uses — returns
    /// the created context afterwards, carrying the SUPI **and** the PEI the peer
    /// sent. Those values exist nowhere else in the fixture, so they can only have
    /// come through this handler.
    ///
    /// The second half pins the load-bearing detail #341 warns about: the resolver
    /// reads `ue_store`, not `amf_ue_list`, so a create that only did `amf_ue_add`
    /// would be correct-but-unreachable. Resolving by SUPI goes through the live
    /// store and would fail on that mistake.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_ue_context_creates_a_context_this_amf_can_resolve() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        // A SUPI/PEI pair no sibling uses, so resolving them proves this handler ran.
        let supi = "imsi-001010000740010";
        let pei = "imeisv-0000000000740010";
        let ue_context_id = supi;

        let req = SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{ue_context_id}"))
            .with_json_body(&create_ue_context_body(supi, pei))
            .expect("json");
        let resp = namf_request_handler(req).await;

        assert_eq!(
            resp.status, 201,
            "TS 29.518 §5.2.2.2.3.1 step 2a: \"the target AMF shall respond with the \
             status code '201 Created'\""
        );
        assert!(
            resp.http
                .get_header("location")
                .is_some_and(|l| l.contains(ue_context_id)),
            "and \"together with a HTTP Location header to provide the location of a newly \
             created resource\""
        );
        let body = body_json(&resp);
        assert_eq!(
            body["ueContext"]["supi"].as_str(),
            Some(supi),
            "the response carries the representation of the created UE Context \
             (UeContextCreatedData requires `ueContext`)"
        );
        assert!(
            body["targetToSourceData"].is_object(),
            "UeContextCreatedData also REQUIRES targetToSourceData \
             (TS29518_Namf_Communication.yaml:3701-3704)"
        );
        assert!(body["pduSessionList"].is_array(), "and pduSessionList");

        // The point of the operation: the context EXISTS and is reachable.
        let resolved = find_ue_by_context_id(ue_context_id).expect(
            "the created UE context must be resolvable -- a 201 that records \
                     nothing would pass a routing test and fail every real handover",
        );
        assert_eq!(
            resolved.supi.as_deref(),
            Some(supi),
            "and it must carry the SUPI the peer sent: this value exists nowhere else in \
             the fixture, so it can only have arrived through CreateUEContext"
        );
        assert_eq!(
            resolved.pei.as_deref(),
            Some(pei),
            "and the rest of the transferred UeContext with it"
        );
        assert_eq!(
            resolved.amf_ue_context_transfer_state,
            UeContextTransferState::TransferNewAmf,
            "the UE is recorded as transferred IN -- the new-AMF side of TS 29.518 §5.2.2.2.1"
        );

        // A second create under the same identity is a conflict, not a silent
        // overwrite of a UE this AMF is serving.
        let req = SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{ue_context_id}"))
            .with_json_body(&create_ue_context_body(supi, pei))
            .expect("json");
        assert_eq!(namf_request_handler(req).await.status, 403);
    }

    /// CreateUEContext refuses a request missing any of the four members
    /// `UeContextCreateData` marks `required`
    /// (`TS29518_Namf_Communication.yaml:3668-3672`).
    ///
    /// Paired with the acceptance test above so the two DISCRIMINATE: together they
    /// show the handler accepts the right bodies rather than accepting everything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_ue_context_requires_every_mandatory_member() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        // Distinct from `create_ue_context_creates_a_context_this_amf_can_resolve`,
        // which leaves its context in the process-global store.
        let supi = "imsi-001010000740011";
        let full = create_ue_context_body(supi, "imeisv-0000000000740011");

        for missing in [
            "ueContext",
            "targetId",
            "sourceToTargetData",
            "pduSessionList",
        ] {
            let mut body = full.clone();
            body.as_object_mut().expect("object").remove(missing);
            let req = SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{supi}"))
                .with_json_body(&body)
                .expect("json");
            let resp = namf_request_handler(req).await;
            assert_eq!(
                resp.status, 400,
                "a CreateUEContext without `{missing}` must be refused"
            );
            assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");
        }

        // `pduSessionList` has `minItems: 1` (yaml:3653), so an empty array is a
        // defect and not "no sessions".
        let mut body = full.clone();
        body["pduSessionList"] = json!([]);
        let req = SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{supi}"))
            .with_json_body(&body)
            .expect("json");
        assert_eq!(
            problem_cause(&namf_request_handler(req).await),
            "MANDATORY_IE_INCORRECT"
        );

        // Nothing was created by any of the refusals.
        assert!(
            find_ue_by_context_id(supi).is_none(),
            "a refused CreateUEContext must not have left a half-built context behind"
        );
    }

    /// #74 criterion 1: `POST .../{id}/release` (ReleaseUEContext) really releases.
    ///
    /// The path reached the router arm before #74 but matched no literal, so it fell
    /// to `send_method_not_allowed` — a source AMF cancelling a handover got a 405.
    ///
    /// The assertion is the TRANSITION, in one test: the context resolves BEFORE and
    /// does not resolve AFTER. Asserting only the absence afterwards would be
    /// satisfied by a context that was never created.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_ue_context_releases_the_context() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI per the process-global note at the top of this section.
        let supi = "imsi-001010000740020";
        let ue = setup_ue(supi, true, true);

        assert!(
            find_ue_by_context_id(supi).is_some(),
            "precondition: the context exists before the release"
        );

        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/release"))
            .with_json_body(&json!({ "ngapCause": { "group": 0, "value": 5 } }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "TS 29.518 §5.2.2.2.4.1 step 2a: \"the target AMF shall return '204 No \
             Content' with an empty content\""
        );
        assert!(
            resp.http.content.as_deref().unwrap_or("").is_empty(),
            "and the content must be empty"
        );

        assert!(
            find_ue_by_context_id(supi).is_none(),
            "after the release the context must NOT resolve. This is the assertion that \
             fails if the handler removes from `amf_ue_list` only: the resolver reads the \
             LIVE store (#341), so an unpublished-but-listed UE would still be served"
        );
        let ctx = amf_self();
        assert!(
            ctx.read()
                .expect("ctx lock")
                .ran_ue_find_by_id(ue.ran_ue_id)
                .is_none(),
            "and the RAN UE with it, or the release frees the NAS state while the \
             AMF-UE-NGAP-ID stays allocated"
        );

        // Releasing an unknown context is 404, never a silent success.
        let req = SbiRequest::post("/namf-comm/v1/ue-contexts/imsi-001010000740029/release")
            .with_json_body(&json!({}))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    /// #74 criterion 1 + the gap PR #390 named: `POST .../{id}/relocate`
    /// (RelocateUEContext) creates the context AND records the transferred PDU
    /// sessions.
    ///
    /// PR #390 flagged that "the received `sessionContextList` is carried and logged
    /// but PDU sessions aren't re-established", naming #74's `/relocate` as its home.
    /// The sessions are RECORDED here, and the ceiling is explicit: their N3 tunnels
    /// are not moved, because the endpoints would have to come over N26 from the
    /// source MME and this AMF has no N26 leg (see `record_transferred_sessions`).
    /// Asserting the session record is asserting exactly what was built — not a
    /// tunnel move that did not happen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relocate_ue_context_creates_the_context_and_records_its_sessions() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        // Distinct from every sibling in this section.
        let supi = "imsi-001010000740030";
        // An smContextRef that appears nowhere else, so finding it on a session proves
        // it came out of THIS request body.
        let sm_context_ref = "smctx-relocate-740030";

        let body = json!({
            "ueContext": {
                "supi": supi,
                "mmContextList": [{ "accessType": "3GPP_ACCESS" }],
                "sessionContextList": [{
                    "pduSessionId": 7,
                    "smContextRef": sm_context_ref,
                    "sNssai": { "sst": 1, "sd": "0000AB" },
                    "dnn": "internet",
                    "accessType": "3GPP_ACCESS",
                }],
            },
            "targetId": {
                "ranNodeId": { "gNbId": { "bitLength": 24, "gNBValue": "000074" } },
                "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "0074" },
            },
            "sourceToTargetData": { "ngapIeType": "SRC_TO_TAR_CONTAINER",
                                    "ngapData": { "contentId": "n2SrcToTar" } },
            "forwardRelocationRequest": { "contentId": "fwdReloc" },
        });

        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/relocate"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "fwdReloc",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from_static(b"\x01\x02\x03"),
            ));
        let resp = namf_request_handler(req).await;

        assert_eq!(
            resp.status, 201,
            "TS 29.518 §5.2.2.2.5.1 step 2a: \"the target AMF shall respond with the \
             status code '201 Created'\""
        );
        assert!(
            resp.http.get_header("location").is_some(),
            "\"together with a HTTP Location header\""
        );
        assert_eq!(
            body_json(&resp)["ueContext"]["supi"].as_str(),
            Some(supi),
            "UeContextRelocatedData requires `ueContext` (yaml:3753-3754)"
        );

        let resolved = find_ue_by_context_id(supi).expect("the relocated context must resolve");
        let ctx = amf_self();
        let sessions = ctx.read().expect("ctx lock").sess_list_for_ue(resolved.id);
        assert_eq!(
            sessions.len(),
            1,
            "the transferred sessionContextList must be RECORDED against the created \
             context -- the gap PR #390 named"
        );
        assert_eq!(sessions[0].psi, 7);
        assert_eq!(
            sessions[0].sm_context_ref.as_deref(),
            Some(sm_context_ref),
            "with the SMF reference the peer sent, which exists nowhere else in this fixture"
        );
        assert_eq!(sessions[0].dnn.as_deref(), Some("internet"));
        assert_eq!(sessions[0].s_nssai.sst, 1);
        assert_eq!(sessions[0].s_nssai.sd, Some(0x0000AB));
    }

    /// `forwardRelocationRequest` is `required` (yaml:3742-3746) and it is a
    /// `RefToBinaryData`, so a reference with no multipart part behind it is a
    /// relocation whose Forward Relocation Request never arrived — refused, not
    /// accepted-and-ignored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relocate_ue_context_refuses_a_dangling_forward_relocation_reference() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        // Distinct from the accepting sibling above.
        let supi = "imsi-001010000740031";

        let base = json!({
            "ueContext": { "supi": supi, "mmContextList": [{ "accessType": "3GPP_ACCESS" }] },
            "targetId": {
                "ranNodeId": { "gNbId": { "bitLength": 24, "gNBValue": "000074" } },
                "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "0074" },
            },
            "sourceToTargetData": { "ngapData": { "contentId": "n2SrcToTar" } },
        });

        // Absent entirely.
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/relocate"))
            .with_json_body(&base)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Present, but referencing a part that is not in the request.
        let mut dangling = base.clone();
        dangling["forwardRelocationRequest"] = json!({ "contentId": "notThere" });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/relocate"))
            .with_json_body(&dangling)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        assert!(
            find_ue_by_context_id(supi).is_none(),
            "neither refusal may have created a context"
        );
    }

    /// #74 criterion 1: `POST .../{id}/cancel-relocate` (CancelRelocateUEContext)
    /// releases the relocated context.
    ///
    /// Asserted as a transition — resolves before, does not resolve after — for the
    /// same reason as the release test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_relocate_ue_context_releases_the_relocated_context() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI per the process-global note.
        let supi = "imsi-001010000740040";
        let _ue = setup_ue(supi, true, true);
        assert!(find_ue_by_context_id(supi).is_some(), "precondition");

        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/cancel-relocate"))
            .with_json_body(&json!({
                "supi": supi,
                "relocationCancelRequest": { "contentId": "cancelReq" },
            }))
            .expect("json")
            .with_part(SbiPart::with_content(
                "cancelReq",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from_static(b"\x04\x05"),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "TS 29.518 §5.2.2.2.6.1 step 2a: \"the target AMF shall return '204 No Content'\""
        );
        assert!(
            find_ue_by_context_id(supi).is_none(),
            "the relocated context must be gone from the LIVE store, which is what the \
             Namf surface resolves against"
        );

        // A `relocationCancelRequest` reference with no part behind it is refused.
        let other = "imsi-001010000740041";
        let _other_ue = setup_ue(other, true, true);
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{other}/cancel-relocate"))
            .with_json_body(&json!({ "relocationCancelRequest": { "contentId": "absent" } }))
            .expect("json");
        assert_eq!(
            problem_cause(&namf_request_handler(req).await),
            "MANDATORY_IE_INCORRECT"
        );
        assert!(
            find_ue_by_context_id(other).is_some(),
            "and the refusal must not have released anything"
        );
    }

    // ==================================================================
    // #74 criterion 3: AMFStatusChange subscription CRUD (TS 29.518 §5.2.2.5)
    // ==================================================================

    /// A full CRUD round trip over `/namf-comm/v1/subscriptions`, which had no router
    /// arm at all before #74.
    ///
    /// The load-bearing assertion is the PUT's effect: §5.2.2.5.1.3 makes the update a
    /// *complete replacement*, so the test replaces the `amfStatusUri` and reads the
    /// NEW one back through the SBI surface. That is a positive assertion on state only
    /// the replace path can produce — a handler that answered 200 and stored nothing
    /// would return the old URI. The 204s alone would be satisfied by a handler that
    /// did nothing at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn amf_status_change_subscriptions_round_trip() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        // URIs unique to this test: the subscription store is process-global, and the
        // replacement assertion below reads back by value.
        let first_uri = "http://127.0.0.1:19740/namf-status/74-create";
        let replaced_uri = "http://127.0.0.1:19740/namf-status/74-replaced";

        let req = SbiRequest::post("/namf-comm/v1/subscriptions")
            .with_json_body(&json!({
                "amfStatusUri": first_uri,
                "guamiList": [{ "plmnId": { "mcc": "001", "mnc": "01" },
                                "amfId": "020010" }],
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(
            resp.status, 201,
            "TS 29.518 §5.2.2.5.1.2 step 2a: 201 with a Location header"
        );
        let location = resp
            .http
            .get_header("location")
            .expect(
                "\"the AMF shall include a HTTP Location header to provide the location \
                     of a newly created resource\"",
            )
            .to_string();
        assert_eq!(body_json(&resp)["amfStatusUri"].as_str(), Some(first_uri));

        // READ: the created subscription is retrievable at the URI the AMF handed out.
        let resp = namf_request_handler(SbiRequest::get(&location)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(body_json(&resp)["amfStatusUri"].as_str(), Some(first_uri));
        assert_eq!(
            body_json(&resp)["guamiList"][0]["amfId"].as_str(),
            Some("020010"),
            "the guamiList round-trips as the consumer sent it"
        );

        // UPDATE: a complete replacement. The new URI must be what comes back.
        let resp = namf_request_handler(
            SbiRequest::put(&location)
                .with_json_body(&json!({ "amfStatusUri": replaced_uri }))
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "§5.2.2.5.1.3 step 2a: \"'200 OK' shall be returned, the content of the PUT \
             response shall contain the representation of the replaced resource\""
        );
        let resp = namf_request_handler(SbiRequest::get(&location)).await;
        assert_eq!(
            body_json(&resp)["amfStatusUri"].as_str(),
            Some(replaced_uri),
            "the replacement must have taken effect in the store, not merely been echoed"
        );
        assert!(
            body_json(&resp)["guamiList"].is_null(),
            "and it is a COMPLETE replacement (§5.2.2.5.1.3), so the guamiList the first \
             body carried is DROPPED rather than preserved"
        );

        // DELETE, then the read must 404.
        let resp = namf_request_handler(SbiRequest::delete(&location)).await;
        assert_eq!(
            resp.status, 204,
            "§5.2.2.5.2.1 step 2a: \"'204 No Content' shall be returned\""
        );
        assert_eq!(
            namf_request_handler(SbiRequest::get(&location))
                .await
                .status,
            404
        );
        assert_eq!(
            namf_request_handler(SbiRequest::delete(&location))
                .await
                .status,
            404
        );
    }

    /// `amfStatusUri` is the only REQUIRED member of `SubscriptionData`
    /// (yaml:2437-2438), and it must be dialable — a callback the AMF cannot parse is
    /// a notification that will never be delivered, better refused at subscribe time.
    /// An unknown subscription is 404 on PUT, never an upsert under a
    /// consumer-chosen ID.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn amf_status_change_subscription_validation() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        let resp = namf_request_handler(
            SbiRequest::post("/namf-comm/v1/subscriptions")
                .with_json_body(&json!({ "guamiList": [] }))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        let resp = namf_request_handler(
            SbiRequest::post("/namf-comm/v1/subscriptions")
                .with_json_body(&json!({ "amfStatusUri": "not-a-uri" }))
                .expect("json"),
        )
        .await;
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // `guamiList` has `minItems: 1` when present (yaml:2436): an explicitly empty
        // array must not be read as "all GUAMIs", which would widen the subscription.
        let resp = namf_request_handler(
            SbiRequest::post("/namf-comm/v1/subscriptions")
                .with_json_body(&json!({
                    "amfStatusUri": "http://127.0.0.1:19741/s",
                    "guamiList": [],
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // A PUT to an ID the AMF never minted is 404, not a create.
        let resp = namf_request_handler(
            SbiRequest::put("/namf-comm/v1/subscriptions/amfstatus-never-minted-74")
                .with_json_body(&json!({ "amfStatusUri": "http://127.0.0.1:19741/s" }))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "SUBSCRIPTION_NOT_FOUND");
    }

    /// The AMFStatusChange registry is READ by a producer: planned removal POSTs an
    /// `AmfStatusChangeNotification` to every subscriber (TS 29.518 §5.2.2.5.3, the
    /// AMF planned-removal procedure §5.2.2.5.1.1 names as this service's purpose).
    ///
    /// Without this the CRUD above would be a write-only registry — this tree's most
    /// common defect. A real in-process `SbiServer` receives the notification, so what
    /// is asserted is **what a subscriber actually got**: the path it registered and a
    /// conformant `amfStatusInfoList` carrying `AMF_UNAVAILABLE`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn planned_removal_notifies_every_amf_status_subscriber() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        // A served GUAMI is a precondition: the notification body's `AmfStatusInfo`
        // REQUIRES `guamiList` (yaml:2465-2466), so an AMF serving none has nothing
        // conformant to send and the notifier correctly declines.
        //
        // An AMF Region of 0x74 no sibling uses, so the `amfId` asserted below can only
        // be this test's GUAMI. `served_guami` is PROCESS-GLOBAL and several `ngap_path`
        // tests set it (`serve_only_local_guami`), so the previous value is saved and
        // restored: leaving a foreign region behind would flip a sibling's
        // is-this-GUTI-mine verdict mid-flight, which is the
        // `reset_sbi_profile_override` failure mode in a different global.
        let saved_guami = {
            let ctx = amf_self();
            let mut guard = ctx.write().expect("ctx lock");
            let saved = (guard.served_guami.clone(), guard.num_of_served_guami);
            guard.served_guami = vec![crate::context::Guami {
                plmn_id: crate::context::PlmnId::new("001", "01"),
                amf_id: crate::context::AmfId {
                    region: 0x74,
                    set: 0x007,
                    pointer: 0x00,
                },
            }];
            guard.num_of_served_guami = 1;
            saved
        };

        let (server, port, mut rx) = start_capture_server().await;
        // The capture server is plaintext loopback, so this fixture describes a
        // dev-profile deployment and says so. Deliberately NOT reset afterwards: the
        // override is PROCESS-WIDE and every loopback-plaintext test in this crate
        // sets it and leaves it set (PR #390 measured 2 failures in 10 whole-crate runs
        // from resetting it mid-flight).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        // A path unique to this test, so what arrives can only be this subscription's.
        let callback_path = "/namf-status/74-planned-removal";
        let resp = namf_request_handler(
            SbiRequest::post("/namf-comm/v1/subscriptions")
                .with_json_body(&json!({
                    "amfStatusUri": format!("http://127.0.0.1:{port}{callback_path}"),
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201);

        crate::sbi_path::notify_amf_status_change("AMF_UNAVAILABLE").await;

        let (uri, body) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("the subscriber must have been notified before the AMF went away")
            .expect("notification channel closed");
        assert!(
            uri.contains(callback_path),
            "the notification must go to the amfStatusUri the consumer registered, got {uri}"
        );
        let notification: Value = serde_json::from_str(&body).expect("notification is JSON");
        assert_eq!(
            notification["amfStatusInfoList"][0]["statusChange"].as_str(),
            Some("AMF_UNAVAILABLE"),
            "`StatusChange` is AMF_UNAVAILABLE / AMF_AVAILABLE (yaml:4479-4486) -- a bare \
             \"UNAVAILABLE\" is not a value of that enum"
        );
        assert_eq!(
            notification["amfStatusInfoList"][0]["guamiList"][0]["amfId"].as_str(),
            // region 0x74 << 16 | set 0x007 << 6 | pointer 0 (`sbi_path::amf_id_hex`).
            Some("7401c0"),
            "and `AmfStatusInfo` REQUIRES guamiList (yaml:2465-2466), carrying the GUAMI \
             this AMF serves -- rendered the same way the NF profile renders it, so the \
             two cannot disagree about what this AMF is called"
        );

        // Restore the process-global GUAMI before the guard drops, for the reason on the
        // save above.
        {
            let ctx = amf_self();
            let mut guard = ctx.write().expect("ctx lock");
            guard.served_guami = saved_guami.0;
            guard.num_of_served_guami = saved_guami.1;
        }
        server.stop().await.expect("server stop");
    }

    // ==================================================================
    // #74 criterion 4: Namf_EventExposure targeting
    // ==================================================================

    /// A subscription keyed SOLELY by `gpsi`, by `pei`, or by `groupId` is ACCEPTED.
    ///
    /// This was a genuine bug: the guard read `supi`/`anyUE` only and answered
    /// `MANDATORY_IE_MISSING` for the other three, so a conformant NWDAF/AF targeting
    /// a UE by GPSI was refused outright. `AmfEventSubscription` offers all five keys
    /// (`TS29518_Namf_EventExposure.yaml:553`, `:555`, `:577`, `:579`, `:581`) and
    /// `required` lists none of them (`:589-593`).
    ///
    /// Each case asserts 201 **and that the echoed subscription carries the key that
    /// was sent** — a positive assertion, where `assert_ne!(status, 400)` would also
    /// be satisfied by a handler that accepted anything. Paired with the
    /// empty-target rejection below so the two discriminate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_event_subscription_targeted_by_gpsi_pei_or_group_id_is_accepted() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);

        // Identities unique to this test: the subscription store is process-global and
        // `event_subscriptions_matching_ue` now matches on GPSI/PEI, so a shared value
        // would have this test's subscription pick up a sibling's UE.
        for (key, value) in [
            ("gpsi", "msisdn-001010000740500"),
            ("pei", "imeisv-0000000000740500"),
            ("groupId", "74000000-group-0500"),
        ] {
            let req = SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&json!({
                    "subscription": {
                        "eventList": [{ "type": "LOCATION_REPORT" }],
                        "eventNotifyUri": "http://127.0.0.1:19742/notify",
                        "notifyCorrelationId": format!("corr-74-{key}"),
                        "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        key: value,
                    }
                }))
                .expect("json");
            let resp = namf_request_handler(req).await;
            assert_eq!(
                resp.status, 201,
                "a subscription targeted solely by `{key}` is conformant (TS 29.518 \
                 §5.3.2.2) and must be accepted, not refused MANDATORY_IE_MISSING"
            );
            assert_eq!(
                body_json(&resp)["subscription"][key].as_str(),
                Some(value),
                "and the created resource must carry the `{key}` the consumer sent, or it \
                 cannot correlate the subscription with its request"
            );
        }

        // The discriminating half: a subscription naming NO target at all is still a
        // defect, because the AMF would have to guess whose events to report.
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&json!({
                "subscription": {
                    "eventList": [{ "type": "LOCATION_REPORT" }],
                    "eventNotifyUri": "http://127.0.0.1:19742/notify",
                    "notifyCorrelationId": "corr-74-no-target",
                    "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                }
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");
    }

    /// A GPSI-targeted subscription against a UE the AMF already knows RESOLVES to
    /// that UE's SUPI, so it keys exactly the way a SUPI subscription does and the
    /// existing SUPI-keyed fire points reach it unchanged.
    ///
    /// `AmfUe.gpsi` comes from the UDM SDM `am-data` at registration, so this is a
    /// lookup against real state — a SUPI cannot be converted into a GPSI.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gpsi_subscription_resolves_to_the_known_ues_supi() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI/GPSI pair: the resolution below is by value against the
        // process-global store.
        let supi = "imsi-001010000740510";
        let gpsi = "msisdn-001010000740510";
        let mut ue = setup_ue(supi, true, true);
        ue.gpsi = Some(gpsi.to_string());
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.amf_ue_update(&ue);
            // Republish so the GPSI is in the record the resolvers read.
            guard.amf_ue_publish(&ue, 900_745, 1);
        }

        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&json!({
                "subscription": {
                    "eventList": [{ "type": "LOCATION_REPORT" }],
                    "eventNotifyUri": "http://127.0.0.1:19743/notify",
                    "notifyCorrelationId": "corr-74-gpsi-resolve",
                    "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "gpsi": gpsi,
                }
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let subscription_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        let ctx = amf_self();
        let stored = ctx
            .read()
            .expect("ctx lock")
            .event_subscription_find(&subscription_id)
            .expect("the subscription must be stored");
        assert_eq!(
            stored.supi.as_deref(),
            Some(supi),
            "the GPSI must have been resolved to the SUPI of the UE that carries it -- the \
             consumer supplied only the GPSI, so this SUPI can only have come from the \
             lookup"
        );
        assert_eq!(
            stored.gpsi.as_deref(),
            Some(gpsi),
            "and the GPSI is retained, so the echo returns what the consumer sent"
        );

        // An UNKNOWN gpsi is stored UNRESOLVED rather than refused: §5.3.2.2 does not
        // condition a subscription on the target being registered, and
        // `event_subscriptions_matching_ue` matches on the GPSI so it fires once the UE
        // appears.
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&json!({
                "subscription": {
                    "eventList": [{ "type": "LOCATION_REPORT" }],
                    "eventNotifyUri": "http://127.0.0.1:19743/notify",
                    "notifyCorrelationId": "corr-74-gpsi-unknown",
                    "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "gpsi": "msisdn-001010000740519",
                }
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let unresolved = ctx
            .read()
            .expect("ctx lock")
            .event_subscription_find(body_json(&resp)["subscriptionId"].as_str().expect("id"))
            .expect("stored");
        assert!(
            unresolved.supi.is_none(),
            "an unknown GPSI must not be resolved to SOME UE's SUPI"
        );
        assert_eq!(unresolved.gpsi.as_deref(), Some("msisdn-001010000740519"));
    }

    /// A GPSI-targeted subscription really DELIVERS: the notification arrives at the
    /// subscriber and carries the GPSI that was targeted.
    ///
    /// This is the half that would be missed by accepting the key and matching on SUPI
    /// only — the subscription would be stored and never fire, trading a wrong 400 for
    /// silent non-delivery. Asserted against a real in-process server, on the GPSI,
    /// which exists nowhere else in the fixture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gpsi_targeted_subscription_receives_a_notification_carrying_that_gpsi() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct identities; the GPSI below is the assertion's subject.
        let supi = "imsi-001010000740520";
        let gpsi = "msisdn-001010000740520";
        let mut ue = setup_ue(supi, true, true);
        ue.gpsi = Some(gpsi.to_string());

        let (server, port, mut rx) = start_capture_server().await;
        // Dev profile for plaintext loopback; deliberately not reset (process-wide).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let notify_path = "/notify/74-gpsi-delivery";
        let resp = namf_request_handler(
            SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&json!({
                    "subscription": {
                        "eventList": [{ "type": "LOCATION_REPORT" }],
                        "eventNotifyUri": format!("http://127.0.0.1:{port}{notify_path}"),
                        "notifyCorrelationId": "corr-74-gpsi-delivery",
                        "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "gpsi": gpsi,
                    }
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201);

        fire_location_report(&ue);

        let (uri, body) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect(
                "a GPSI-targeted subscription must RECEIVE its notifications, or \
                     accepting the key only traded a wrong 400 for silent non-delivery",
            )
            .expect("notification channel closed");
        assert!(
            uri.contains(notify_path),
            "delivered to the subscribed URI, got {uri}"
        );
        let notification: Value = serde_json::from_str(&body).expect("notification is JSON");
        assert_eq!(
            notification["reportList"][0]["gpsi"].as_str(),
            Some(gpsi),
            "and the report carries the GPSI (Table 6.2.6.2.5-1: \"shall be present if \
             available\") -- this value exists nowhere else in the fixture"
        );
        assert_eq!(
            notification["reportList"][0]["type"].as_str(),
            Some("LOCATION_REPORT")
        );

        server.stop().await.expect("server stop");
    }

    // ==================================================================
    // #74 criterion 5 (the three types with honest sites): a previously
    // silent event type produces a notification
    // ==================================================================

    /// `LOSS_OF_CONNECTIVITY` fires, where it was one of nine types accepted at
    /// subscribe time and never emitted.
    ///
    /// TS 29.518 §6.2 names the trigger literally: *"Such condition is identified when
    /// Mobile Reachable timer expires in the AMF"*, and that expiry is wired in
    /// `ngap_path::process_reachability_timers`. Driven here through
    /// `fire_loss_of_connectivity` because the timer sweep is `NgapServer`-bound; the
    /// production call site is asserted by reverting it and watching this test's
    /// sibling in `ngap_path` — the emitter is what this test pins.
    ///
    /// The assertion is on the delivered body: the subscribed SUPI and the
    /// `LossOfConnectivityReason` the spec defines for a timer expiry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loss_of_connectivity_delivers_a_notification() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI: the delivered report is matched on it below.
        let supi = "imsi-001010000740600";
        let ue = setup_ue(supi, true, true);

        let (server, port, mut rx) = start_capture_server().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let notify_path = "/notify/74-loss-of-connectivity";
        let resp = namf_request_handler(
            SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&json!({
                    "subscription": {
                        "eventList": [{ "type": "LOSS_OF_CONNECTIVITY" }],
                        "eventNotifyUri": format!("http://127.0.0.1:{port}{notify_path}"),
                        "notifyCorrelationId": "corr-74-loss",
                        "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "supi": supi,
                    }
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 201,
            "LOSS_OF_CONNECTIVITY was already accepted at subscribe time; #74's defect is \
             that it never fired"
        );

        fire_loss_of_connectivity(&ue, "MAX_DETECTION_TIME_EXPIRED");

        let (uri, body) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("a LOSS_OF_CONNECTIVITY subscription must produce a notification")
            .expect("notification channel closed");
        assert!(uri.contains(notify_path), "got {uri}");
        let notification: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            notification["reportList"][0]["type"].as_str(),
            Some("LOSS_OF_CONNECTIVITY")
        );
        assert_eq!(
            notification["reportList"][0]["supi"].as_str(),
            Some(supi),
            "for the UE that was subscribed, not whichever UE the store held first"
        );
        assert_eq!(
            notification["reportList"][0]["lossOfConnectReason"].as_str(),
            Some("MAX_DETECTION_TIME_EXPIRED"),
            "the `LossOfConnectivityReason` for a mobile-reachable timer expiry \
             (TS29518_Namf_EventExposure.yaml:1605-1614)"
        );

        server.stop().await.expect("server stop");
    }

    /// `CONNECTIVITY_STATE_REPORT` and `ACCESS_TYPE_REPORT` fire, the other two of the
    /// three silent types #74 leaves closeable here.
    ///
    /// Both are asserted on their type-specific report members — `cmInfoList` and
    /// `accessTypeList` — so a fire point that emitted the right event type with the
    /// wrong body would fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connectivity_state_and_access_type_reports_deliver_notifications() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI from the LOSS_OF_CONNECTIVITY test.
        let supi = "imsi-001010000740610";
        let ue = setup_ue(supi, true, true);

        let (server, port, mut rx) = start_capture_server().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let notify_path = "/notify/74-cm-and-access";
        let resp = namf_request_handler(
            SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&json!({
                    "subscription": {
                        "eventList": [
                            { "type": "CONNECTIVITY_STATE_REPORT" },
                            { "type": "ACCESS_TYPE_REPORT" },
                        ],
                        "eventNotifyUri": format!("http://127.0.0.1:{port}{notify_path}"),
                        "notifyCorrelationId": "corr-74-cm-access",
                        "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "supi": supi,
                    }
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201);

        fire_connectivity_state_report(&ue, true);
        let (_, body) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("CONNECTIVITY_STATE_REPORT must produce a notification")
            .expect("channel closed");
        let cm: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            cm["reportList"][0]["type"].as_str(),
            Some("CONNECTIVITY_STATE_REPORT")
        );
        assert_eq!(
            cm["reportList"][0]["cmInfoList"][0]["cmState"].as_str(),
            Some("CONNECTED"),
            "the CM state is the report's own member, not merely the event type"
        );

        fire_access_type_report(&ue, "3GPP_ACCESS");
        let (_, body) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("ACCESS_TYPE_REPORT must produce a notification")
            .expect("channel closed");
        let at: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            at["reportList"][0]["type"].as_str(),
            Some("ACCESS_TYPE_REPORT")
        );
        assert_eq!(
            at["reportList"][0]["accessTypeList"][0].as_str(),
            Some("3GPP_ACCESS"),
            "carried in `accessTypeList` (TS29518_Namf_EventExposure.yaml:757-760)"
        );

        server.stop().await.expect("server stop");
    }

    // ==================================================================
    // #74 criteria 6 + 7: Namf_Location routing and the LMF round trip
    // ==================================================================

    /// #74 criterion 6: `POST /namf-loc/v1/{id}/provide-loc-info`
    /// (ProvideLocationInfo) is routed and answers a conformant `ProvideLocInfo`.
    ///
    /// Unrouted before #74 — the `namf-loc` arm matched `provide-pos-info` only, so a
    /// UDM asking for NPLI got a 404.
    ///
    /// Both halves of the honest answer are pinned: the last known location AND
    /// `currentLoc: false`. §5.5.2.4.1 makes `currentLoc: true` conditional on a paging
    /// procedure or an NG-RAN Location Reporting Control round trip, neither of which
    /// exists in this tree, and the clause's own instruction for that case is *"the AMF
    /// shall provide the last known location and set 'currentLoc' attribute to
    /// 'false'"*. A test that asserted only the location would not catch a handler that
    /// claimed `true`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provide_location_info_is_routed_and_reports_the_last_known_location() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI; the cell id below is this test's own.
        let supi = "imsi-001010000740700";
        let mut ue = setup_ue(supi, true, true);
        ue.nr_cgi.cell_id = 0x0074_0700;
        ue.nr_tai.tac = 0x0707;
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.amf_ue_update(&ue);
            guard.amf_ue_publish(&ue, 900_747, 1);
        }

        // `RequestLocInfo` has NO required members (yaml:552-569, all four optional
        // with `default: false`), so an empty object is a valid request.
        let resp = namf_request_handler(
            SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-loc-info"))
                .with_json_body(&json!({}))
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "an empty RequestLocInfo is conformant and must not be refused"
        );
        let body = body_json(&resp);
        assert_eq!(
            body["currentLoc"].as_bool(),
            Some(false),
            "§5.5.2.4.1: with no paging and no Location Reporting Control, the AMF \
             \"shall provide the last known location and set 'currentLoc' attribute to \
             'false'\" -- claiming `true` would be the defect"
        );
        assert_eq!(
            body["location"]["nrLocation"]["ncgi"]["nrCellId"].as_str(),
            Some("000740700"),
            "and the NPLI itself: the cell this AMF holds the UE in, which is this test's \
             own value"
        );
        assert_eq!(
            body["ratType"].as_str(),
            Some("NR"),
            "a CM-CONNECTED UE is attached over NR"
        );
        assert!(
            body["timezone"].is_null(),
            "`timezone` is OMITTED: the AMF never learns a UE time zone (gmm_build sends \
             `local_time_zone: None`), and the host's zone is not the UE's"
        );

        // An unknown UE is 404, not an invented location.
        let resp = namf_request_handler(
            SbiRequest::post("/namf-loc/v1/imsi-001010000740709/provide-loc-info")
                .with_json_body(&json!({}))
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    /// #74 criterion 6: `POST /namf-loc/v1/{id}/cancel-pos-info` (CancelLocation) is
    /// routed, validates `CancelPosInfo`'s three required members, and drops the AMF's
    /// stored LCS correlation.
    ///
    /// The positive assertion is that the correlation is GONE afterwards: the consumer
    /// cancelled, so this AMF must stop routing the UE's uplink positioning to the old
    /// LMF. A 204-only assertion would be satisfied by a handler that returned 204 and
    /// kept reporting.
    ///
    /// `nrppaPeriodicInd: true` is exercised because §5.5.2.5.1 step 2a says *"the AMF
    /// shall skip the cancel location procedures towards the UE"* in that case — with
    /// no LMF in this fixture, that path is the one that must still answer 204.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_location_is_routed_and_drops_the_lcs_correlation() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI; the correlation below is keyed on it.
        let supi = "imsi-001010000740710";
        let _ue = setup_ue(supi, true, true);
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.lcs_correlation_set(
                supi,
                LcsCorrelationRecord {
                    lcs_correlation_id: "corr-74-0710".to_string(),
                    serving_lmf_identification: Some("LMF-74-0710".to_string()),
                },
            );
        }
        assert!(
            amf_self()
                .read()
                .expect("ctx lock")
                .lcs_correlation_find(supi)
                .is_some(),
            "precondition: the AMF holds an LCS correlation for this UE"
        );

        // `nrppaPeriodicInd: true` -> the cancel toward the UE is skipped, so no LMF is
        // needed for this leg and the 204 stands on its own.
        let resp = namf_request_handler(
            SbiRequest::post(format!("/namf-loc/v1/{supi}/cancel-pos-info"))
                .with_json_body(&json!({
                    "supi": supi,
                    "hgmlcCallBackURI": "http://127.0.0.1:19744/hgmlc",
                    "ldrReference": "ldr-74-0710",
                    "nrppaPeriodicInd": true,
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 204,
            "§5.5.2.5.1 step 2a: \"On success, AMF responds with '204 No Content'\""
        );
        assert!(
            amf_self()
                .read()
                .expect("ctx lock")
                .lcs_correlation_find(supi)
                .is_none(),
            "the stored correlation must be DROPPED: the consumer cancelled, so this AMF \
             must stop routing this UE's positioning to the old LMF"
        );

        // `CancelPosInfo` requires supi, hgmlcCallBackURI and ldrReference
        // (TS29518_Namf_Location.yaml:612-615).
        let other = "imsi-001010000740711";
        let _other = setup_ue(other, true, true);
        let full = json!({
            "supi": other,
            "hgmlcCallBackURI": "http://127.0.0.1:19744/hgmlc",
            "ldrReference": "ldr-74-0711",
        });
        for missing in ["supi", "hgmlcCallBackURI", "ldrReference"] {
            let mut body = full.clone();
            body.as_object_mut().expect("object").remove(missing);
            let resp = namf_request_handler(
                SbiRequest::post(format!("/namf-loc/v1/{other}/cancel-pos-info"))
                    .with_json_body(&body)
                    .expect("json"),
            )
            .await;
            assert_eq!(resp.status, 400, "a CancelPosInfo without `{missing}`");
            assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");
        }
    }

    /// #74 criterion 7: `provide-pos-info` INVOKES the LMF and returns the
    /// LMF-derived position.
    ///
    /// TS 29.518 §5.5.2.2.1 is explicit — *"The service operation triggers the AMF to
    /// invoke the service towards the LMF"* — and before #74 the handler returned the
    /// stored NGAP cell identity while carrying an in-code admission that "No LMF
    /// client path exists in this AMF". `lmfd` has served
    /// `/nlmf-loc/v1/determine-location` all along, so the producer existed and had no
    /// consumer.
    ///
    /// A real in-process `SbiServer` stands in for the LMF over real HTTP/2, so the
    /// assertions are on **what the LMF actually received** (the SUPI, on the
    /// DetermineLocation path) and on **the position the LMF returned** appearing in
    /// the AMF's answer. That latitude exists nowhere else in the fixture, so a
    /// handler that skipped the round trip cannot produce it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provide_positioning_info_drives_the_lmf_and_returns_its_position() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI; the latitude below is this test's marker value.
        let supi = "imsi-001010000740720";
        let mut ue = setup_ue(supi, true, true);
        ue.nr_cgi.cell_id = 0x0074_0720;
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.amf_ue_update(&ue);
            guard.amf_ue_publish(&ue, 900_748, 1);
        }

        // A latitude no other fixture uses, so finding it in the AMF's response proves
        // the LMF was consulted.
        let lmf_latitude = 47.740_720_f64;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let lmf_port = addr.port();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(8);
        let lmf = SbiServer::on_listener(
            SbiServerConfig::new(format!("127.0.0.1:{lmf_port}").parse().expect("addr")),
            listener,
        );
        lmf.start(move |req: SbiRequest| {
            let tx = tx.clone();
            async move {
                let _ = tx
                    .send((
                        req.header.uri.clone(),
                        req.http.content.clone().unwrap_or_default(),
                    ))
                    .await;
                // The shape lmfd's `encode_location_response` produces: a
                // `LocationDataExt` whose members ProvidePosInfo shares by name
                // (TS29518_Namf_Location.yaml:369-429).
                SbiResponse::with_status(200)
                    .with_json_body(&json!({
                        "locationEstimate": {
                            "shape": "POINT",
                            "point": { "lat": lmf_latitude, "lon": 8.740_720 },
                        },
                        "accuracyFulfilmentIndicator": "REQUESTED_ACCURACY_FULFILLED",
                        "ageOfLocationEstimate": 0,
                        "positioningDataList": [{
                            "method": "CELL_ID",
                            "mode": "CONVENTIONAL",
                            "usage": "SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION",
                        }],
                    }))
                    .expect("json")
            }
        })
        .await
        .expect("stand-in LMF start");

        // Plaintext loopback -> dev profile, and deliberately NOT reset (process-wide).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // No NRF here, so the LMF is reached through the configured fallback -- the
        // same path a bring-up without an NRF takes.
        std::env::set_var("LMF_SBI_ADDR", "127.0.0.1");
        std::env::set_var("LMF_SBI_PORT", lmf_port.to_string());

        let resp = namf_request_handler(
            SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
                .with_json_body(&json!({
                    "lcsClientType": "EMERGENCY_SERVICES",
                    "lcsLocation": "CURRENT_LOCATION",
                    "supportedGADShapes": ["POINT"],
                }))
                .expect("json"),
        )
        .await;

        std::env::remove_var("LMF_SBI_ADDR");
        std::env::remove_var("LMF_SBI_PORT");

        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        assert_eq!(
            body["locationEstimate"]["point"]["lat"].as_f64(),
            Some(lmf_latitude),
            "the AMF must return the LMF-DERIVED position. This latitude exists nowhere \
             else in the fixture, so it can only have arrived over \
             Nlmf_Location_DetermineLocation -- which had no consumer at all before #74"
        );
        assert_eq!(
            body["positioningDataList"][0]["method"].as_str(),
            Some("CELL_ID"),
            "and the LMF's positioning method with it"
        );
        assert_eq!(
            body["ncgi"]["nrCellId"].as_str(),
            Some("000740720"),
            "alongside the serving cell, which is the AMF's own knowledge and a \
             ProvidePosInfo member in its own right (yaml:399-400)"
        );

        // What the LMF actually received.
        let (uri, lmf_body) = rx
            .try_recv()
            .expect("the LMF must have been invoked (TS 29.518 §5.5.2.2.1)");
        assert!(
            uri.contains("/nlmf-loc/v1/determine-location"),
            "on the DetermineLocation resource lmfd serves, got {uri}"
        );
        let input: Value = serde_json::from_str(&lmf_body).expect("InputData is JSON");
        assert_eq!(
            input["supi"].as_str(),
            Some(supi),
            "carrying the target SUPI, which only the AMF holds"
        );
        assert_eq!(
            input["ncgi"]["nrCellId"].as_str(),
            Some("000740720"),
            "and the serving cell, the E-CID starting point only the AMF has"
        );
        assert_eq!(
            input["externalClientType"].as_str(),
            Some("EMERGENCY_SERVICES"),
            "and the GMLC's client type carried through, not dropped"
        );

        lmf.stop().await.expect("LMF stop");
    }

    /// With no LMF reachable, `provide-pos-info` falls back to the stored NGAP cell —
    /// the pre-#74 answer — rather than failing.
    ///
    /// This is what keeps a deployment without an LMF working: a consumer that used to
    /// get a cell identity must not start getting a 5xx. `AMF_NAMF_LOC_LMF=off` forces
    /// the same path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provide_positioning_info_falls_back_to_the_ngap_cell_without_an_lmf() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Distinct SUPI and cell from the LMF-driven sibling.
        let supi = "imsi-001010000740730";
        let mut ue = setup_ue(supi, true, true);
        ue.nr_cgi.cell_id = 0x0074_0730;
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.amf_ue_update(&ue);
            guard.amf_ue_publish(&ue, 900_749, 1);
        }

        // The switch, not an absent LMF: asserting the OFF path also asserts the
        // fallback body, and it does so without depending on nothing listening on a
        // port this test does not control.
        std::env::set_var("AMF_NAMF_LOC_LMF", "off");
        let resp = namf_request_handler(
            SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
                .with_json_body(&json!({
                    "lcsClientType": "VALUE_ADDED_SERVICES",
                    "lcsLocation": "CURRENT_OR_LAST_KNOWN_LOCATION",
                }))
                .expect("json"),
        )
        .await;
        std::env::remove_var("AMF_NAMF_LOC_LMF");

        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        assert_eq!(
            body["ncgi"]["nrCellId"].as_str(),
            Some("000740730"),
            "the pre-#74 answer is preserved when the LMF leg is off"
        );
        assert!(
            body["locationEstimate"].is_null(),
            "and no position is invented: the AMF has none without the LMF"
        );
    }
    // ========================================================================
    // #396: NonUeN2MessageTransfer, PWS information class
    // (TS 29.518 §5.2.2.4.1.3)
    // ========================================================================

    /// A conformant WRITE-REPLACE WARNING REQUEST container as a CBCF would send
    /// it: real APER bytes from the NGAP builder, not a placeholder. Returns the
    /// PDU so a test can assert what the gNB would receive.
    fn pws_warning_container(message_identifier: u16, serial_number: u16) -> Vec<u8> {
        nextgcore_ngap::builder::build_write_replace_warning_request(
            &nextgcore_ngap::types::WriteReplaceWarningRequest {
                message_identifier,
                serial_number,
                warning_area_list: None,
                repetition_period: 32,
                number_of_broadcasts_requested: 3,
                warning_type: None,
                warning_security_info: None,
                data_coding_scheme: Some(0x01),
                warning_message_contents: Some(b"TSUNAMI".to_vec()),
                concurrent_warning_message_indicator: false,
                warning_area_coordinates: None,
            },
        )
        .expect("build WRITE-REPLACE WARNING REQUEST")
    }

    /// A `NonUeN2MessageTransfer` request with the container in a multipart part,
    /// the shape `N2InfoContent.ngapData` (a `RefToBinaryData`) requires.
    fn pws_transfer_request(body: Value, container: Vec<u8>) -> SbiRequest {
        SbiRequest::post("/namf-comm/v1/non-ue-n2-messages/transfer")
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "pws-container",
                "application/vnd.3gpp.ngap",
                container.into(),
            ))
    }

    fn pws_body(message_identifier: u16, serial_number: u16) -> Value {
        json!({
            "n2Information": {
                "n2InformationClass": "PWS",
                "pwsInfo": {
                    "messageIdentifier": message_identifier,
                    "serialNumber": serial_number,
                    "pwsContainer": {
                        "ngapData": { "contentId": "pws-container" }
                    }
                }
            }
        })
    }

    /// The router arm exists AND the handler enqueues the container for NGAP
    /// egress, and the 200 body echoes the three mandatory `PWSResponseData`
    /// members (TS 29.518 §5.2.2.4.1.3 step 2a, `29518-k00.txt:4169`).
    ///
    /// Before #396 this URI fell to the `_` arm and answered 404
    /// RESOURCE_URI_STRUCTURE_NOT_FOUND.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pws_warning_transfer_is_routed_enqueued_and_echoed() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        // Distinct literal identifiers per test: the queue is process-global, so
        // reusing a pair across tests would let one test drain another's item.
        let (mid, sn) = (0x1396u16, 0x3396u16);
        let container = pws_warning_container(mid, sn);

        // Start from a known-empty queue: an earlier test in this process may
        // have left an item if it failed mid-way.
        {
            let ctx = crate::context::amf_self();
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            let _ = guard.pws_n2_drain();
        }

        let resp =
            namf_request_handler(pws_transfer_request(pws_body(mid, sn), container.clone())).await;
        assert_eq!(resp.status, 200, "the PWS transfer arm must be routed");

        let body = body_json(&resp);
        assert_eq!(
            body["result"].as_str(),
            Some("N2_INFO_TRANSFER_INITIATED"),
            "result is the only required member of N2InformationTransferRspData"
        );
        // `ngapMessageType` is the NGAP procedure code the AMF relayed:
        // id-WriteReplaceWarning = 51 (`38413-j30.txt:59115`).
        assert_eq!(body["pwsRspData"]["ngapMessageType"].as_u64(), Some(51));
        assert_eq!(
            body["pwsRspData"]["messageIdentifier"].as_u64(),
            Some(mid as u64)
        );
        assert_eq!(body["pwsRspData"]["serialNumber"].as_u64(), Some(sn as u64));
        // `sendRanResponse` was absent, so the AMF must NOT volunteer the
        // "re-create your subscription" signal.
        assert!(
            body["pwsRspData"]["n2PwsSubMissInd"].is_null(),
            "n2PwsSubMissInd is only for sendRanResponse:true (§5.2.2.4.1.3)"
        );

        // The arm reached the queue the NGAP pump drains -- the "correct but
        // unreachable" check. And the enqueued bytes are the container VERBATIM:
        // the AMF forwards, it does not re-encode (`29518-k00.txt:4152`).
        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert_eq!(pending.len(), 1, "exactly one relay must be queued");
        assert_eq!(
            pending[0].ngap_pdu, container,
            "the relayed PDU must be byte-identical to the CBCF's container"
        );
        assert_eq!(pending[0].message_identifier, mid);
        assert_eq!(pending[0].serial_number, sn);
        // And that PDU really is procedure 51 with the InitiatingMessage CHOICE
        // index in byte 0 -- what the gNB would decode.
        assert_eq!(pending[0].ngap_pdu[0], 0x00);
        assert_eq!(pending[0].ngap_pdu[1], 51);
    }

    /// `sendRanResponse: true` gets `n2PwsSubMissInd: true`, because this AMF
    /// serves no `non-ue-n2-info-subscriptions` resource so the subscription
    /// genuinely cannot exist. That is the spec's own prescribed answer
    /// (§5.2.2.4.1.3, `29518-k00.txt:4176-4181`), not a stub.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_ran_response_without_a_subscription_reports_n2_pws_sub_miss_ind() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let (mid, sn) = (0x2396u16, 0x4396u16);
        let mut body = pws_body(mid, sn);
        body["n2Information"]["pwsInfo"]["sendRanResponse"] = Value::Bool(true);

        let resp =
            namf_request_handler(pws_transfer_request(body, pws_warning_container(mid, sn))).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["pwsRspData"]["n2PwsSubMissInd"].as_bool(),
            Some(true),
            "with no PWS N2 information subscription the AMF must tell the \
             consumer to re-create it, not fabricate a per-RAN report"
        );

        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        let _ = guard.pws_n2_drain();
    }

    /// A container that is not an AMF-initiated PWS procedure is REFUSED, not
    /// relayed. TS 38.413 §8.12 makes WriteReplaceWarning (51) and PWSCancel (32)
    /// AMF-initiated; the two indications are gNB-initiated, so a consumer
    /// sending one has the direction backwards. Relaying it would earn an Error
    /// Indication from the gNB that the CBCF never sees.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_amf_initiated_pws_container_is_refused_rather_than_relayed() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        // A PWS FAILURE INDICATION (procedure 33) -- gNB->AMF.
        let wrong_direction = nextgcore_ngap::builder::build_pws_failure_indication(
            &nextgcore_ngap::types::PwsFailureIndication {
                failed_cell_list: nextgcore_ngap::types::PwsCellList::Nr(vec![
                    nextgcore_ngap::types::NrCgi {
                        plmn_identity: [0x00, 0xF1, 0x10],
                        nr_cell_identity: 0x396,
                    },
                ]),
                global_ran_node_id: nextgcore_ngap::types::GlobalRanNodeId::GlobalGnbId {
                    plmn_identity: [0x00, 0xF1, 0x10],
                    gnb_id: 0x396,
                    gnb_id_len: 32,
                },
            },
        )
        .expect("build PWS FAILURE INDICATION");
        assert_eq!(wrong_direction[1], 33, "the fixture must be procedure 33");

        let resp = namf_request_handler(pws_transfer_request(
            pws_body(0x3396, 0x5396),
            wrong_direction,
        ))
        .await;
        assert_eq!(resp.status, 400);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert!(
            pending.is_empty(),
            "a refused container must not reach the NGAP egress queue"
        );
    }

    /// An undecodable container is a 400 and is not enqueued. Without this the
    /// AMF would forward arbitrary bytes to every served gNB.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_undecodable_pws_container_is_refused() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let resp = namf_request_handler(pws_transfer_request(
            pws_body(0x4396, 0x6396),
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        ))
        .await;
        assert_eq!(resp.status, 400);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert!(pending.is_empty());
    }

    /// The JSON identifiers and the container's must agree. A mismatch means one
    /// of the two is wrong, and echoing one while broadcasting the other would
    /// make the AMF lie in both directions at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mismatched_identifiers_between_json_and_container_are_refused() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        // JSON says 0x5396/0x7396; the container carries 0x0001/0x0002.
        let resp = namf_request_handler(pws_transfer_request(
            pws_body(0x5396, 0x7396),
            pws_warning_container(0x0001, 0x0002),
        ))
        .await;
        assert_eq!(resp.status, 400);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert!(pending.is_empty());
    }

    /// A non-PWS `n2InformationClass` is refused rather than answered 200. The
    /// other classes this operation carries (NRPPa, RAN, TSS) each need their own
    /// transport; a 200 for them would claim a transfer that never happened.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_pws_information_class_is_not_served_here() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let resp = namf_request_handler(pws_transfer_request(
            json!({
                "n2Information": {
                    "n2InformationClass": "NRPPa",
                    "nrppaInfo": {
                        "nfId": "6396",
                        "nrppaPdu": { "ngapData": { "contentId": "pws-container" } }
                    }
                }
            }),
            pws_warning_container(0x6396, 0x8396),
        ))
        .await;
        assert_eq!(resp.status, 403);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert!(pending.is_empty());
    }

    /// Each mandatory member of the request is enforced with
    /// MANDATORY_IE_MISSING, not defaulted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_mandatory_pws_members_are_rejected() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let container = pws_warning_container(0x7396, 0x9396);

        // n2Information absent entirely.
        let resp = namf_request_handler(pws_transfer_request(json!({}), container.clone())).await;
        assert_eq!(resp.status, 400);

        // pwsInfo absent.
        let resp = namf_request_handler(pws_transfer_request(
            json!({ "n2Information": { "n2InformationClass": "PWS" } }),
            container.clone(),
        ))
        .await;
        assert_eq!(resp.status, 400);

        // Each of the three required PwsInformation members, dropped in turn.
        for missing in ["messageIdentifier", "serialNumber", "pwsContainer"] {
            let mut body = pws_body(0x7396, 0x9396);
            body["n2Information"]["pwsInfo"]
                .as_object_mut()
                .expect("pwsInfo object")
                .remove(missing);
            let resp = namf_request_handler(pws_transfer_request(body, container.clone())).await;
            assert_eq!(
                resp.status, 400,
                "a PWS transfer missing {missing} must be refused"
            );
        }

        // A contentId naming no part is a 400, not a relay of nothing.
        let mut body = pws_body(0x7396, 0x9396);
        body["n2Information"]["pwsInfo"]["pwsContainer"]["ngapData"]["contentId"] =
            Value::String("no-such-part".into());
        let resp = namf_request_handler(pws_transfer_request(body, container)).await;
        assert_eq!(resp.status, 400);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert!(pending.is_empty(), "no refused request may be enqueued");
    }

    /// The targeting selectors survive the JSON boundary into the queue item the
    /// NGAP pump resolves. `gNBValue` is hex and `tac` is hex (TS 29.571), so a
    /// decimal parse here would silently target the wrong nodes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn targeting_selectors_survive_the_json_boundary() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let (mid, sn) = (0x8396u16, 0xA396u16);
        let mut body = pws_body(mid, sn);
        body["globalRanNodeList"] = json!([
            { "plmnId": { "mcc": "001", "mnc": "01" },
              "gNbId": { "bitLength": 32, "gNBValue": "0000ABCD" } }
        ]);
        body["taiList"] = json!([
            { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000074" }
        ]);
        body["ratSelector"] = Value::String("NR".into());

        let resp =
            namf_request_handler(pws_transfer_request(body, pws_warning_container(mid, sn))).await;
        assert_eq!(resp.status, 200);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].target_gnb_ids,
            vec![0xABCDu32],
            "gNBValue is HEX: a decimal parse would target gNB 0"
        );
        assert_eq!(
            pending[0].target_tais,
            vec![(crate::context::PlmnId::new("001", "01"), 0x74u32)],
            "tac is HEX: 000074 is 116, not 74"
        );
        assert_eq!(
            pending[0].rat_selector,
            Some(crate::context::PwsRatSelector::Nr)
        );
    }

    /// An unknown `ratSelector` is refused rather than silently ignored: treating
    /// it as absent would broadcast to every RAT the consumer meant to exclude.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unknown_rat_selector_is_refused() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let (mid, sn) = (0x9396u16, 0xB396u16);
        let mut body = pws_body(mid, sn);
        body["ratSelector"] = Value::String("WLAN".into());

        let resp =
            namf_request_handler(pws_transfer_request(body, pws_warning_container(mid, sn))).await;
        assert_eq!(resp.status, 400);

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert!(pending.is_empty());
    }

    /// A PWS CANCEL REQUEST container (procedure 32) relays too, and its echoed
    /// `ngapMessageType` is 32 — not hardcoded 51.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pws_cancel_container_relays_and_echoes_procedure_32() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let (mid, sn) = (0xA396u16, 0xC396u16);
        let cancel = nextgcore_ngap::builder::build_pws_cancel_request(
            &nextgcore_ngap::types::PwsCancelRequest {
                message_identifier: mid,
                serial_number: sn,
                warning_area_list: None,
                cancel_all_warning_messages: true,
            },
        )
        .expect("build PWS CANCEL REQUEST");

        let resp = namf_request_handler(pws_transfer_request(pws_body(mid, sn), cancel)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["pwsRspData"]["ngapMessageType"].as_u64(),
            Some(32),
            "ngapMessageType must be the procedure actually relayed"
        );

        let ctx = crate::context::amf_self();
        let pending = {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.pws_n2_drain()
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].ngap_pdu[1], 32);
    }

    // ========================================================================
    // #399: NonUeN2InfoSubscribe / UnSubscribe and the conditional
    // n2PwsSubMissInd + unknownTaiList (TS 29.518 §5.2.2.4.2/.3/.4)
    // ========================================================================

    /// Remove every stored ANONYMOUS (no `nfId`) non-UE N2 subscription. The store
    /// is process-global, so a test that asserts "no subscription matched" has to
    /// start from empty or a sibling test's leftover subscription would answer for
    /// it.
    ///
    /// Only the anonymous ones, because `find_by_class_exact(class, None)` matches
    /// exactly those, and neither lookup can reach an `nfId`-bearing subscription
    /// without knowing the id — `find_by_class(class, None)` deliberately refuses a
    /// subscription that named an instance, which is the fail-closed rule under
    /// test. The two tests that create `nfId`-bearing subscriptions therefore
    /// remove them by their own minted id, which is also a better assertion: it
    /// proves the DELETE resource works rather than reaching around it.
    ///
    /// Drains by repeated find-and-remove rather than a bulk clear: adding a
    /// `clear_all` to the context purely for tests would put a production-looking
    /// API there that no production caller has — the shape that becomes a dead
    /// method later.
    fn clear_non_ue_n2_subscriptions() {
        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        for class in super::PWS_N2_INFORMATION_CLASSES {
            while let Some(sub) = guard.non_ue_n2_subscription_find_by_class_exact(class, None) {
                guard.non_ue_n2_subscription_remove(&sub.subscription_id);
            }
        }
    }

    fn non_ue_n2_subscribe_request(body: Value) -> SbiRequest {
        SbiRequest::post("/namf-comm/v1/non-ue-n2-messages/subscriptions")
            .with_json_body(&body)
            .expect("json")
    }

    /// Criterion 1. The subscription resource is routed **at the URI TS 29.518
    /// defines** and returns the 201 + Location + CreatedData §6.1.3.9.3.1
    /// requires, and the record is findable by class afterwards.
    ///
    /// The second half is the load-bearing one: #399's body names the path
    /// `non-ue-n2-info-subscriptions`, which appears NOWHERE in TS 29.518 or its
    /// OpenAPI. §6.1.3.9.2 (`29518-k00.txt:9962`) and `yaml:1921` both put the
    /// collection at `non-ue-n2-messages/subscriptions`. This asserts the wrong
    /// spelling stays a 404, so it can never quietly start working and leave the
    /// AMF serving an endpoint no conformant CBCF calls.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_ue_n2_info_subscribe_is_routed_at_the_spec_uri_and_returns_a_location() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        clear_non_ue_n2_subscriptions();

        let resp = namf_request_handler(non_ue_n2_subscribe_request(json!({
            "n2InformationClass": "PWS-BCAL",
            "n2NotifyCallbackUri": "http://127.0.0.1:19399/pws-notify",
            "nfId": "cbcf-399-0001",
            "notifCorrelationId": "corr-399",
        })))
        .await;
        assert_eq!(
            resp.status, 201,
            "the NonUeN2InfoSubscribe arm must be routed"
        );

        let body = body_json(&resp);
        let sub_id = body["n2NotifySubscriptionId"]
            .as_str()
            .expect("n2NotifySubscriptionId is mandatory in NonUeN2InfoSubscriptionCreatedData")
            .to_string();
        assert_eq!(
            body["n2InformationClass"].as_str(),
            Some("PWS-BCAL"),
            "the registered class is echoed so the consumer can confirm it"
        );
        // §6.1.3.9.3.1 requires the Location header, structured per `yaml:1945`.
        let location = resp
            .http
            .get_header("location")
            .expect("201 must carry a Location header")
            .clone();
        assert_eq!(
            location,
            format!("/namf-comm/v1/non-ue-n2-messages/subscriptions/{sub_id}"),
            "Location must be the spec's resource structure, not the issue's"
        );

        // The arm reached the store the NGAP notify path reads -- the
        // "correct but unreachable" check, from the writer side.
        let ctx = crate::context::amf_self();
        {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            let stored = guard
                .non_ue_n2_subscription_find("=none=")
                .or_else(|| guard.non_ue_n2_subscription_find(&sub_id))
                .expect("the subscription must be findable by its minted id");
            assert_eq!(stored.n2_information_class, "PWS-BCAL");
            assert_eq!(
                stored.n2_notify_callback_uri,
                "http://127.0.0.1:19399/pws-notify"
            );
            assert_eq!(stored.nf_id.as_deref(), Some("cbcf-399-0001"));
            assert_eq!(stored.notif_correlation_id.as_deref(), Some("corr-399"));
            // And findable by the class the notify path looks it up under, for the
            // same nfId.
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class("PWS-BCAL", Some("cbcf-399-0001"))
                    .is_some(),
                "the notify path's own lookup must find what the router stored"
            );
        }

        // The URI #399 asked for is NOT served.
        let wrong = namf_request_handler(
            SbiRequest::post("/namf-comm/v1/non-ue-n2-info-subscriptions")
                .with_json_body(&json!({
                    "n2InformationClass": "PWS",
                    "n2NotifyCallbackUri": "http://127.0.0.1:19399/pws-notify",
                }))
                .expect("json"),
        )
        .await;
        assert_eq!(
            wrong.status, 404,
            "`non-ue-n2-info-subscriptions` is not a TS 29.518 resource and must stay unrouted"
        );

        // DELETE round-trips at the Location the 201 advertised, which is the only
        // proof that header is usable rather than merely present.
        let deleted = namf_request_handler(SbiRequest::delete(&location)).await;
        assert_eq!(deleted.status, 204);
        clear_non_ue_n2_subscriptions();
    }

    /// Fail-closed validation: each mandatory member enforced, a non-HTTP callback
    /// refused, and a class this AMF cannot notify refused rather than stored as a
    /// subscription that silently never fires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_ue_n2_info_subscribe_rejects_half_pairs_and_unservable_classes() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        clear_non_ue_n2_subscriptions();

        // n2InformationClass absent (M, `yaml:2595`).
        let resp = namf_request_handler(non_ue_n2_subscribe_request(json!({
            "n2NotifyCallbackUri": "http://127.0.0.1:19399/x",
        })))
        .await;
        assert_eq!(resp.status, 400);

        // n2NotifyCallbackUri absent (M, `yaml:2596`).
        let resp = namf_request_handler(non_ue_n2_subscribe_request(json!({
            "n2InformationClass": "PWS",
        })))
        .await;
        assert_eq!(resp.status, 400);

        // A callback the AMF could never POST to.
        let resp = namf_request_handler(non_ue_n2_subscribe_request(json!({
            "n2InformationClass": "PWS",
            "n2NotifyCallbackUri": "not-a-uri",
        })))
        .await;
        assert_eq!(resp.status, 400);

        // A class with no producer here. NRPPa in particular is already served by
        // the per-UE `n1-n2-messages/subscriptions` registry, so accepting it would
        // store a second subscription nothing reads.
        for class in ["NRPPa", "SM", "TSS", "RAN"] {
            let resp = namf_request_handler(non_ue_n2_subscribe_request(json!({
                "n2InformationClass": class,
                "n2NotifyCallbackUri": "http://127.0.0.1:19399/x",
            })))
            .await;
            assert_eq!(
                resp.status, 403,
                "class {class} has no PWS producer and must not be stored"
            );
        }

        // Nothing refused reached the store. Asserted per-class rather than as a
        // count: the store is process-global and a sibling test's `nfId`-bearing
        // subscription would make a count assertion fail for the wrong reason,
        // whereas "is this exact class findable" is precisely the claim.
        let ctx = crate::context::amf_self();
        {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            for class in ["NRPPa", "SM", "TSS", "RAN"] {
                assert!(
                    guard
                        .non_ue_n2_subscription_find_by_class_exact(class, None)
                        .is_none(),
                    "refused class {class} must not have been stored"
                );
            }
        }

        // All three PWS classes ARE accepted (§5.2.2.4.2.2, `29518-k00.txt:4334`)
        // and each becomes findable under its own class.
        for class in super::PWS_N2_INFORMATION_CLASSES {
            let resp = namf_request_handler(non_ue_n2_subscribe_request(json!({
                "n2InformationClass": class,
                "n2NotifyCallbackUri": "http://127.0.0.1:19399/x",
            })))
            .await;
            assert_eq!(resp.status, 201, "class {class} must be accepted");
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class_exact(class, None)
                    .is_some(),
                "accepted class {class} must be stored and findable"
            );
        }
        clear_non_ue_n2_subscriptions();
    }

    /// DELETE is 204 the first time and 404 `SUBSCRIPTION_NOT_FOUND` the second —
    /// the cause §6.1.3.10.3.1's table names (`29518-k00.txt:10170`), which is NOT
    /// the `CONTEXT_NOT_FOUND` the per-UE unsubscribe uses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_ue_n2_info_unsubscribe_removes_it_and_is_404_the_second_time() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        clear_non_ue_n2_subscriptions();

        let created = namf_request_handler(non_ue_n2_subscribe_request(json!({
            "n2InformationClass": "PWS-RF",
            "n2NotifyCallbackUri": "http://127.0.0.1:19399/rf",
        })))
        .await;
        assert_eq!(created.status, 201);
        let sub_id = body_json(&created)["n2NotifySubscriptionId"]
            .as_str()
            .expect("id")
            .to_string();

        let path = format!("/namf-comm/v1/non-ue-n2-messages/subscriptions/{sub_id}");
        let first = namf_request_handler(SbiRequest::delete(&path)).await;
        assert_eq!(first.status, 204, "§5.2.2.4.3.1 step 2 answers 204");

        let second = namf_request_handler(SbiRequest::delete(&path)).await;
        assert_eq!(second.status, 404);
        assert_eq!(
            body_json(&second)["cause"].as_str(),
            Some("SUBSCRIPTION_NOT_FOUND"),
            "§6.1.3.10.3.1 names this cause, not CONTEXT_NOT_FOUND"
        );

        // And the notify path can no longer find it: an unsubscribed consumer must
        // stop receiving, which is the whole point of the DELETE.
        let ctx = crate::context::amf_self();
        {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class("PWS-RF", None)
                    .is_none(),
                "the removed subscription must not still match a notify lookup"
            );
        }
    }

    /// A `PWS-RF` subscription must NOT answer for a RESPONSE, and a `PWS-BCAL` one
    /// must NOT answer for an INDICATION. The two classes carry disjoint message
    /// sets (Tables 6.1.6.4.3.3-2 / -3, `29518-k00.txt:19055` / `:19108`), so
    /// crossing them would notify a consumer about a class it did not ask for.
    /// The umbrella `PWS` does answer for both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_two_specific_pws_classes_do_not_answer_for_each_other() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        clear_non_ue_n2_subscriptions();

        let ctx = crate::context::amf_self();

        // Only PWS-RF subscribed.
        assert_eq!(
            namf_request_handler(non_ue_n2_subscribe_request(json!({
                "n2InformationClass": "PWS-RF",
                "n2NotifyCallbackUri": "http://127.0.0.1:19399/rf",
            })))
            .await
            .status,
            201
        );
        {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class("PWS-RF", None)
                    .is_some(),
                "an indication finds the PWS-RF subscription"
            );
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class("PWS-BCAL", None)
                    .is_none(),
                "a RESPONSE must NOT be delivered to a PWS-RF-only subscriber"
            );
        }
        clear_non_ue_n2_subscriptions();

        // The umbrella class answers for both.
        assert_eq!(
            namf_request_handler(non_ue_n2_subscribe_request(json!({
                "n2InformationClass": "PWS",
                "n2NotifyCallbackUri": "http://127.0.0.1:19399/pws",
            })))
            .await
            .status,
            201
        );
        {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class("PWS-BCAL", None)
                    .is_some(),
                "the umbrella PWS class covers responses (§5.2.2.4.2.2)"
            );
            assert!(
                guard
                    .non_ue_n2_subscription_find_by_class("PWS-RF", None)
                    .is_some(),
                "and indications"
            );
        }
        clear_non_ue_n2_subscriptions();
    }

    /// Criterion 4. `n2PwsSubMissInd` is `true` only when `sendRanResponse: true`
    /// **AND** no subscription exists — §5.2.2.4.1.3's actual condition
    /// (`29518-k00.txt:4175-4181`). Before #399 it was unconditional on
    /// `sendRanResponse`, which was right when no subscription resource existed and
    /// becomes a lie the moment one does: a consumer told to "re-create the missing
    /// N2 information subscription" would needlessly tear down a live one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn n2_pws_sub_miss_ind_is_suppressed_once_a_pws_subscription_exists() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);
        clear_non_ue_n2_subscriptions();

        // Distinct literal pair: both the queue and the sendRanResponse map are
        // process-global and keyed on it.
        let (mid, sn) = (0xB396u16, 0xD396u16);
        let nf_id = "cbcf-399-missind";

        let mut body = pws_body(mid, sn);
        body["n2Information"]["pwsInfo"]["sendRanResponse"] = Value::Bool(true);
        body["n2Information"]["pwsInfo"]["nfId"] = Value::String(nf_id.into());

        // No subscription yet -> the spec's signal, as #401 shipped it.
        let resp = namf_request_handler(pws_transfer_request(
            body.clone(),
            pws_warning_container(mid, sn),
        ))
        .await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["pwsRspData"]["n2PwsSubMissInd"].as_bool(),
            Some(true),
            "with no subscription the consumer must be told to create one"
        );

        // Now subscribe as that same CBCF instance and repeat.
        let created = namf_request_handler(non_ue_n2_subscribe_request(json!({
            "n2InformationClass": "PWS-BCAL",
            "n2NotifyCallbackUri": "http://127.0.0.1:19399/missind",
            "nfId": nf_id,
        })))
        .await;
        assert_eq!(created.status, 201);
        let sub_id = body_json(&created)["n2NotifySubscriptionId"]
            .as_str()
            .expect("id")
            .to_string();

        let resp =
            namf_request_handler(pws_transfer_request(body, pws_warning_container(mid, sn))).await;
        assert_eq!(resp.status, 200);
        assert!(
            body_json(&resp)["pwsRspData"]["n2PwsSubMissInd"].is_null(),
            "the subscription EXISTS now, so claiming it is missing would make a \
             conformant consumer tear down a live subscription"
        );

        let ctx = crate::context::amf_self();
        {
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            let _ = guard.pws_n2_drain();
            // The sendRanResponse record the asynchronous notify path reads was
            // written by this live SBI arm -- reachability, from the writer side.
            let record = guard
                .pws_response_request_get(mid, sn)
                .expect("sendRanResponse:true must be recorded for the response path");
            assert!(record.send_ran_response);
            assert_eq!(record.nf_id.as_deref(), Some(nf_id));
            assert_eq!(record.procedure_code, 51);
        }

        // Remove through the real DELETE resource: the helper only reaches
        // anonymous subscriptions, and going through the router also proves the
        // subscription an `nfId` created is removable.
        assert_eq!(
            namf_request_handler(SbiRequest::delete(&format!(
                "/namf-comm/v1/non-ue-n2-messages/subscriptions/{sub_id}"
            )))
            .await
            .status,
            204
        );
        clear_non_ue_n2_subscriptions();
    }

    /// A transfer WITHOUT `sendRanResponse` records nothing, so the asynchronous
    /// response path has nothing to match and cannot notify. Asserted positively
    /// rather than as "no error occurred": the record's absence is the fail-closed
    /// gate §5.2.2.4.4.3 item 1 requires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transfer_without_send_ran_response_records_nothing_to_notify() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        let (mid, sn) = (0xC396u16, 0xE396u16);
        let resp = namf_request_handler(pws_transfer_request(
            pws_body(mid, sn),
            pws_warning_container(mid, sn),
        ))
        .await;
        assert_eq!(resp.status, 200);

        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        let _ = guard.pws_n2_drain();
        assert!(
            guard.pws_response_request_get(mid, sn).is_none(),
            "no sendRanResponse means no record, so no notification is ever owed"
        );
    }

    /// Criterion 5, in the only form the spec and the code permit.
    ///
    /// `unknownTaiList` reports the `taiList` entries naming TAIs this AMF does not
    /// SERVE, and only on the PWS Cancel branch — §5.2.2.4.1.3 step 2a
    /// (`29518-k00.txt:4169-4173`) hangs the "optionally the unknown TAI List IE"
    /// option off the *Stop-Warning* Confirm response, not off the
    /// Write-Replace-Warning Confirm one.
    ///
    /// It deliberately is NOT "TAIs no connected node served", which #399 asked
    /// for: that fact lives in the NGAP pump, which runs after this 200 is written,
    /// and `unknownTaiList` exists only in the SYNCHRONOUS `PWSResponseData`
    /// (`yaml:3348` is its one referent) — it is absent from
    /// `N2InformationNotification`, so it cannot ride the async notify either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_tai_list_reports_tais_this_amf_does_not_serve_on_the_cancel_branch() {
        let _ctx = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = super::pws_queue_test_lock().lock().await;
        amf_context_init(64, 1024, 4096);

        // Configure ONE served TAI, the way the config loader does at startup
        // (`lib.rs:520`) -- unlike `gnb_list`, `served_tai` has a real production
        // writer, which is what makes this fact honestly knowable here.
        {
            let ctx = crate::context::amf_self();
            let mut guard = ctx.write().unwrap_or_else(|e| e.into_inner());
            guard.served_tai.clear();
            guard.num_of_served_tai = 0;
            let mut served = crate::context::ServedTai::default();
            served.list0.plmn_id = crate::context::PlmnId::new("001", "01");
            served.list0.tac = vec![0x74];
            guard.served_tai.push(served);
            guard.num_of_served_tai = 1;
        }

        let (mid, sn) = (0xD396u16, 0xF396u16);
        let cancel = nextgcore_ngap::builder::build_pws_cancel_request(
            &nextgcore_ngap::types::PwsCancelRequest {
                message_identifier: mid,
                serial_number: sn,
                warning_area_list: None,
                cancel_all_warning_messages: false,
            },
        )
        .expect("build PWS CANCEL REQUEST");

        // One served TAI (tac 000074 == 0x74) and one this AMF does not serve.
        let mut body = pws_body(mid, sn);
        body["taiList"] = json!([
            { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000074" },
            { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000099" },
        ]);

        let resp = namf_request_handler(pws_transfer_request(body.clone(), cancel.clone())).await;
        assert_eq!(resp.status, 200);
        let unknown = body_json(&resp)["pwsRspData"]["unknownTaiList"].clone();
        assert_eq!(
            unknown,
            json!([{ "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000099" }]),
            "exactly the unserved TAI is reported -- not the served one, and not all of them"
        );

        // The Write-Replace branch carries no unknownTaiList even with the same
        // unserved TAI, because the spec scopes the IE to Stop-Warning Confirm.
        let mut wr_body = pws_body(mid, sn);
        wr_body["taiList"] = body["taiList"].clone();
        let resp = namf_request_handler(pws_transfer_request(
            wr_body,
            pws_warning_container(mid, sn),
        ))
        .await;
        assert_eq!(resp.status, 200);
        assert!(
            body_json(&resp)["pwsRspData"]["unknownTaiList"].is_null(),
            "§5.2.2.4.1.3 step 2a offers the unknown TAI List only on the \
             Stop-Warning Confirm branch"
        );

        // And when every TAI is served the IE is OMITTED, not sent empty
        // (`minItems: 1`, `yaml:3791`).
        let mut all_served = pws_body(mid, sn);
        all_served["taiList"] =
            json!([{ "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000074" }]);
        let resp = namf_request_handler(pws_transfer_request(all_served, cancel)).await;
        assert_eq!(resp.status, 200);
        assert!(body_json(&resp)["pwsRspData"]["unknownTaiList"].is_null());

        let ctx = crate::context::amf_self();
        let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
        let _ = guard.pws_n2_drain();
    }

    /// The `n2InfoNotify` body the AMF delivers, asserted member by member against
    /// a **gNB-produced** WRITE-REPLACE WARNING RESPONSE (criterion 6's
    /// `build_write_replace_warning_response`).
    ///
    /// This is the body builder the live producer calls, so the assertions are on
    /// what a CBCF would actually receive: the class, the RAN's own identifiers,
    /// the responding node's identity, and the container byte-for-byte.
    #[test]
    fn the_n2_info_notify_body_carries_the_rans_own_response_verbatim() {
        let (mid, sn) = (0xE396u16, 0x1397u16);
        // A conformant response as the gNB would send it, with a real completed
        // area list.
        let pdu = nextgcore_ngap::builder::build_write_replace_warning_response(
            &nextgcore_ngap::types::WriteReplaceWarningResponse {
                message_identifier: mid,
                serial_number: sn,
                broadcast_completed_area_list: Some(
                    nextgcore_ngap::types::BroadcastCompletedAreaList::CellIdNr(vec![
                        nextgcore_ngap::types::NrCgi {
                            plmn_identity: [0x00, 0xF1, 0x10],
                            nr_cell_identity: 0x399,
                        },
                    ]),
                ),
                criticality_diagnostics: None,
            },
        )
        .expect("build WRITE-REPLACE WARNING RESPONSE");
        // Byte 0 is the PDU-type CHOICE index and byte 1 the procedure code: a
        // response is a SuccessfulOutcome (0x20) of procedure 51
        // (`38413-j30.txt:59115`). PR #379's MBS byte-writers were undecodable
        // because they opened with the procedure code instead.
        assert_eq!(pdu[0], 0x20, "a response is a SuccessfulOutcome");
        assert_eq!(pdu[1], 51, "id-WriteReplaceWarning = 51");

        let ran_node_id =
            super::global_ran_node_id_json(&crate::context::PlmnId::new("001", "01"), 0xABCD, 32);
        let request = super::build_non_ue_n2_info_notify_request(
            "/pws-notify",
            "nonuen2sub-399",
            "PWS-BCAL",
            mid,
            sn,
            &ran_node_id,
            false,
            Some("cbcf-399-0001"),
            Some("corr-399"),
            &pdu,
        )
        .expect("build NonUeN2InfoNotify");

        let json: Value = serde_json::from_str(
            request
                .http
                .content
                .as_deref()
                .expect("the notification must carry a jsonData part"),
        )
        .expect("json");
        assert_eq!(
            json["n2NotifySubscriptionId"].as_str(),
            Some("nonuen2sub-399")
        );
        // §6.1.6.4.3.3 Table 6.1.6.4.3.3-2 puts the two RESPONSES in PWS-BCAL.
        assert_eq!(
            json["n2InfoContainer"]["n2InformationClass"].as_str(),
            Some("PWS-BCAL")
        );
        // The identifiers are the RAN's, lifted out of the decoded response.
        assert_eq!(
            json["n2InfoContainer"]["pwsInfo"]["messageIdentifier"].as_u64(),
            Some(mid as u64)
        );
        assert_eq!(
            json["n2InfoContainer"]["pwsInfo"]["serialNumber"].as_u64(),
            Some(sn as u64)
        );
        assert_eq!(
            json["n2InfoContainer"]["pwsInfo"]["pwsContainer"]["ngapMessageType"].as_u64(),
            Some(51),
            "the container's own procedure code, read off byte 1"
        );
        // THIS specific node, not "a node": `GNbId` needs both members
        // (`TS29571_CommonData.yaml:2911-2913`).
        assert_eq!(
            json["ranNodeId"]["gNbId"]["gNBValue"].as_str(),
            Some("0000ABCD")
        );
        assert_eq!(json["ranNodeId"]["gNbId"]["bitLength"].as_u64(), Some(32));
        assert_eq!(json["ranNodeId"]["plmnId"]["mcc"].as_str(), Some("001"));
        assert_eq!(json["ranNodeId"]["plmnId"]["mnc"].as_str(), Some("01"));
        assert_eq!(json["notifCorrelationId"].as_str(), Some("corr-399"));
        assert_eq!(
            json["n2InfoContainer"]["pwsInfo"]["nfId"].as_str(),
            Some("cbcf-399-0001")
        );
        // The area list WAS present, so bcEmptyAreaList must be absent -- asserting
        // it would tell the CBCF the broadcast reached nowhere.
        assert!(
            json["n2InfoContainer"]["pwsInfo"]["bcEmptyAreaList"].is_null(),
            "bcEmptyAreaList is for a response that OMITTED its area list"
        );

        // And the RAN's PDU rides verbatim: the AMF declines §6.1.6.4.3.3's
        // re-encode permission (`29518-k00.txt:19069`) because a round trip through
        // a partial model drops IEs the gNB sent.
        let part = request
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some(super::NON_UE_N2_INFO_NOTIFY_PWS_CONTENT_ID))
            .expect("the binary PWS part must be present");
        assert_eq!(
            part.data.as_ref(),
            pdu.as_slice(),
            "the notified container must be byte-identical to the gNB's response"
        );
    }

    /// A response that omitted its Broadcast Completed Area List gets
    /// `bcEmptyAreaList` naming the responding node — §5.2.2.4.4.3's imperative
    /// ("the AMF **shall** include the NG-RAN node ID(s)",
    /// `29518-k00.txt:4468-4471`), as opposed to the aggregation "may" this path
    /// declines.
    #[test]
    fn a_response_without_an_area_list_reports_bc_empty_area_list() {
        let (mid, sn) = (0xF396u16, 0x2397u16);
        let pdu = nextgcore_ngap::builder::build_write_replace_warning_response(
            &nextgcore_ngap::types::WriteReplaceWarningResponse {
                message_identifier: mid,
                serial_number: sn,
                broadcast_completed_area_list: None,
                criticality_diagnostics: None,
            },
        )
        .expect("build WRITE-REPLACE WARNING RESPONSE");

        let ran_node_id =
            super::global_ran_node_id_json(&crate::context::PlmnId::new("001", "01"), 0x1234, 28);
        let request = super::build_non_ue_n2_info_notify_request(
            "/pws-notify",
            "nonuen2sub-399-empty",
            "PWS-BCAL",
            mid,
            sn,
            &ran_node_id,
            true,
            None,
            None,
            &pdu,
        )
        .expect("build NonUeN2InfoNotify");

        let json: Value = serde_json::from_str(
            request
                .http
                .content
                .as_deref()
                .expect("the notification must carry a jsonData part"),
        )
        .expect("json");
        assert_eq!(
            json["n2InfoContainer"]["pwsInfo"]["bcEmptyAreaList"],
            json!([ran_node_id]),
            "the node that answered with no area list must be named, not merely counted"
        );
        // A 28-bit gNB ID renders as 8 nibbles; a 22-bit one as 6. Padding to 8
        // always would claim a 32-bit ID for a narrow node.
        assert_eq!(
            json["ranNodeId"]["gNbId"]["gNBValue"].as_str(),
            Some("00001234")
        );
        assert_eq!(json["ranNodeId"]["gNbId"]["bitLength"].as_u64(), Some(28));
    }

    /// `gNBValue` width follows the bit length (TS 29.571's
    /// `^[A-Fa-f0-9]{6,8}$`): 6 nibbles at or below 24 bits, 8 above. This is why
    /// `AmfGnb` had to start carrying `gnb_id_len` — fabricating 22 or 32 would
    /// misidentify any node whose real ID is neither.
    #[test]
    fn global_ran_node_id_renders_the_gnb_id_at_its_real_bit_length() {
        let plmn = crate::context::PlmnId::new("001", "01");
        for (len, expected) in [
            (22u8, "0000AB"),
            (24, "0000AB"),
            (25, "000000AB"),
            (32, "000000AB"),
        ] {
            let json = super::global_ran_node_id_json(&plmn, 0xAB, len);
            assert_eq!(
                json["gNbId"]["gNBValue"].as_str(),
                Some(expected),
                "a {len}-bit gNB ID must render as {} nibbles",
                expected.len()
            );
            assert_eq!(json["gNbId"]["bitLength"].as_u64(), Some(len as u64));
        }
    }

    // ==================================================================
    // #397: SUBSCRIPTION_ID_CHANGE / _ADDITION and the §5.2.2.2.3.1 takeover
    // ==================================================================

    /// **#397 criterion 2.** CreateUEContext takes over the transferred
    /// `eventSubscriptionList` and fires `SUBSCRIPTION_ID_CHANGE` to the
    /// `subsChangeNotifyUri` — a DIFFERENT endpoint from `eventNotifyUri`.
    ///
    /// `EventSubscription` had no `subs_change_*` member at all before this, so the two
    /// types could not be emitted conformantly and were silent. §6.2 says of both that
    /// they *"need no explicit subscription form an NF service consumer"*
    /// (`29518-k00.txt:24052`), so no consumer ever lists them in an `eventList` — which
    /// is why they are NOT matched against `event_types` the way every other emitter is.
    ///
    /// # What makes this assert the production site
    ///
    /// The subscription arrives ONLY inside the CreateUEContext body and the
    /// notification arrives at a server this test owns, so the assertion traverses the
    /// real router arm, the real takeover and a real HTTP POST. Two endpoints are stood
    /// up, not one: asserting on the `subsChangeNotifyUri` sink proves §6.2.5.2.1's
    /// routing rule — *"this callback URI shall be the `subsChangeNotifyUri`... Otherwise
    /// ... the `eventNotifyUri`"* — rather than merely that something was delivered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_ue_context_takes_over_subscriptions_and_fires_subscription_id_change() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        // A SUPI and PEI no sibling uses: the subscription store and the UE store are
        // both process-global, and the delivered report is asserted on this SUPI.
        let supi = "imsi-001010000397600";
        let pei = "imeisv-0000000000397600";
        // TWO sinks. The change notification must arrive at the `subsChange` one and
        // NOT at the event one -- that distinction is the clause under test.
        let (change_sink, change_port, mut change_rx) = start_capture_server().await;
        let (event_sink, event_port, mut event_rx) = start_capture_server().await;

        let mut body = create_ue_context_body(supi, pei);
        body["ueContext"]["eventSubscriptionList"] = json!([{
            "eventList": [{ "type": "LOCATION_REPORT" }],
            "eventNotifyUri": format!("http://127.0.0.1:{event_port}/notify/397-evt"),
            "notifyCorrelationId": "corr-397-transferred",
            "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "supi": supi,
            "subsChangeNotifyUri": format!("http://127.0.0.1:{change_port}/notify/397-subs-change"),
            "subsChangeNotifyCorrelationId": "corr-397-subs-change",
        }]);

        let resp = namf_request_handler(
            SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{supi}"))
                .with_json_body(&body)
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 201,
            "CreateUEContext must succeed; the takeover runs on the created context"
        );

        let (uri, posted) = tokio::time::timeout(Duration::from_secs(3), change_rx.recv())
            .await
            .expect(
                "the §5.2.2.2.3.1 takeover must fire SUBSCRIPTION_ID_CHANGE to the \
                 subsChangeNotifyUri. Before #397 `EventSubscription` had no such member, \
                 so this event type could not be emitted at all",
            )
            .expect("channel closed");
        assert_eq!(uri, "/notify/397-subs-change");
        let posted: Value = serde_json::from_str(&posted).expect("notification JSON");
        let report = &posted["reportList"][0];
        assert_eq!(
            report["type"].as_str(),
            Some("SUBSCRIPTION_ID_CHANGE"),
            "a UE-specific subscription (no `groupId`) reports CHANGE, not ADDITION \
             (Table 6.2.6.2.5-1)"
        );
        assert_eq!(
            report["supi"].as_str(),
            Some(supi),
            "for the UE whose context was transferred -- this SUPI exists nowhere else"
        );
        let subscription_id = report["subscriptionId"]
            .as_str()
            .expect("`subscriptionId` is what this notification exists to carry");
        assert!(
            subscription_id.starts_with("/namf-evts/v1/subscriptions/sub-"),
            "§6.2.6.2.5 requires the URI of the created subscription RESOURCE per \
             §6.2.3.3.2, not the bare id -- got {subscription_id}"
        );
        assert_eq!(
            report["state"]["active"].as_bool(),
            Some(true),
            "Table 6.2.6.2.5-1: `state` \"shall be set to 'TRUE' when subscriptionId IE \
             is present\""
        );
        assert_eq!(
            posted["subsChangeNotifyCorrelationId"].as_str(),
            Some("corr-397-subs-change"),
            "the subscription carried a `subsChangeNotifyCorrelationId`, so Table \
             6.2.6.2.4-1 requires THAT member"
        );
        assert!(
            posted["notifyCorrelationId"].is_null(),
            "and NOT `notifyCorrelationId`: Table 6.2.6.2.4-1 makes the two mutually \
             exclusive for a subscription-ID notification, so sending both would be wrong"
        );

        // The subscription really EXISTS under the id the consumer was just told. A
        // notification naming an id the AMF did not store would be a promise it cannot
        // keep -- the consumer's next act is to PATCH or DELETE that resource
        // (§6.2.3.3.3 defines those two methods on it and no GET, which is why this
        // reads the store rather than issuing one).
        let stored_id = subscription_id
            .rsplit('/')
            .next()
            .expect("the URI ends in the id");
        let stored = {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard
                .event_subscription_find(stored_id)
                .expect("the id the consumer was told must resolve to a stored subscription")
        };
        assert_eq!(
            stored.event_types,
            vec!["LOCATION_REPORT".to_string()],
            "and it carries the events the SOURCE subscription was for -- the takeover \
             recreates the subscription, it does not invent a new one"
        );
        assert_eq!(
            stored.supi.as_deref(),
            Some(supi),
            "keyed to the transferred UE, so the existing fire points reach it"
        );
        assert!(
            stored
                .subs_change_notify_uri
                .as_deref()
                .is_some_and(|u| u.contains("/notify/397-subs-change")),
            "and it retains the change endpoint, so a LATER id change reaches the same \
             consumer"
        );

        // It is also reachable the way a consumer would next use it: the DELETE
        // §6.2.3.3.3 defines resolves this id.
        let resp = namf_request_handler(SbiRequest::delete(format!(
            "/namf-evts/v1/subscriptions/{stored_id}"
        )))
        .await;
        assert_eq!(
            resp.status, 204,
            "the id the consumer was told must resolve to a DELETABLE resource"
        );

        // Nothing went to the EVENT endpoint: §6.2.5.2.1 routes a subscription-ID
        // notification to `subsChangeNotifyUri` when one was provided, and posting it to
        // `eventNotifyUri` as well would send a report for a type the consumer never
        // subscribed to down the channel it uses for the ones it did.
        assert!(
            tokio::time::timeout(Duration::from_millis(600), event_rx.recv())
                .await
                .is_err(),
            "the SUBSCRIPTION_ID_CHANGE must NOT also go to `eventNotifyUri` \
             (TS 29.518 §6.2.5.2.1)"
        );

        // The DELETE above already removed it from the process-global store.
        change_sink.stop().await.expect("change sink stop");
        event_sink.stop().await.expect("event sink stop");
    }

    /// **#397 criterion 2, the other type.** A transferred GROUP subscription reports
    /// `SUBSCRIPTION_ID_ADDITION`, not `SUBSCRIPTION_ID_CHANGE`.
    ///
    /// The discriminating sibling: Table 6.2.6.2.5-1 ties the two types to
    /// §5.2.2.2.3.1's two cases — a) UE-specific reports CHANGE, b) group reports
    /// ADDITION. Without this test the emitter could report CHANGE unconditionally and
    /// its sibling would still pass.
    ///
    /// The correlation-ID assertion is the OTHER branch too: this subscription carries
    /// NO `subsChangeNotifyCorrelationId`, so Table 6.2.6.2.4-1 requires
    /// `notifyCorrelationId` instead — the exact inverse of the sibling.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transferred_group_subscription_reports_subscription_id_addition() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        // Distinct from the CHANGE sibling, for the process-global reason.
        let supi = "imsi-001010000397700";
        let pei = "imeisv-0000000000397700";
        let (change_sink, change_port, mut change_rx) = start_capture_server().await;

        let mut body = create_ue_context_body(supi, pei);
        body["ueContext"]["eventSubscriptionList"] = json!([{
            "eventList": [{ "type": "LOCATION_REPORT" }],
            "eventNotifyUri": "http://127.0.0.1:9/notify/397-grp-evt",
            "notifyCorrelationId": "corr-397-group",
            "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            // `groupId` is what makes this §5.2.2.2.3.1 case b).
            "groupId": "group-397-700",
            "subsChangeNotifyUri": format!("http://127.0.0.1:{change_port}/notify/397-grp-change"),
            // NO `subsChangeNotifyCorrelationId`: the other branch of Table 6.2.6.2.4-1.
        }]);

        let resp = namf_request_handler(
            SbiRequest::put(format!("/namf-comm/v1/ue-contexts/{supi}"))
                .with_json_body(&body)
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201);

        let (_, posted) = tokio::time::timeout(Duration::from_secs(3), change_rx.recv())
            .await
            .expect("a transferred group subscription must fire SUBSCRIPTION_ID_ADDITION")
            .expect("channel closed");
        let posted: Value = serde_json::from_str(&posted).expect("notification JSON");
        assert_eq!(
            posted["reportList"][0]["type"].as_str(),
            Some("SUBSCRIPTION_ID_ADDITION"),
            "§5.2.2.2.3.1 case b) -- a group-Id subscription. Reporting CHANGE here \
             would tell the consumer the wrong thing about what the AMF did"
        );
        assert_eq!(
            posted["notifyCorrelationId"].as_str(),
            Some("corr-397-group"),
            "with NO `subsChangeNotifyCorrelationId` on the subscription, Table \
             6.2.6.2.4-1 requires `notifyCorrelationId` -- the inverse of the sibling"
        );
        assert!(
            posted["subsChangeNotifyCorrelationId"].is_null(),
            "and not the member the subscription did not carry"
        );

        let stored_id = posted["reportList"][0]["subscriptionId"]
            .as_str()
            .and_then(|u| u.rsplit('/').next().map(String::from))
            .expect("subscriptionId");
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("ctx lock");
            guard.event_subscription_remove(&stored_id);
        }
        change_sink.stop().await.expect("change sink stop");
    }

    /// **#397.** A subscription created over the SBI round-trips its
    /// `subsChangeNotifyUri` / `subsChangeNotifyCorrelationId`, and an unusable one is
    /// REFUSED rather than stored.
    ///
    /// The echo matters for the reason the GPSI echo does (#74 criterion 4): it is how a
    /// consumer confirms the created resource matches the request it made. The refusal
    /// matters more — a stored-but-undeliverable change endpoint produces a subscription
    /// whose SUBSCRIPTION_ID_CHANGE can never arrive, and the consumer would have no way
    /// to learn that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_subscription_round_trips_its_subs_change_callback_and_refuses_a_bad_uri() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        amf_context_init(64, 1024, 4096);
        let supi = "imsi-001010000397800";

        let mut body = subscription_body(
            supi,
            "http://127.0.0.1:9/notify/397-echo",
            "LOCATION_REPORT",
        );
        body["subscription"]["subsChangeNotifyUri"] =
            json!("http://127.0.0.1:9/notify/397-echo-change");
        body["subscription"]["subsChangeNotifyCorrelationId"] = json!("corr-397-echo-change");

        let resp = namf_request_handler(
            SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&body)
                .expect("json"),
        )
        .await;
        assert_eq!(resp.status, 201);
        let created = body_json(&resp);
        assert_eq!(
            created["subscription"]["subsChangeNotifyUri"].as_str(),
            Some("http://127.0.0.1:9/notify/397-echo-change"),
            "the echo returns the change endpoint the consumer sent \
             (TS29518_Namf_EventExposure.yaml:549)"
        );
        assert_eq!(
            created["subscription"]["subsChangeNotifyCorrelationId"].as_str(),
            Some("corr-397-echo-change"),
            "and its correlation id (yaml:551)"
        );
        let sub_id = created["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // An unusable change URI is refused, not silently stored.
        let mut bad = subscription_body(
            "imsi-001010000397801",
            "http://127.0.0.1:9/notify/397-echo2",
            "LOCATION_REPORT",
        );
        bad["subscription"]["subsChangeNotifyUri"] = json!("not-a-uri");
        let resp = namf_request_handler(
            SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&bad)
                .expect("json"),
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "a present-but-unusable `subsChangeNotifyUri` must be refused: storing it \
             would create a subscription whose SUBSCRIPTION_ID_CHANGE can never be \
             delivered, and the consumer could not learn that"
        );

        let _ = namf_request_handler(SbiRequest::delete(format!(
            "/namf-evts/v1/subscriptions/{sub_id}"
        )))
        .await;
    }
}
