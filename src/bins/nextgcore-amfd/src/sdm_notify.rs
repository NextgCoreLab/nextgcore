//! Nudm_SDM Data Change Notification at the AMF (#1748, TS 29.503 §5.2.2.5.2).
//!
//! The AMF subscribes to the UE's `am-data` at registration (and again at a takeover
//! or restore) with `callbackReference` `.../{supi}/sdmsubscription-notify/{token}`
//! (`sbi_path::sdm_callback_reference`). The UDM POSTs a `ModificationNotification`
//! (TS 29.503 §6.1.6.2.21) there when the data changes: `notifyItems`, each a
//! `NotifyItem` (TS 29.571) naming the changed resource and its `ChangeItem`s.
//!
//! The AMF keeps the UE's whole am-data (`AmfUe::am_data`) and applies the changes to
//! it. It acts on the members `sbi_path::AM_DATA_APPLIED_MEMBERS`: from them the UE's
//! subscribed UE-AMBR, GPSI and priority subscription are derived again exactly as
//! registration derives them (`sbi_path::parse_am_data`).
//!
//! What is refused, with nothing applied (TS 29.503 §5.2.2.5.2 step 2b; the
//! notification is all or nothing, so a refusal never leaves half of it applied).
//! The answer is 400 with a ProblemDetails naming the change (operator decision
//! 2026-11-18, DECISIONS 2026-11-18-030000: in the callback's listed statuses, and
//! not a 5xx that invites a retry), because answering 204 would tell the UDM a
//! change was applied that was not:
//! - a change of a member this AMF does not act on, however it is encoded (a
//!   member path, or a whole-resource replacement whose other members differ from
//!   the ones held);
//! - a removal of the subscribed UE-AMBR (the AMF has no other UE-AMBR to fall back
//!   to);
//! - a change of the subscribed UE-AMBR for a CM-CONNECTED UE: NG-RAN enforces the
//!   UE-AMBR it was given, and moving it needs a UE Context Modification
//!   (TS 23.502 §4.5.1, TS 38.413 §8.3.4), which this AMF does not send. For a
//!   CM-IDLE UE the change is applied and reaches NG-RAN in the next Initial
//!   Context Setup;
//! - a change of the subscribed S-NSSAIs (the Allowed NSSAI is decided at
//!   registration and a change needs a UE Configuration Update, which this handler
//!   does not drive).
//!
//! The cause is `UNSPECIFIED_MSG_FAILURE`: TS 29.500 Table 5.2.7.2-1 pairs
//! `MODIFICATION_NOT_ALLOWED` with 403, so it is not sent with a 400.
//!
//! Also refused: a malformed notification, 400 `INVALID_MSG_FORMAT`; a resource or a
//! subscription this AMF does not hold for the UE, 404 `CONTEXT_NOT_FOUND`
//! (Table 6.1.5.2-3).
//!
//! Retries are idempotent: `ADD`/`REPLACE` set a member to the new value, and a
//! `REMOVE` of a member already absent changes nothing. `MOVE`, and a path into an
//! array, are refused: §5.2.2.5.2 has the UDM replace arrays whole.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::context::AmfUe;
use crate::sbi_path::AM_DATA_APPLIED_MEMBERS;

/// Why a notification was not applied, and the status it is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotApplied {
    /// 400 INVALID_MSG_FORMAT: not a well-formed `ModificationNotification`.
    Malformed(String),
    /// 404 CONTEXT_NOT_FOUND: names a resource or a subscription this AMF does not
    /// hold for the UE.
    NotSubscribed(String),
    /// 400 UNSPECIFIED_MSG_FAILURE: a well-formed change this AMF does not apply.
    NotAllowed(String),
}

impl NotApplied {
    /// The HTTP status this refusal is answered with.
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Malformed(_) | Self::NotAllowed(_) => 400,
            Self::NotSubscribed(_) => 404,
        }
    }

    /// The ProblemDetails `cause` (TS 29.500 Table 5.2.7.2-1).
    pub(crate) fn cause(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "INVALID_MSG_FORMAT",
            Self::NotSubscribed(_) => "CONTEXT_NOT_FOUND",
            Self::NotAllowed(_) => "UNSPECIFIED_MSG_FAILURE",
        }
    }

    /// The human-readable reason.
    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::Malformed(d) | Self::NotSubscribed(d) | Self::NotAllowed(d) => d,
        }
    }
}

/// The am-data a notification is applied to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HeldAmData {
    /// The am-data as this AMF holds it.
    pub(crate) doc: Value,
    /// Whether `doc` is the whole am-data the UDM gave. `false` for one rebuilt from
    /// the UE's fields ([`current_am_data`]): its other members are not known.
    pub(crate) complete: bool,
    /// A rebuilt `doc` whose `mpsPriority: true` stands for a priority subscription
    /// that may as well have been MCX ([`current_am_data`]).
    pub(crate) priority_assumed: bool,
}

/// The am-data this AMF holds for `ue`: [`AmfUe::am_data`], or, for a context whose
/// am-data was never read here (one restored from a record written before #1748),
/// rebuilt from the fields registration derived from it. A rebuilt one carries no
/// `nssai`, so a change of the subscribed S-NSSAIs is refused for it, and none of the
/// members this AMF does not act on, so any change naming one is refused.
///
/// Such a record keeps only that the UE had an MPS or an MCX priority subscription,
/// not which: the rebuilt am-data says `mpsPriority: true`. A member-path change of
/// just one of the two would then be decided on a guess (`REPLACE /mcsPriority
/// false` for an MCX-only UE would leave the priority in place), so it is refused;
/// a whole-resource replacement, or a change naming both, says what both are.
pub(crate) fn current_am_data(ue: &AmfUe) -> HeldAmData {
    if let Some(doc) = ue.am_data.as_ref().filter(|v| v.is_object()) {
        return HeldAmData {
            doc: doc.clone(),
            complete: true,
            priority_assumed: false,
        };
    }
    let mut doc = serde_json::Map::new();
    if ue.ue_ambr.uplink != 0 || ue.ue_ambr.downlink != 0 {
        doc.insert(
            "subscribedUeAmbr".to_string(),
            serde_json::json!({
                "uplink": format!("{} bps", ue.ue_ambr.uplink),
                "downlink": format!("{} bps", ue.ue_ambr.downlink),
            }),
        );
    }
    if let Some(gpsi) = &ue.gpsi {
        doc.insert("gpsis".to_string(), serde_json::json!([gpsi]));
    }
    if ue.priority_subscription {
        doc.insert("mpsPriority".to_string(), Value::Bool(true));
    }
    HeldAmData {
        doc: Value::Object(doc),
        complete: false,
        priority_assumed: ue.priority_subscription,
    }
}

/// The members a notification's changes name, and whether one replaced the whole
/// resource.
#[derive(Default)]
struct Touched {
    members: BTreeSet<String>,
    whole: bool,
}

/// The UE's am-data once `notification` (a `ModificationNotification`) is applied to
/// `current`, or why it is not applied. Pure: nothing is changed here.
///
/// `held_subscription` is the id of the UE's SDM subscription: a notification
/// naming another `subscriptionId` is for a subscription this AMF does not hold.
/// `cm_connected`: the UE has an NG connection now, so NG-RAN holds its UE-AMBR.
pub(crate) fn applied_am_data(
    supi: &str,
    current: &HeldAmData,
    held_subscription: Option<&str>,
    notification: &Value,
    cm_connected: bool,
) -> Result<Value, NotApplied> {
    let items = notification
        .get("notifyItems")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| {
            NotApplied::Malformed("ModificationNotification needs notifyItems".to_string())
        })?;
    if let (Some(named), Some(held)) = (
        notification.get("subscriptionId").and_then(Value::as_str),
        held_subscription,
    ) {
        if named != held {
            return Err(NotApplied::NotSubscribed(format!(
                "subscription {named} is not this UE's"
            )));
        }
    }
    let mut doc = current.doc.clone();
    let mut touched = Touched::default();
    for item in items {
        let resource = item
            .get("resourceId")
            .and_then(Value::as_str)
            .ok_or_else(|| NotApplied::Malformed("NotifyItem needs resourceId".to_string()))?;
        if !names_am_data_of(resource, supi) {
            return Err(NotApplied::NotSubscribed(format!(
                "{resource} is not a resource this AMF monitors for {supi}"
            )));
        }
        let changes = item
            .get("changes")
            .and_then(Value::as_array)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| NotApplied::Malformed("NotifyItem needs changes".to_string()))?;
        for change in changes {
            apply_change(&mut doc, change, &mut touched)?;
        }
    }
    check_applicable(current, &doc, &touched, cm_connected)?;
    Ok(doc)
}

/// Whether `resource` (a `resourceId`, absolute or a path) is `{supi}`'s
/// `/nudm-sdm/v2/{supi}/am-data`, the one resource this AMF subscribes to.
fn names_am_data_of(resource: &str, supi: &str) -> bool {
    let path = resource.split(['?', '#']).next().unwrap_or_default();
    let path = path.trim_end_matches('/');
    path.ends_with(&format!("/nudm-sdm/v2/{supi}/am-data"))
}

/// Apply one `ChangeItem` (TS 29.571) to `doc`, noting what it names in `touched`.
fn apply_change(doc: &mut Value, change: &Value, touched: &mut Touched) -> Result<(), NotApplied> {
    let op = change
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| NotApplied::Malformed("ChangeItem needs op".to_string()))?;
    let path = change
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| NotApplied::Malformed("ChangeItem needs path".to_string()))?;
    let new_value = change.get("newValue");
    // The whole resource ("path": "", TS 29.503 §6.1.6.2.21 example): the new
    // am-data as a whole, whose members `check_applicable` compares with the held.
    if path.is_empty() || path == "/" {
        return match (op, new_value) {
            ("ADD" | "REPLACE", Some(Value::Object(members))) => {
                touched.whole = true;
                touched.members.extend(members.keys().cloned());
                *doc = Value::Object(members.clone());
                Ok(())
            }
            ("ADD" | "REPLACE", _) => Err(NotApplied::Malformed(
                "a whole-resource change needs an object newValue".to_string(),
            )),
            _ => Err(NotApplied::NotAllowed(format!("{op} of the whole am-data"))),
        };
    }
    let tokens: Vec<&str> = path
        .strip_prefix('/')
        .ok_or_else(|| NotApplied::Malformed(format!("path {path} is not a JSON pointer")))?
        .split('/')
        .collect();
    if tokens
        .iter()
        .any(|t| *t == "-" || t.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(NotApplied::Malformed(format!(
            "{op} {path}: arrays are replaced whole (TS 29.503 §5.2.2.5.2)"
        )));
    }
    touched
        .members
        .insert(tokens[0].replace("~1", "/").replace("~0", "~"));
    let patch = match op {
        "ADD" | "REPLACE" => {
            let value = new_value
                .ok_or_else(|| NotApplied::Malformed(format!("{op} {path} needs newValue")))?;
            serde_json::json!([{ "op": "add", "path": path, "value": value }])
        }
        "REMOVE" => {
            if doc.pointer(path).is_none() {
                // Already absent: a retried REMOVE changes nothing.
                return Ok(());
            }
            serde_json::json!([{ "op": "remove", "path": path }])
        }
        other => {
            return Err(NotApplied::NotAllowed(format!(
                "{other} {path}: only ADD, REPLACE and REMOVE are applied"
            )))
        }
    };
    nextgcore_sbi::json_patch::apply_patch(doc, &patch)
        .map_err(|e| NotApplied::Malformed(format!("{op} {path}: {e}")))
}

/// The subscribed UE-AMBR of an am-data, in bps (uplink, downlink), if it has one
/// that parses.
fn ue_ambr_bps(doc: &Value) -> Option<(u64, u64)> {
    let ambr = doc.get("subscribedUeAmbr")?;
    let bps = |dir: &str| {
        ambr.get(dir)
            .and_then(Value::as_str)
            .and_then(crate::ngap_path::parse_bitrate_bps)
    };
    Some((bps("uplink")?, bps("downlink")?))
}

/// Refuse a result this AMF cannot apply (see the module docs).
fn check_applicable(
    current: &HeldAmData,
    after: &Value,
    touched: &Touched,
    cm_connected: bool,
) -> Result<(), NotApplied> {
    let before = &current.doc;
    let not_acted_on = |m: &str| !AM_DATA_APPLIED_MEMBERS.contains(&m);
    if current.complete {
        let members = |doc: &Value| -> BTreeSet<String> {
            doc.as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default()
        };
        let mut all = members(before);
        all.extend(members(after));
        if let Some(m) = all
            .iter()
            .find(|m| not_acted_on(m) && before.get(m.as_str()) != after.get(m.as_str()))
        {
            return Err(NotApplied::NotAllowed(format!(
                "a change of am-data member {m}: this AMF does not act on it"
            )));
        }
    } else if let Some(m) = touched.members.iter().find(|m| not_acted_on(m)) {
        return Err(NotApplied::NotAllowed(format!(
            "a change naming am-data member {m}: this context was restored without its \
             am-data, so whether {m} changed is not known"
        )));
    }
    if current.priority_assumed && !touched.whole {
        let named = ["mpsPriority", "mcsPriority"].map(|m| touched.members.contains(m));
        if named[0] != named[1] {
            return Err(NotApplied::NotAllowed(
                "a change of one of mpsPriority and mcsPriority: this context was restored \
                 without its am-data, and which of the two its priority subscription is \
                 was not recorded"
                    .to_string(),
            ));
        }
    }
    match after.get("subscribedUeAmbr") {
        Some(_) if ue_ambr_bps(after).is_none() => {
            return Err(NotApplied::Malformed(
                "subscribedUeAmbr is not an uplink and a downlink BitRate".to_string(),
            ));
        }
        Some(_) => {}
        None if before.get("subscribedUeAmbr").is_some() => {
            return Err(NotApplied::NotAllowed(
                "removal of subscribedUeAmbr: the AMF has no other UE-AMBR to apply".to_string(),
            ));
        }
        None => {}
    }
    if cm_connected && ue_ambr_bps(before) != ue_ambr_bps(after) {
        return Err(NotApplied::NotAllowed(
            "a change of subscribedUeAmbr for a CM-CONNECTED UE: NG-RAN holds the UE-AMBR, \
             and this AMF does not send the UE Context Modification that would change it \
             (TS 23.502 §4.5.1, TS 38.413 §8.3.4)"
                .to_string(),
        ));
    }
    // The whole `nssai` member, not only the defaults `parse_am_data` reads: its
    // `singleNssais` (the non-default subscribed S-NSSAIs, TS 29.503 §6.1.6.2.2) is
    // acted on by nothing here, so a change of it must be refused too (R13 M1).
    if before.get("nssai") != after.get("nssai") {
        return Err(NotApplied::NotAllowed(
            "a change of the subscribed S-NSSAIs: the Allowed NSSAI is decided at \
             registration, and changing it needs a UE Configuration Update"
                .to_string(),
        ));
    }
    Ok(())
}

/// Set the fields of `ue` derived from its am-data `doc`, as registration does, and
/// keep `doc`.
pub(crate) fn adopt_am_data(supi: &str, ue: &mut AmfUe, doc: Value) {
    let derived = crate::sbi_path::parse_am_data(&doc, supi);
    if let Some(ul) = derived
        .ue_ambr_uplink
        .as_deref()
        .and_then(crate::ngap_path::parse_bitrate_bps)
    {
        ue.ue_ambr.uplink = ul;
    }
    if let Some(dl) = derived
        .ue_ambr_downlink
        .as_deref()
        .and_then(crate::ngap_path::parse_bitrate_bps)
    {
        ue.ue_ambr.downlink = dl;
    }
    ue.gpsi = derived.gpsi;
    ue.priority_subscription = derived.priority_subscription;
    ue.am_data = Some(doc);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SUPI: &str = "imsi-001010000017490";

    fn notification(changes: Value) -> Value {
        json!({
            "subscriptionId": "sub-1",
            "notifyItems": [{
                "resourceId": format!("/nudm-sdm/v2/{SUPI}/am-data"),
                "changes": changes,
            }],
        })
    }

    /// The whole am-data `doc`, as Nudm_SDM_Get gave it.
    fn held(doc: Value) -> HeldAmData {
        HeldAmData {
            doc,
            complete: true,
            priority_assumed: false,
        }
    }

    /// #1748 (R11 MAJOR-1): a whole-resource replacement (`"path": ""`) is applied
    /// when the members this AMF does not act on are as held, and the whole new
    /// am-data is kept. When one of them differs, or is dropped, the notification is
    /// refused, as the same change sent on the member's own path is: the outcome
    /// does not depend on how the UDM encodes the change.
    ///
    /// REVERT-VERIFIED: with the comparison of the other members in
    /// `check_applicable` skipped, the changed and dropped `rfspIndex` cases are Ok.
    #[test]
    fn a_whole_resource_replacement_refuses_a_change_of_an_unapplied_member_1748() {
        let current = held(json!({"gpsis": ["msisdn-111111"], "rfspIndex": 7}));
        let replace = |doc: Value| {
            applied_am_data(
                SUPI,
                &current,
                Some("sub-1"),
                &notification(json!([{"op": "REPLACE", "path": "", "newValue": doc}])),
                false,
            )
        };
        let same = json!({"gpsis": ["msisdn-222222"], "mpsPriority": true, "rfspIndex": 7});
        assert_eq!(
            replace(same.clone()),
            Ok(same),
            "the whole new am-data is kept"
        );
        for (doc, why) in [
            (
                json!({"gpsis": ["msisdn-222222"], "rfspIndex": 8}),
                "changed",
            ),
            (json!({"gpsis": ["msisdn-222222"]}), "dropped"),
            (
                json!({"gpsis": ["msisdn-222222"], "rfspIndex": 7, "odbPacketServices": "ALL"}),
                "added",
            ),
        ] {
            assert!(
                matches!(replace(doc), Err(NotApplied::NotAllowed(ref d)) if d.contains("am-data member")),
                "{why}"
            );
        }
        // The same change on the member's path: refused, and a REPLACE that leaves
        // it as held (a retry) is not a change.
        let member = |v: Value| {
            applied_am_data(
                SUPI,
                &current,
                None,
                &notification(json!([{"op": "REPLACE", "path": "/rfspIndex", "newValue": v}])),
                false,
            )
        };
        assert!(matches!(member(json!(8)), Err(NotApplied::NotAllowed(_))));
        assert_eq!(
            member(json!(7)),
            Ok(json!({"gpsis": ["msisdn-111111"], "rfspIndex": 7}))
        );
    }

    /// #1748: a context restored without its am-data does not know the members this
    /// AMF does not act on, so any change naming one is refused; a whole-resource
    /// replacement with only the acted-on members is applied.
    ///
    /// REVERT-VERIFIED: with the `touched.members` check for a rebuilt am-data
    /// skipped, the `rfspIndex` replacement and removal are Ok.
    #[test]
    fn a_rebuilt_am_data_refuses_a_change_naming_an_unknown_member_1748() {
        let mut ue = AmfUe::new(1, 1);
        ue.gpsi = Some("msisdn-333333".to_string());
        let current = current_am_data(&ue);
        assert!(!current.complete);
        let apply =
            |changes: Value| applied_am_data(SUPI, &current, None, &notification(changes), false);
        for changes in [
            json!([{"op": "REPLACE", "path": "", "newValue": {"gpsis": ["msisdn-1"], "rfspIndex": 7}}]),
            json!([{"op": "REMOVE", "path": "/rfspIndex"}]),
        ] {
            assert!(
                matches!(apply(changes.clone()), Err(NotApplied::NotAllowed(ref d)) if d.contains("rfspIndex")),
                "{changes}"
            );
        }
        assert_eq!(
            apply(json!([{"op": "REPLACE", "path": "", "newValue": {"gpsis": ["msisdn-1"]}}])),
            Ok(json!({"gpsis": ["msisdn-1"]}))
        );
    }

    /// #1748 (R11 MAJOR-2): a change of the UE-AMBR is refused for a CM-CONNECTED UE,
    /// whose UE-AMBR NG-RAN holds and this AMF does not modify, and applied for a
    /// CM-IDLE one. A change that leaves the UE-AMBR as it was (another encoding of
    /// the same rate) is applied either way.
    ///
    /// REVERT-VERIFIED: with the `cm_connected` check in `check_applicable` skipped,
    /// the connected case is Ok.
    #[test]
    fn a_ue_ambr_change_is_refused_for_a_cm_connected_ue_1748() {
        let current = held(json!({"subscribedUeAmbr": {"uplink": "1 Mbps", "downlink": "2 Mbps"}}));
        let change = |ul: &str, connected: bool| {
            applied_am_data(
                SUPI,
                &current,
                None,
                &notification(json!([{"op": "REPLACE", "path": "/subscribedUeAmbr",
                    "newValue": {"uplink": ul, "downlink": "2 Mbps"}}])),
                connected,
            )
        };
        assert!(matches!(
            change("5 Mbps", true),
            Err(NotApplied::NotAllowed(ref d)) if d.contains("CM-CONNECTED")
        ));
        assert!(change("5 Mbps", false).is_ok(), "CM-IDLE: applied");
        assert!(change("1000 Kbps", true).is_ok(), "the same rate: applied");
    }

    /// #1748 (R13 M1): a change of `nssai.singleNssais`, the non-default subscribed
    /// S-NSSAIs, is refused like a change of the defaults: nothing here acts on it,
    /// so a 204 would tell the UDM an ignored change was applied. `nssai` as held
    /// is not a change.
    ///
    /// REVERT-VERIFIED: with the whole-member comparison replaced by one of the
    /// parsed defaults only, the `singleNssais` case is Ok.
    #[test]
    fn a_change_of_the_non_default_s_nssais_is_refused_1748() {
        let current = held(json!({"nssai": {"defaultSingleNssais": [{"sst": 1}]}}));
        let replace = |nssai: Value| {
            applied_am_data(
                SUPI,
                &current,
                None,
                &notification(json!([{"op": "REPLACE", "path": "/nssai", "newValue": nssai}])),
                false,
            )
        };
        assert!(matches!(
            replace(json!({"defaultSingleNssais": [{"sst": 1}],
                           "singleNssais": [{"sst": 2, "sd": "000002"}]})),
            Err(NotApplied::NotAllowed(ref d)) if d.contains("S-NSSAIs")
        ));
        assert!(replace(json!({"defaultSingleNssais": [{"sst": 1}]})).is_ok());
    }

    /// #1748: `subscriptionId` names the subscription; one this UE does not hold is
    /// 404, and a notification without it (an older UDM) is matched on the token.
    ///
    /// REVERT-VERIFIED: with the subscriptionId comparison dropped, the first is Ok.
    #[test]
    fn another_subscription_s_notification_is_not_applied_1748() {
        let body = notification(json!([{"op": "ADD", "path": "/mpsPriority", "newValue": true}]));
        let empty = held(json!({}));
        assert!(matches!(
            applied_am_data(SUPI, &empty, Some("sub-2"), &body, false),
            Err(NotApplied::NotSubscribed(_))
        ));
        let mut unnamed = body.clone();
        unnamed
            .as_object_mut()
            .expect("object")
            .remove("subscriptionId");
        assert_eq!(
            applied_am_data(SUPI, &empty, Some("sub-2"), &unnamed, false),
            Ok(json!({"mpsPriority": true}))
        );
        // Another UE's am-data.
        let mut other = body;
        other["notifyItems"][0]["resourceId"] = json!("/nudm-sdm/v2/imsi-999/am-data");
        assert!(matches!(
            applied_am_data(SUPI, &empty, Some("sub-1"), &other, false),
            Err(NotApplied::NotSubscribed(_))
        ));
    }

    /// #1748: a path into an array is refused: the UDM replaces arrays whole
    /// (TS 29.503 §5.2.2.5.2), and an append would not be idempotent.
    #[test]
    fn a_path_into_an_array_is_refused_1748() {
        for path in ["/gpsis/-", "/gpsis/0"] {
            let body = notification(json!([{"op": "ADD", "path": path, "newValue": "msisdn-1"}]));
            assert!(
                matches!(
                    applied_am_data(SUPI, &held(json!({"gpsis": []})), None, &body, false),
                    Err(NotApplied::Malformed(_))
                ),
                "{path}"
            );
        }
    }

    /// #1748: a context whose am-data was never read here has it rebuilt from the
    /// fields registration derived, so a change applies to what the UE holds.
    #[test]
    fn a_context_without_kept_am_data_has_it_rebuilt_from_its_fields_1748() {
        let mut ue = AmfUe::new(1, 1);
        ue.ue_ambr.uplink = 1_000;
        ue.ue_ambr.downlink = 2_000;
        ue.gpsi = Some("msisdn-333333".to_string());
        ue.priority_subscription = true;
        let rebuilt = current_am_data(&ue);
        assert_eq!(
            rebuilt.doc,
            json!({
                "subscribedUeAmbr": {"uplink": "1000 bps", "downlink": "2000 bps"},
                "gpsis": ["msisdn-333333"],
                "mpsPriority": true,
            })
        );
        let withdrawn = applied_am_data(
            SUPI,
            &rebuilt,
            None,
            &notification(json!([
                {"op": "REPLACE", "path": "/mpsPriority", "newValue": false},
                {"op": "REPLACE", "path": "/mcsPriority", "newValue": false},
            ])),
            false,
        )
        .expect("applied");
        adopt_am_data(SUPI, &mut ue, withdrawn);
        assert!(
            !ue.priority_subscription,
            "the priority subscription is withdrawn"
        );
        assert_eq!((ue.ue_ambr.uplink, ue.ue_ambr.downlink), (1_000, 2_000));
        assert_eq!(ue.gpsi.as_deref(), Some("msisdn-333333"));
    }

    /// #1748 (R11 MINOR-2): a rebuilt am-data does not record whether the priority
    /// subscription was MPS or MCX, so a member-path change of just one of the two
    /// is refused rather than decided on the `mpsPriority` guess: `REPLACE
    /// /mcsPriority false` for what was an MCX-only UE would otherwise leave the
    /// priority subscription in place. A whole-resource replacement says both.
    ///
    /// REVERT-VERIFIED: with the `priority_assumed` check skipped, the
    /// `/mcsPriority` case is Ok.
    #[test]
    fn a_rebuilt_priority_is_not_changed_on_a_guess_1748() {
        let mut ue = AmfUe::new(1, 1);
        ue.priority_subscription = true;
        let rebuilt = current_am_data(&ue);
        assert!(rebuilt.priority_assumed);
        let apply =
            |changes: Value| applied_am_data(SUPI, &rebuilt, None, &notification(changes), false);
        assert!(matches!(
            apply(json!([{"op": "REPLACE", "path": "/mcsPriority", "newValue": false}])),
            Err(NotApplied::NotAllowed(ref d)) if d.contains("mcsPriority")
        ));
        assert_eq!(
            apply(json!([{"op": "REPLACE", "path": "", "newValue": {"mcsPriority": false}}])),
            Ok(json!({"mcsPriority": false}))
        );
    }
}
