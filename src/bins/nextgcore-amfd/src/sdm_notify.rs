//! Nudm_SDM Data Change Notification at the AMF (#1748, TS 29.503 §5.2.2.5.2).
//!
//! The AMF subscribes to the UE's `am-data` at registration (and again at a takeover
//! or restore) with `callbackReference` `.../{supi}/sdmsubscription-notify/{token}`
//! (`sbi_path::sdm_callback_reference`). The UDM POSTs a `ModificationNotification`
//! (TS 29.503 §6.1.6.2.21) there when the data changes: `notifyItems`, each a
//! `NotifyItem` (TS 29.571) naming the changed resource and its `ChangeItem`s.
//!
//! What is applied: the changes, to the am-data members this AMF keeps
//! (`sbi_path::AM_DATA_KEPT_MEMBERS`, `AmfUe::am_data`), and from them the UE's
//! subscribed UE-AMBR, GPSI and priority subscription are derived again exactly as
//! registration derives them (`sbi_path::parse_am_data`). Nothing else is.
//!
//! What is refused, with nothing applied (TS 29.503 §5.2.2.5.2 step 2b; the
//! notification is all or nothing, so a refusal never leaves half of it applied):
//! - a change of a member this AMF does not keep (it would act on nothing), a
//!   removal of the subscribed UE-AMBR (the AMF has no other UE-AMBR to fall back
//!   to), and a change of the subscribed S-NSSAIs (the Allowed NSSAI is decided at
//!   registration and a change needs a UE Configuration Update, which this handler
//!   does not drive): 501, naming the change, because answering 204 would tell the
//!   UDM a change was applied that was not;
//! - a malformed notification: 400;
//! - a resource or a subscription this AMF does not hold for the UE: 404
//!   CONTEXT_NOT_FOUND (Table 6.1.5.2-3).
//!
//! Retries are idempotent: `ADD`/`REPLACE` set a member to the new value, and a
//! `REMOVE` of a member already absent changes nothing. `MOVE`, and a path into an
//! array, are refused: §5.2.2.5.2 has the UDM replace arrays whole.

use serde_json::Value;

use crate::context::AmfUe;

/// Why a notification was not applied, and the status it is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotApplied {
    /// 400: not a well-formed `ModificationNotification`.
    Malformed(String),
    /// 404 CONTEXT_NOT_FOUND: names a resource or a subscription this AMF does not
    /// hold for the UE.
    NotSubscribed(String),
    /// 501: a change this AMF does not apply.
    Unsupported(String),
}

impl NotApplied {
    /// The HTTP status this refusal is answered with.
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Malformed(_) => 400,
            Self::NotSubscribed(_) => 404,
            Self::Unsupported(_) => 501,
        }
    }

    /// The human-readable reason.
    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::Malformed(d) | Self::NotSubscribed(d) | Self::Unsupported(d) => d,
        }
    }
}

/// The am-data this AMF keeps for `ue`: [`AmfUe::am_data`], or, for a context whose
/// am-data was never read here (one restored from a record written before #1748),
/// rebuilt from the fields registration derived from it. A rebuilt one carries no
/// `nssai`, so a change of the subscribed S-NSSAIs is refused for it.
pub(crate) fn current_am_data(ue: &AmfUe) -> Value {
    if let Some(kept) = ue.am_data.as_ref().filter(|v| v.is_object()) {
        return kept.clone();
    }
    let mut kept = serde_json::Map::new();
    if ue.ue_ambr.uplink != 0 || ue.ue_ambr.downlink != 0 {
        kept.insert(
            "subscribedUeAmbr".to_string(),
            serde_json::json!({
                "uplink": format!("{} bps", ue.ue_ambr.uplink),
                "downlink": format!("{} bps", ue.ue_ambr.downlink),
            }),
        );
    }
    if let Some(gpsi) = &ue.gpsi {
        kept.insert("gpsis".to_string(), serde_json::json!([gpsi]));
    }
    if ue.priority_subscription {
        // Which of the two it was is not recorded: MPS is assumed.
        kept.insert("mpsPriority".to_string(), Value::Bool(true));
    }
    Value::Object(kept)
}

/// The UE's kept am-data once `notification` (a `ModificationNotification`) is
/// applied to `current`, or why it is not applied. Pure: nothing is changed here.
///
/// `held_subscription` is the id of the UE's SDM subscription: a notification
/// naming another `subscriptionId` is for a subscription this AMF does not hold.
pub(crate) fn applied_am_data(
    supi: &str,
    current: &Value,
    held_subscription: Option<&str>,
    notification: &Value,
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
    let mut doc = current.clone();
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
            apply_change(&mut doc, change)?;
        }
    }
    check_applicable(supi, current, &doc)?;
    Ok(doc)
}

/// Whether `resource` (a `resourceId`, absolute or a path) is `{supi}`'s
/// `/nudm-sdm/v2/{supi}/am-data`, the one resource this AMF subscribes to.
fn names_am_data_of(resource: &str, supi: &str) -> bool {
    let path = resource.split(['?', '#']).next().unwrap_or_default();
    let path = path.trim_end_matches('/');
    path.ends_with(&format!("/nudm-sdm/v2/{supi}/am-data"))
}

/// Apply one `ChangeItem` (TS 29.571) to `doc`.
fn apply_change(doc: &mut Value, change: &Value) -> Result<(), NotApplied> {
    let op = change
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| NotApplied::Malformed("ChangeItem needs op".to_string()))?;
    let path = change
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| NotApplied::Malformed("ChangeItem needs path".to_string()))?;
    let new_value = change.get("newValue");
    // The whole resource ("path": "", TS 29.503 §6.1.6.2.21 example).
    if path.is_empty() || path == "/" {
        return match (op, new_value) {
            ("ADD" | "REPLACE", Some(v)) if v.is_object() => {
                *doc = crate::sbi_path::kept_am_data(v);
                Ok(())
            }
            ("ADD" | "REPLACE", _) => Err(NotApplied::Malformed(
                "a whole-resource change needs an object newValue".to_string(),
            )),
            _ => Err(NotApplied::Unsupported(format!(
                "{op} of the whole am-data"
            ))),
        };
    }
    let tokens: Vec<&str> = path
        .strip_prefix('/')
        .ok_or_else(|| NotApplied::Malformed(format!("path {path} is not a JSON pointer")))?
        .split('/')
        .collect();
    let member = tokens[0].replace("~1", "/").replace("~0", "~");
    if !crate::sbi_path::AM_DATA_KEPT_MEMBERS.contains(&member.as_str()) {
        return Err(NotApplied::Unsupported(format!(
            "{op} {path}: this AMF does not act on am-data member {member}"
        )));
    }
    if tokens
        .iter()
        .any(|t| *t == "-" || t.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(NotApplied::Malformed(format!(
            "{op} {path}: arrays are replaced whole (TS 29.503 §5.2.2.5.2)"
        )));
    }
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
            return Err(NotApplied::Unsupported(format!(
                "{other} {path}: only ADD, REPLACE and REMOVE are applied"
            )))
        }
    };
    nextgcore_sbi::json_patch::apply_patch(doc, &patch)
        .map_err(|e| NotApplied::Malformed(format!("{op} {path}: {e}")))
}

/// Refuse a result this AMF cannot apply (see the module docs).
fn check_applicable(supi: &str, before: &Value, after: &Value) -> Result<(), NotApplied> {
    match after.get("subscribedUeAmbr") {
        Some(ambr) => {
            for dir in ["uplink", "downlink"] {
                let ok = ambr
                    .get(dir)
                    .and_then(Value::as_str)
                    .and_then(crate::ngap_path::parse_bitrate_bps)
                    .is_some();
                if !ok {
                    return Err(NotApplied::Malformed(format!(
                        "subscribedUeAmbr.{dir} is not a BitRate"
                    )));
                }
            }
        }
        None if before.get("subscribedUeAmbr").is_some() => {
            return Err(NotApplied::Unsupported(
                "removal of subscribedUeAmbr: the AMF has no other UE-AMBR to apply".to_string(),
            ));
        }
        None => {}
    }
    let slices = |doc: &Value| {
        let mut s = crate::sbi_path::parse_am_data(doc, supi).nssai;
        s.sort_unstable();
        s.dedup();
        s
    };
    if slices(before) != slices(after) {
        return Err(NotApplied::Unsupported(
            "a change of the subscribed S-NSSAIs: the Allowed NSSAI is decided at \
             registration, and changing it needs a UE Configuration Update"
                .to_string(),
        ));
    }
    Ok(())
}

/// Set the fields of `ue` derived from its kept am-data `kept`, as registration does,
/// and keep `kept`.
pub(crate) fn adopt_am_data(supi: &str, ue: &mut AmfUe, kept: Value) {
    let derived = crate::sbi_path::parse_am_data(&kept, supi);
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
    ue.am_data = Some(kept);
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

    /// #1748: a whole-resource replacement (`"path": ""`) keeps the kept members of
    /// the new am-data, and only them.
    #[test]
    fn a_whole_resource_replacement_keeps_the_kept_members_1748() {
        let current = json!({"gpsis": ["msisdn-111111"]});
        let out = applied_am_data(
            SUPI,
            &current,
            Some("sub-1"),
            &notification(json!([{"op": "REPLACE", "path": "", "newValue": {
                "gpsis": ["msisdn-222222"],
                "mpsPriority": true,
                "rfspIndex": 7,
            }}])),
        )
        .expect("applied");
        assert_eq!(
            out,
            json!({"gpsis": ["msisdn-222222"], "mpsPriority": true})
        );
    }

    /// #1748: `subscriptionId` names the subscription; one this UE does not hold is
    /// 404, and a notification without it (an older UDM) is matched on the token.
    ///
    /// REVERT-VERIFIED: with the subscriptionId comparison dropped, the first is Ok.
    #[test]
    fn another_subscription_s_notification_is_not_applied_1748() {
        let body = notification(json!([{"op": "ADD", "path": "/mpsPriority", "newValue": true}]));
        assert!(matches!(
            applied_am_data(SUPI, &json!({}), Some("sub-2"), &body),
            Err(NotApplied::NotSubscribed(_))
        ));
        let mut unnamed = body.clone();
        unnamed
            .as_object_mut()
            .expect("object")
            .remove("subscriptionId");
        assert_eq!(
            applied_am_data(SUPI, &json!({}), Some("sub-2"), &unnamed),
            Ok(json!({"mpsPriority": true}))
        );
        // Another UE's am-data.
        let mut other = body;
        other["notifyItems"][0]["resourceId"] = json!("/nudm-sdm/v2/imsi-999/am-data");
        assert!(matches!(
            applied_am_data(SUPI, &json!({}), Some("sub-1"), &other),
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
                    applied_am_data(SUPI, &json!({"gpsis": []}), None, &body),
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
            rebuilt,
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
            &notification(json!([{"op": "REPLACE", "path": "/mpsPriority", "newValue": false}])),
        )
        .expect("applied");
        adopt_am_data(SUPI, &mut ue, withdrawn);
        assert!(
            !ue.priority_subscription,
            "the MPS subscription is withdrawn"
        );
        assert_eq!((ue.ue_ambr.uplink, ue.ue_ambr.downlink), (1_000, 2_000));
        assert_eq!(ue.gpsi.as_deref(), Some("msisdn-333333"));
    }
}
