//! `Ndccf_DataManagement` wire types and subscription scoping (issue #112).
//!
//! # Which schema is authoritative
//!
//! TS 29.574 defines `Ndccf_DataManagement`, and its OpenAPI file is **not
//! vendored** in this tree. The service's data model is the same as
//! `Nnwdaf_DataManagement`, whose file **is** vendored
//! (`TS29520_Nnwdaf_DataManagement.yaml`), so every member name, requirement and
//! `oneOf` below was read out of that file. Where a member's type comes from a
//! yaml that is *also* absent (`DataSubscription` from TS 29.575,
//! `FormattingInstruction` / `ProcessingInstruction` / `NotifSummaryReport` from
//! TS 29.574) it is carried as passthrough [`serde_json::Value`] — the
//! established convention in this repo for a cross-spec leaf, because modelling
//! a schema nobody can check against invents a contract.
//!
//! # What was wrong before
//!
//! The subscribe handler read the callback URI from `"notifyUri"`. The required
//! member is `notificURI` (yaml `required: [notifCorrId, notificURI]`), so a
//! conformant consumer's URI was never captured, the stored URI stayed empty,
//! and the empty-URI filter in the fan-out dropped that consumer from every
//! notification. It subscribed successfully and was never told anything.
//!
//! `notifCorrId` was never parsed, stored or echoed anywhere in the crate, so
//! even a delivered notification could not be correlated by the consumer.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// `NnwdafDataManagementSubsc` (`TS29520_Nnwdaf_DataManagement.yaml`) — the
/// subscribe request body, the `201` echo, and the `PUT` update body.
///
/// `required: [notifCorrId, notificURI]` and `oneOf: [anaSub | dataSub]`, both
/// enforced by [`Self::validate`] — serde cannot express either (it accepts an
/// empty string for a required `String`, and has no `oneOf`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataManagementSubsc {
    /// Notification correlation identifier (REQUIRED). Echoed on every
    /// notification so the consumer can tie it back to this subscription.
    ///
    /// `serde(default)` although the yaml marks it required: without it an absent
    /// member is a *parse* error, which the handler can only report as
    /// `INVALID_MSG_FORMAT`. TS 29.500 wants `MANDATORY_IE_MISSING` for a missing
    /// mandatory IE, and that distinction is what tells a consumer whether its
    /// JSON is malformed or merely incomplete. So absence deserialises to an
    /// empty string and [`Self::validate`] names the member.
    #[serde(default)]
    pub notif_corr_id: String,
    /// Consumer callback URI (REQUIRED).
    ///
    /// `notificURI` in the yaml — note the spelling: `notific`, not `notif`, and
    /// `URI` uppercase. `rename_all = "camelCase"` would produce `notificUri`,
    /// so this needs the explicit rename. That single character is the defect
    /// this type exists to fix.
    #[serde(rename = "notificURI", default)]
    pub notific_uri: String,
    /// Analytics subscription (`NnwdafEventsSubscription`) — one of the two
    /// `oneOf` branches. Passthrough: the events are read out of it by
    /// [`SubscriptionScope::from_subsc`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ana_sub: Option<serde_json::Value>,
    /// Data subscription (`DataSubscription`, TS 29.575 — yaml not vendored) —
    /// the other `oneOf` branch. Passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_sub: Option<serde_json::Value>,
    /// ADRF instance the collected data should be stored in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adrf_id: Option<String>,
    /// ADRF set, as an alternative to `adrfId`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adrf_set_id: Option<String>,
    /// Target NF instance the data is collected about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_nf_id: Option<String>,
    /// Target NF set, as an alternative to `targetNfId`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_nf_set_id: Option<String>,
    /// Formatting instruction (TS 29.574; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_instruct: Option<serde_json::Value>,
    /// Processing instruction (TS 29.574; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_instruct: Option<serde_json::Value>,
    /// Time window the data is requested for (passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_period: Option<serde_json::Value>,
    /// Data-collection purposes, when user consent applies (passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_collect_purposes: Option<serde_json::Value>,
    /// The consumer has already checked user consent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_consent_ind: Option<bool>,
    /// Supported features.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// Why a subscribe/update body was rejected. Each variant maps to a distinct
/// `ProblemDetails` detail, because "invalid request" tells a consumer nothing
/// about which member to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscValidationError {
    /// `notifCorrId` absent or empty.
    MissingNotifCorrId,
    /// `notificURI` absent or empty.
    MissingNotificUri,
    /// Neither `anaSub` nor `dataSub` was supplied.
    NeitherAnaSubNorDataSub,
    /// Both were supplied — `oneOf` means exactly one.
    BothAnaSubAndDataSub,
}

impl SubscValidationError {
    /// The `detail` for the `400` ProblemDetails.
    pub fn detail(&self) -> &'static str {
        match self {
            Self::MissingNotifCorrId => {
                "Missing mandatory IE notifCorrId (TS29520_Nnwdaf_DataManagement.yaml \
                 NnwdafDataManagementSubsc required: [notifCorrId, notificURI])"
            }
            Self::MissingNotificUri => {
                "Missing mandatory IE notificURI (TS29520_Nnwdaf_DataManagement.yaml \
                 NnwdafDataManagementSubsc required: [notifCorrId, notificURI]). Note the \
                 spelling: notificURI, not notifyUri"
            }
            Self::NeitherAnaSubNorDataSub => {
                "Exactly one of anaSub / dataSub must be present \
                 (NnwdafDataManagementSubsc oneOf); neither was supplied"
            }
            Self::BothAnaSubAndDataSub => {
                "Exactly one of anaSub / dataSub must be present \
                 (NnwdafDataManagementSubsc oneOf); both were supplied"
            }
        }
    }
}

impl DataManagementSubsc {
    /// Enforce the yaml's `required` and `oneOf` constraints.
    ///
    /// Empty strings count as absent. serde deserialises `{"notifCorrId": ""}`
    /// into a present-but-empty `String`, and an empty callback URI is exactly
    /// the state that made the old code silently un-notifiable — so accepting it
    /// would reproduce the defect through a different door.
    pub fn validate(&self) -> Result<(), SubscValidationError> {
        if self.notif_corr_id.trim().is_empty() {
            return Err(SubscValidationError::MissingNotifCorrId);
        }
        if self.notific_uri.trim().is_empty() {
            return Err(SubscValidationError::MissingNotificUri);
        }
        match (self.ana_sub.is_some(), self.data_sub.is_some()) {
            (false, false) => Err(SubscValidationError::NeitherAnaSubNorDataSub),
            (true, true) => Err(SubscValidationError::BothAnaSubAndDataSub),
            _ => Ok(()),
        }
    }
}

/// `NnwdafDataManagementNotif` (`TS29520_Nnwdaf_DataManagement.yaml`) — the
/// notification body delivered to a consumer's `notificURI`.
///
/// `required: [notifCorrId, notifTimestamp]`, `oneOf: [dataNotification |
/// dataReports | fetchInstruct]`. The previous code sent `{"data": "<string>"}`,
/// which satisfies none of that: no correlation id, no timestamp, and the
/// producer's body stringified inside a member the schema does not define.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataManagementNotif {
    /// The subscription's `notifCorrId`, echoed (REQUIRED).
    pub notif_corr_id: String,
    /// RFC 3339 timestamp of this notification (REQUIRED).
    pub notif_timestamp: String,
    /// The collected data (`DataNotification`, TS 29.575; passthrough). This is
    /// the `oneOf` branch the DCCF uses when forwarding producer data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_notification: Option<serde_json::Value>,
    /// Summary reports of processed notifications (passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_reports: Option<serde_json::Value>,
    /// Instruction to fetch the data from elsewhere (passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetch_instruct: Option<serde_json::Value>,
}

impl DataManagementNotif {
    /// A notification carrying forwarded producer data, which is the only
    /// `oneOf` branch this DCCF produces.
    pub fn with_data(
        notif_corr_id: impl Into<String>,
        notif_timestamp: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            notif_corr_id: notif_corr_id.into(),
            notif_timestamp: notif_timestamp.into(),
            data_notification: Some(data),
            data_reports: None,
            fetch_instruct: None,
        }
    }
}

/// What a subscription asked for: the set of event identifiers, and the target
/// it is scoped to (#112).
///
/// This is the fan-out key. The old fan-out returned *every* subscriber with a
/// non-empty URI, so a consumer that populated the non-standard `notifyUri`
/// received every other such consumer's collected data — no keying on event or
/// target at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionScope {
    /// Event identifiers this subscription covers. Empty means the scope could
    /// not be determined — see [`Self::matches`] for what that implies.
    pub events: BTreeSet<String>,
    /// `targetNfId` / `targetNfSetId`, when the subscription named one.
    pub target: Option<String>,
}

impl SubscriptionScope {
    /// Derive the scope from a subscription.
    ///
    /// For `anaSub` the extraction is **exact**: `NnwdafEventsSubscription` is
    /// vendored, so `eventSubscriptions[].event` is read directly.
    ///
    /// For `dataSub` it is a documented **heuristic**: `DataSubscription`
    /// (TS 29.575) is not vendored, so its exact nesting cannot be verified
    /// here. Every string under a key named `event`, `eventId` or `type`, at any
    /// depth, is collected. That is deliberately conservative in the direction
    /// that matters: an over-broad *extraction* can only ever make a
    /// subscription's scope larger than intended for its own notifications,
    /// whereas guessing wrong in the other direction would resurrect the
    /// unkeyed fan-out this replaces.
    pub fn from_subsc(sub: &DataManagementSubsc) -> Self {
        let mut events = BTreeSet::new();
        if let Some(ana) = &sub.ana_sub {
            // Exact: the vendored NnwdafEventsSubscription shape.
            if let Some(list) = ana.get("eventSubscriptions").and_then(|v| v.as_array()) {
                for entry in list {
                    if let Some(ev) = entry.get("event").and_then(|e| e.as_str()) {
                        events.insert(ev.to_string());
                    }
                }
            }
        }
        if let Some(data) = &sub.data_sub {
            collect_event_strings(data, &mut events);
        }
        Self {
            events,
            target: sub
                .target_nf_id
                .clone()
                .or_else(|| sub.target_nf_set_id.clone()),
        }
    }

    /// Derive the scope of an inbound **producer notification**, so it can be
    /// matched against subscriptions.
    ///
    /// Reads `eventNotifications[].event` (the vendored
    /// `NnwdafEventsSubscriptionNotification` shape) and then applies the same
    /// key-name sweep, so an event-exposure notification from another producer
    /// family is still scoped rather than treated as unkeyed.
    pub fn from_notification(body: &serde_json::Value) -> Self {
        let mut events = BTreeSet::new();
        if let Some(list) = body.get("eventNotifications").and_then(|v| v.as_array()) {
            for entry in list {
                if let Some(ev) = entry.get("event").and_then(|e| e.as_str()) {
                    events.insert(ev.to_string());
                }
            }
        }
        if events.is_empty() {
            collect_event_strings(body, &mut events);
        }
        Self {
            events,
            target: body
                .get("targetNfId")
                .or_else(|| body.get("nfInstanceId"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
        }
    }

    /// Should a subscription with this scope receive a notification scoped
    /// `notif`?
    ///
    /// Two rules, both deliberate:
    ///
    /// * **The event sets must intersect.** A subscription whose events are
    ///   unknown (empty set) matches **nothing**. Delivering to it instead — the
    ///   old behaviour — is the cross-consumer disclosure defect; and a
    ///   scope-less subscriber is visible in the logs, which an over-broad
    ///   delivery is not.
    /// * **A target, if named on both sides, must match.** A subscription that
    ///   named no target accepts any, because it constrained nothing. A
    ///   notification that names no target is delivered to any matching event
    ///   subscription, because a producer that did not say which NF the data is
    ///   about cannot be filtered on that basis.
    pub fn matches(&self, notif: &SubscriptionScope) -> bool {
        if self.events.is_empty() || notif.events.is_empty() {
            return false;
        }
        if !self.events.iter().any(|e| notif.events.contains(e)) {
            return false;
        }
        match (&self.target, &notif.target) {
            (Some(mine), Some(theirs)) => mine == theirs,
            _ => true,
        }
    }
}

/// Recursively collect every string value under a key named `event`, `eventId`
/// or `type`. Bounded by [`MAX_SCOPE_DEPTH`] so a deeply nested (or
/// adversarially nested) body cannot recurse without limit.
fn collect_event_strings(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    fn walk(value: &serde_json::Value, out: &mut BTreeSet<String>, depth: usize) {
        if depth > MAX_SCOPE_DEPTH {
            return;
        }
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    if matches!(key.as_str(), "event" | "eventId" | "type") {
                        if let Some(s) = val.as_str() {
                            out.insert(s.to_string());
                        }
                    }
                    walk(val, out, depth + 1);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, out, depth + 1);
                }
            }
            _ => {}
        }
    }
    walk(value, out, 0);
}

/// Depth bound for the scope sweep. A `dataSub` is peer-supplied and this walk
/// runs on the request path, so the recursion needs a ceiling; 16 is far deeper
/// than any nesting in the TS 29.5xx models.
const MAX_SCOPE_DEPTH: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> DataManagementSubsc {
        DataManagementSubsc {
            notif_corr_id: "corr-1".into(),
            notific_uri: "http://consumer/cb".into(),
            ana_sub: Some(serde_json::json!({
                "eventSubscriptions": [{"event": "SERVICE_EXPERIENCE"}]
            })),
            ..Default::default()
        }
    }

    /// The member spelling is the anchor defect: `notificURI`, not `notifyUri`
    /// and not the `notificUri` that `rename_all = "camelCase"` would produce.
    ///
    /// Asserted on the serialized TEXT and by deserialising a hand-written
    /// spec-shaped body: a round trip of our own struct passes even when every
    /// member name is wrong, because both directions use the same wrong name.
    #[test]
    fn the_callback_member_is_spelled_notific_uri() {
        let json = serde_json::to_string(&valid()).expect("json");
        assert!(
            json.contains(r#""notificURI":"http://consumer/cb""#),
            "expected the yaml spelling, got {json}"
        );
        assert!(
            !json.contains("notifyUri") && !json.contains("notificUri"),
            "neither the old bespoke key nor the camelCase default may appear: {json}"
        );

        // A body copied out of the yaml parses.
        let parsed: DataManagementSubsc = serde_json::from_str(
            r#"{"notifCorrId":"c1","notificURI":"http://x/cb",
                "anaSub":{"eventSubscriptions":[{"event":"NF_LOAD"}]}}"#,
        )
        .expect("parses");
        assert_eq!(parsed.notific_uri, "http://x/cb");
        assert_eq!(parsed.notif_corr_id, "c1");

        // The OLD key is NOT honoured by the type: a body using `notifyUri`
        // leaves `notificURI` absent, so validation refuses it rather than
        // silently accepting an un-notifiable subscription.
        let old: DataManagementSubsc = serde_json::from_str(
            r#"{"notifCorrId":"c1","notifyUri":"http://x/cb",
                "anaSub":{"eventSubscriptions":[{"event":"NF_LOAD"}]}}"#,
        )
        .expect("unknown members are ignored");
        assert!(old.notific_uri.is_empty());
        assert_eq!(old.validate(), Err(SubscValidationError::MissingNotificUri));
    }

    /// Every `required` / `oneOf` violation is a distinct error, so the 400 can
    /// say which member to fix.
    #[test]
    fn validation_covers_required_and_one_of() {
        assert!(valid().validate().is_ok());

        let mut s = valid();
        s.notif_corr_id = String::new();
        assert_eq!(s.validate(), Err(SubscValidationError::MissingNotifCorrId));
        // Whitespace is not a value.
        let mut s = valid();
        s.notif_corr_id = "   ".into();
        assert_eq!(s.validate(), Err(SubscValidationError::MissingNotifCorrId));

        let mut s = valid();
        s.notific_uri = String::new();
        assert_eq!(s.validate(), Err(SubscValidationError::MissingNotificUri));

        let mut s = valid();
        s.ana_sub = None;
        assert_eq!(
            s.validate(),
            Err(SubscValidationError::NeitherAnaSubNorDataSub)
        );

        let mut s = valid();
        s.data_sub = Some(serde_json::json!({"dataSpec": {}}));
        assert_eq!(
            s.validate(),
            Err(SubscValidationError::BothAnaSubAndDataSub),
            "oneOf means exactly one, not at least one"
        );

        // Each detail names its own member.
        assert!(SubscValidationError::MissingNotificUri
            .detail()
            .contains("notificURI"));
        assert!(SubscValidationError::MissingNotifCorrId
            .detail()
            .contains("notifCorrId"));
    }

    /// `anaSub` events are read exactly, from the vendored schema's shape.
    #[test]
    fn scope_from_ana_sub_is_exact() {
        let sub = DataManagementSubsc {
            ana_sub: Some(serde_json::json!({
                "eventSubscriptions": [
                    {"event": "SERVICE_EXPERIENCE"},
                    {"event": "NF_LOAD"}
                ],
                "notificationURI": "http://nwdaf/cb"
            })),
            ..valid()
        };
        let scope = SubscriptionScope::from_subsc(&sub);
        assert_eq!(scope.events.len(), 2);
        assert!(scope.events.contains("SERVICE_EXPERIENCE"));
        assert!(scope.events.contains("NF_LOAD"));
        assert_eq!(scope.target, None);
    }

    /// `dataSub` is swept heuristically, and the target is picked up from either
    /// `targetNfId` or `targetNfSetId`.
    #[test]
    fn scope_from_data_sub_sweeps_nested_event_keys() {
        let sub = DataManagementSubsc {
            notif_corr_id: "c".into(),
            notific_uri: "http://x".into(),
            ana_sub: None,
            data_sub: Some(serde_json::json!({
                "dataSpec": {"nwdafEventsSub": {"eventSubscriptions": [{"event": "UE_MOBILITY"}]}}
            })),
            target_nf_set_id: Some("set-1".into()),
            ..Default::default()
        };
        let scope = SubscriptionScope::from_subsc(&sub);
        assert!(scope.events.contains("UE_MOBILITY"));
        assert_eq!(scope.target.as_deref(), Some("set-1"));
    }

    /// The keying rules: intersect on events, and an unknown scope matches
    /// nothing rather than everything.
    #[test]
    fn matching_requires_an_event_intersection() {
        let a = SubscriptionScope {
            events: ["NF_LOAD".to_string()].into_iter().collect(),
            target: None,
        };
        let b = SubscriptionScope {
            events: ["UE_MOBILITY".to_string()].into_iter().collect(),
            target: None,
        };
        let notif_a = SubscriptionScope {
            events: ["NF_LOAD".to_string()].into_iter().collect(),
            target: None,
        };

        assert!(a.matches(&notif_a));
        assert!(
            !b.matches(&notif_a),
            "a consumer subscribed to a different event must not receive this"
        );

        // An unknown scope on either side matches nothing -- NOT everything,
        // which is the disclosure defect being fixed.
        let unknown = SubscriptionScope::default();
        assert!(!unknown.matches(&notif_a));
        assert!(!a.matches(&SubscriptionScope::default()));
    }

    /// A target named on both sides must agree; a side that named none does not
    /// constrain.
    #[test]
    fn matching_honours_a_target_named_on_both_sides() {
        let events: BTreeSet<String> = ["NF_LOAD".to_string()].into_iter().collect();
        let scoped = SubscriptionScope {
            events: events.clone(),
            target: Some("nf-1".into()),
        };
        let unscoped = SubscriptionScope {
            events: events.clone(),
            target: None,
        };

        assert!(scoped.matches(&SubscriptionScope {
            events: events.clone(),
            target: Some("nf-1".into())
        }));
        assert!(
            !scoped.matches(&SubscriptionScope {
                events: events.clone(),
                target: Some("nf-2".into())
            }),
            "data about another NF must not be delivered"
        );
        // Either side unset: no target constraint.
        assert!(scoped.matches(&unscoped));
        assert!(unscoped.matches(&scoped));
    }

    /// The producer-notification scope is read from the vendored notification
    /// shape.
    #[test]
    fn scope_from_a_producer_notification() {
        let body = serde_json::json!({
            "subscriptionId": "prod-sub-1",
            "eventNotifications": [{"event": "NF_LOAD", "timeStamp": "2026-01-01T00:00:00Z"}]
        });
        let scope = SubscriptionScope::from_notification(&body);
        assert!(scope.events.contains("NF_LOAD"));
    }

    /// The notification body uses the yaml member names, carries both required
    /// members, and exactly one `oneOf` branch.
    #[test]
    fn notification_uses_the_yaml_member_names() {
        let notif = DataManagementNotif::with_data(
            "corr-1",
            "2026-01-01T00:00:00Z",
            serde_json::json!({"eventNotifications": []}),
        );
        let json = serde_json::to_string(&notif).expect("json");
        assert!(json.contains(r#""notifCorrId":"corr-1""#), "got {json}");
        assert!(json.contains(r#""notifTimestamp""#), "got {json}");
        assert!(json.contains(r#""dataNotification""#), "got {json}");
        // The old bespoke envelope must be gone.
        assert!(!json.contains(r#""data":"#), "got {json}");
        // Only one oneOf branch is present.
        assert!(!json.contains("dataReports"), "got {json}");
        assert!(!json.contains("fetchInstruct"), "got {json}");
        // And it round-trips.
        let parsed: DataManagementNotif = serde_json::from_str(&json).expect("parses");
        assert_eq!(parsed, notif);
    }

    /// The scope sweep terminates on a deeply nested body rather than recursing
    /// without bound: `dataSub` is peer-supplied on the request path.
    #[test]
    fn the_scope_sweep_is_depth_bounded() {
        // Nest well past the ceiling.
        let mut body = serde_json::json!({"event": "DEEP"});
        for _ in 0..(MAX_SCOPE_DEPTH * 3) {
            body = serde_json::json!({"nested": body});
        }
        let mut out = BTreeSet::new();
        collect_event_strings(&body, &mut out);
        // It returns (does not hang or overflow) and does not see past the bound.
        assert!(
            out.is_empty(),
            "the sweep must stop at the depth ceiling, got {out:?}"
        );

        // ...while a shallow event is still found.
        let mut out = BTreeSet::new();
        collect_event_strings(&serde_json::json!({"a": {"event": "SHALLOW"}}), &mut out);
        assert!(out.contains("SHALLOW"));
    }
}
