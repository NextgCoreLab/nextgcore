//! `eees-acrevents` — ACR events subscribe/notify API (TS 24.558 §6.4; D5).
//!
//! This is the conformant T-EAS delivery path that the ACR
//! Determine/Initiate/Declare 204s leave dangling: a compliant EEC creates an
//! individual ACR-events subscription (`POST /subscriptions`, 201 + `Location`)
//! and the EES POSTs an [`ACRInfoNotification`] to the subscriber's
//! `notificationDestination` when the ACR reaches a subscribed event
//! (`TARGET_INFORMATION` after Determine selects a T-EAS, `ACR_COMPLETE` after
//! Declare/status-update completes).
//!
//! Every model here is derived field-for-field from
//! `specs/TS24558_Eees_ACREvents.yaml` (schema anchors cited per field). Two
//! yaml facts drive the shape:
//! * `ACREventsSubscription.eventIds` is **singular-typed** (one `ACREventIDs`
//!   value) despite the plural name (yaml:303-304 → yaml:389-404) — it is a
//!   single [`String`], NOT a `Vec`.
//! * `ACREventsSubscription` carries **no** id field: the server-minted
//!   `subscriptionId` is the store key and is surfaced only via the `Location`
//!   header (the same convention as D1's `ACInfoSubscription`).
//!
//! Cross-spec leaf types (`EDNConfigInfo`, `EecCtxtRelocStatus`,
//! `EASBundleInfo`, `WebsockNotifConfig`) are carried as passthrough
//! [`serde_json::Value`] per the established `acr.rs` convention — preserving
//! the wire bytes without fabricating a local model.
//!
//! Actual outbound delivery is owned by the shared notifier (D6); D5 hands each
//! built notification to the [`crate::notifier`] seam, whose default stub
//! queues it in-process (see that module).

use serde::{Deserialize, Serialize};

use crate::types::{DiscoveredEas, EndPoint};

// ---------------------------------------------------------------------------
// ACREventIDs (yaml:389-404) — open enum modelled as constants + open string.
// ---------------------------------------------------------------------------

/// `ACREventIDs` value: target information event (yaml:393, 403).
pub const EVENT_TARGET_INFORMATION: &str = "TARGET_INFORMATION";
/// `ACREventIDs` value: ACR complete event (yaml:394, 404).
pub const EVENT_ACR_COMPLETE: &str = "ACR_COMPLETE";

/// Top-level members of `ACREventsSubscriptionPatch` (yaml:372-387) — the ONLY
/// fields a `PATCH` (`application/merge-patch+json`) may modify. The RFC 7396
/// merge is restricted to these keys; anything else in the patch document
/// (including the immutable `eecId`) is ignored.
pub const ACREVENTS_PATCHABLE_FIELDS: [&str; 4] =
    ["expTime", "easIds", "eventIds", "notificationDestination"];

// ---------------------------------------------------------------------------
// ACREventsSubscription (yaml:281-320)
// ---------------------------------------------------------------------------

/// `ACREventsSubscription` (TS24558_Eees_ACREvents.yaml:281-320) — body of
/// `CreateACREventsSubscripton` (POST /subscriptions) and the stored resource.
///
/// Required IEs (yaml:316-320): `eecId`, `easIds` (minItems 1), `eventIds`,
/// `notificationDestination`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACREventsSubscription {
    /// Unique identifier of the EEC (yaml:285-287; REQUIRED).
    pub eec_id: String,
    /// Application identifiers of the EASs of interest (yaml:292-297, minItems
    /// 1; REQUIRED).
    pub eas_ids: Vec<String>,
    /// The subscribed ACR event — a SINGLE `ACREventIDs` value despite the
    /// plural name (yaml:303-304, 389-404; REQUIRED, open-enum string).
    pub event_ids: String,
    /// Callback URI the EES POSTs [`ACRInfoNotification`]s to (`Uri`,
    /// yaml:305-306; REQUIRED).
    pub notification_destination: String,
    /// UE identifier (`Gpsi`, yaml:288-289).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Subscription expiration time (`DateTime`, yaml:290-291).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// List of AC identities (yaml:298-302).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_ids: Option<Vec<String>>,
    /// Set to true to request a test notification on create (yaml:307-311).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_test_notification: Option<bool>,
    /// TS 29.122 `WebsockNotifConfig` (yaml:312-313; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websock_notif_config: Option<serde_json::Value>,
    /// Supported features (yaml:314-315).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

impl ACREventsSubscription {
    /// True when this subscription is subscribed to `event_id`
    /// (`eventIds` is a single value, so this is exact equality).
    pub fn covers_event(&self, event_id: &str) -> bool {
        self.event_ids == event_id
    }

    /// True when an ACR transition should deliver `event_id` to this
    /// subscriber. The filter is deliberately conservative (TS 24.558 §6.4):
    /// the subscribed event must match, the transition's EAS must be one of the
    /// subscribed `easIds`, and — when the transition carries an identity — the
    /// `eecId` or `ueId` must match. The `easId`-keyed status-update path
    /// carries no identity (`eec_id`/`ue_id` both `None`), so `easId`
    /// membership alone selects there.
    pub fn matches(
        &self,
        event_id: &str,
        eec_id: Option<&str>,
        ue_id: Option<&str>,
        eas_id: Option<&str>,
    ) -> bool {
        if !self.covers_event(event_id) {
            return false;
        }
        // easId membership is mandatory: nothing to report without a subscribed EAS.
        let eas_ok = eas_id.is_some_and(|id| self.eas_ids.iter().any(|e| e == id));
        if !eas_ok {
            return false;
        }
        match (eec_id, ue_id) {
            (None, None) => true,
            _ => {
                eec_id.is_some_and(|e| e == self.eec_id)
                    || ue_id.is_some_and(|u| self.ue_id.as_deref() == Some(u))
            }
        }
    }
}

/// `ACREventsSubscriptionPatch` (yaml:372-387) — the `application/merge-patch+
/// json` document for `ModifyACREventsSubscription`. All members optional; the
/// merge is restricted to [`ACREVENTS_PATCHABLE_FIELDS`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ACREventsSubscriptionPatch {
    /// New expiration time (`DateTime`, yaml:376-377).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// New EAS identifier list (yaml:378-383, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ids: Option<Vec<String>>,
    /// New subscribed event (yaml:384-385).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_ids: Option<String>,
    /// New callback URI (yaml:386-387).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_destination: Option<String>,
}

// ---------------------------------------------------------------------------
// ACRInfoNotification (yaml:322-359) — the callback body.
// ---------------------------------------------------------------------------

/// `ACRInfoNotification` (yaml:322-359) — the callback body POSTed to
/// `notificationDestination`. Required IEs (yaml:356-359): `subId`, `easId`,
/// `eventId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACRInfoNotification {
    /// Identifier of the individual ACR-events subscription (yaml:326-330;
    /// REQUIRED). This is the server-minted `subscriptionId`.
    pub sub_id: String,
    /// Application identifier of the EAS (yaml:331-333; REQUIRED).
    pub eas_id: String,
    /// The ACR event being reported (`ACREventIDs`, yaml:337-338; REQUIRED).
    pub event_id: String,
    /// Identity of the AC (yaml:334-336).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// Selected T-EAS / T-EES details (yaml:339-340).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trgt_info: Option<TargetInfo>,
    /// Completed-ACR result (yaml:341-342).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_status: Option<ACRCompleteEventInfo>,
    /// `EecCtxtRelocStatus` (yaml:343-344, 406-411; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_ctxt_reloc: Option<serde_json::Value>,
    /// Selected `ACRScenario` list (yaml:345-348; open-enum strings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_scenario_list: Option<Vec<String>>,
    /// `EASBundleInfo` (yaml:349-350; passthrough).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_bundle_info: Option<serde_json::Value>,
    /// T-EAS endpoints for the EAS bundle (yaml:351-355, minItems 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t_eas_end_point_bundle_list: Option<Vec<EndPoint>>,
}

/// `TargetInfo` (yaml:361-370) — details of the selected T-EAS and T-EES.
///
/// NOTE the acronym casing: the yaml keys are `trgetEASInfo`/`trgetEESInfo`
/// (uppercase EAS/EES), NOT the `rename_all = "camelCase"` output
/// (`trgetEasInfo`/`trgetEesInfo`) — pinned with explicit `#[serde(rename)]`
/// and a byte-level serialization assertion in the tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TargetInfo {
    /// `DiscoveredEas` of the selected T-EAS (yaml:367-368; SHALL be present
    /// per the schema description, modelled optional for wire compatibility).
    #[serde(rename = "trgetEASInfo", skip_serializing_if = "Option::is_none")]
    pub trget_eas_info: Option<DiscoveredEas>,
    /// `EDNConfigInfo` of the selected T-EES (yaml:369-370; passthrough).
    #[serde(rename = "trgetEESInfo", skip_serializing_if = "Option::is_none")]
    pub trget_ees_info: Option<serde_json::Value>,
}

/// `ACRCompleteEventInfo` (yaml:413-427) — the completed-ACR result and T-EAS
/// endpoint. Required IEs (yaml:425-427): `acrRes`, `tEasEndpoint`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ACRCompleteEventInfo {
    /// Whether the ACR succeeded (yaml:417-419; REQUIRED).
    pub acr_res: bool,
    /// Target EAS endpoint (`EndPoint`, yaml:420-421; REQUIRED).
    pub t_eas_endpoint: EndPoint,
    /// Cause information for the failure (yaml:422-424).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EasProfile;

    /// Spec-exact `ACREventsSubscription` round-trips (all 4 required + optionals).
    #[test]
    fn test_acrevents_subscription_roundtrip() {
        // Hand-built from the yaml (no `example:` block exists) — all camelCase.
        let body = r#"{
            "eecId":"eec1.example.com",
            "easIds":["eas-s.example.com","eas-t.example.com"],
            "eventIds":"TARGET_INFORMATION",
            "notificationDestination":"http://eec.example.com/acr-cb",
            "ueId":"imsi-999700000000001",
            "expTime":"2030-01-01T00:00:00Z",
            "acIds":["ac1"],
            "requestTestNotification":true,
            "suppFeat":"1"
        }"#;
        let sub: ACREventsSubscription = serde_json::from_str(body).expect("deserializes");
        assert_eq!(sub.eec_id, "eec1.example.com");
        assert_eq!(sub.eas_ids.len(), 2);
        assert_eq!(sub.event_ids, "TARGET_INFORMATION");
        assert_eq!(sub.notification_destination, "http://eec.example.com/acr-cb");
        assert_eq!(sub.request_test_notification, Some(true));

        let wire = serde_json::to_value(&sub).unwrap();
        // camelCase exactness for the trap-prone keys.
        assert!(wire.get("eecId").is_some());
        assert!(wire.get("easIds").is_some());
        assert!(wire.get("eventIds").is_some());
        assert!(wire.get("notificationDestination").is_some());
        // The wire body never carries a server id.
        assert!(wire.get("subscriptionId").is_none());
    }

    /// `eventIds` is singular — a JSON array must NOT deserialize into it.
    #[test]
    fn test_acrevents_event_ids_is_singular() {
        let body = r#"{
            "eecId":"eec1","easIds":["eas1"],
            "eventIds":["TARGET_INFORMATION"],
            "notificationDestination":"http://cb"
        }"#;
        assert!(
            serde_json::from_str::<ACREventsSubscription>(body).is_err(),
            "eventIds is a single ACREventIDs value, not an array"
        );
    }

    /// Each of the 4 required IEs, individually missing, fails to deserialize.
    #[test]
    fn test_acrevents_subscription_missing_required_fail() {
        let base = [
            ("eecId", r#""eec1""#),
            ("easIds", r#"["eas1"]"#),
            ("eventIds", r#""ACR_COMPLETE""#),
            ("notificationDestination", r#""http://cb""#),
        ];
        for skip in base.iter().map(|(k, _)| *k) {
            let mut obj = serde_json::Map::new();
            for (k, v) in base.iter() {
                if *k == skip {
                    continue;
                }
                obj.insert(k.to_string(), serde_json::from_str(v).unwrap());
            }
            let val = serde_json::Value::Object(obj);
            assert!(
                serde_json::from_value::<ACREventsSubscription>(val).is_err(),
                "missing required IE {skip} must fail to deserialize"
            );
        }
    }

    /// `ACRInfoNotification` round-trips with `TARGET_INFORMATION` + trgtInfo.
    #[test]
    fn test_acr_info_notification_target_information_roundtrip() {
        let notif = ACRInfoNotification {
            sub_id: "sub-1".into(),
            eas_id: "eas-s.example.com".into(),
            event_id: EVENT_TARGET_INFORMATION.into(),
            ac_id: None,
            trgt_info: Some(TargetInfo {
                trget_eas_info: Some(DiscoveredEas {
                    eas: EasProfile {
                        eas_id: "eas-t.example.com".into(),
                        end_pt: EndPoint {
                            fqdn: Some("eas-t.edge.example.com".into()),
                            ..Default::default()
                        },
                        prov_id: None,
                        eas_type: None,
                        flex_eas_type: None,
                        ac_ids: None,
                        svc_area: None,
                        svc_kpi: None,
                    },
                }),
                trget_ees_info: None,
            }),
            acr_status: None,
            eec_ctxt_reloc: None,
            acr_scenario_list: None,
            eas_bundle_info: None,
            t_eas_end_point_bundle_list: None,
        };
        let wire = serde_json::to_value(&notif).unwrap();
        assert_eq!(wire["subId"], "sub-1");
        assert_eq!(wire["easId"], "eas-s.example.com");
        assert_eq!(wire["eventId"], "TARGET_INFORMATION");
        assert_eq!(
            wire["trgtInfo"]["trgetEASInfo"]["eas"]["easId"],
            "eas-t.example.com"
        );
        // Acronym-casing trap: the yaml key is trgetEASInfo, NOT trgetEasInfo.
        assert!(wire["trgtInfo"].get("trgetEASInfo").is_some());
        assert!(wire["trgtInfo"].get("trgetEasInfo").is_none());
        let back: ACRInfoNotification = serde_json::from_value(wire).unwrap();
        assert_eq!(back, notif);
    }

    /// `ACRCompleteEventInfo` requires `acrRes` + `tEasEndpoint`; casing pinned.
    #[test]
    fn test_acr_complete_event_info_casing() {
        let info = ACRCompleteEventInfo {
            acr_res: true,
            t_eas_endpoint: EndPoint {
                fqdn: Some("eas-t.edge.example.com".into()),
                ..Default::default()
            },
            fail_reason: None,
        };
        let wire = serde_json::to_value(&info).unwrap();
        assert_eq!(wire["acrRes"], true);
        // yaml field is tEasEndpoint (lowercase 'p').
        assert!(wire.get("tEasEndpoint").is_some());
        assert!(wire.get("tEasEndPoint").is_none());
        // Missing tEasEndpoint fails to deserialize.
        assert!(serde_json::from_str::<ACRCompleteEventInfo>(r#"{"acrRes":true}"#).is_err());
    }

    /// `ACREventsSubscriptionPatch` round-trips; all members optional.
    #[test]
    fn test_acrevents_subscription_patch_roundtrip() {
        let patch: ACREventsSubscriptionPatch = serde_json::from_str(
            r#"{"notificationDestination":"http://cb2","eventIds":"ACR_COMPLETE"}"#,
        )
        .unwrap();
        assert_eq!(patch.notification_destination.as_deref(), Some("http://cb2"));
        assert_eq!(patch.event_ids.as_deref(), Some("ACR_COMPLETE"));
        assert!(patch.exp_time.is_none());
        // Empty merge document is valid (all-optional).
        assert_eq!(
            serde_json::to_string(&ACREventsSubscriptionPatch::default()).unwrap(),
            "{}"
        );
    }

    /// `ACRInfoNotification` requires the subId/easId/eventId trio.
    #[test]
    fn test_acr_info_notification_missing_required_fail() {
        assert!(serde_json::from_str::<ACRInfoNotification>(
            r#"{"easId":"e","eventId":"ACR_COMPLETE"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<ACRInfoNotification>(r#"{"subId":"s","eventId":"ACR_COMPLETE"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ACRInfoNotification>(r#"{"subId":"s","easId":"e"}"#).is_err()
        );
    }

    fn sub_for(event: &str, eec: &str, eas_ids: &[&str], ue: Option<&str>) -> ACREventsSubscription {
        ACREventsSubscription {
            eec_id: eec.into(),
            eas_ids: eas_ids.iter().map(|s| s.to_string()).collect(),
            event_ids: event.into(),
            notification_destination: "http://cb".into(),
            ue_id: ue.map(String::from),
            exp_time: None,
            ac_ids: None,
            request_test_notification: None,
            websock_notif_config: None,
            supp_feat: None,
        }
    }

    /// Matching: event + easId-membership + identity, all conservative.
    #[test]
    fn test_matches_conservative_filter() {
        let s = sub_for(EVENT_TARGET_INFORMATION, "eec-1", &["eas-s.example.com"], None);
        // Happy path: event + easId + eecId all match.
        assert!(s.matches(
            EVENT_TARGET_INFORMATION,
            Some("eec-1"),
            None,
            Some("eas-s.example.com")
        ));
        // Wrong event → no fire.
        assert!(!s.matches(EVENT_ACR_COMPLETE, Some("eec-1"), None, Some("eas-s.example.com")));
        // easId not in the subscribed set → no fire.
        assert!(!s.matches(EVENT_TARGET_INFORMATION, Some("eec-1"), None, Some("eas-x")));
        // Wrong eecId (and no ueId match) → no fire.
        assert!(!s.matches(
            EVENT_TARGET_INFORMATION,
            Some("eec-2"),
            None,
            Some("eas-s.example.com")
        ));
    }

    /// ueId identity match works when eecId does not (e.g. EAS-triggered Declare).
    #[test]
    fn test_matches_ue_id_path() {
        let s = sub_for(
            EVENT_ACR_COMPLETE,
            "eec-1",
            &["eas-t.example.com"],
            Some("imsi-1"),
        );
        // requestorId is an EAS (not the eecId) but ueId matches → fire.
        assert!(s.matches(
            EVENT_ACR_COMPLETE,
            Some("eas-s.example.com"),
            Some("imsi-1"),
            Some("eas-t.example.com")
        ));
    }

    /// Identity-less status-update path: easId membership alone selects.
    #[test]
    fn test_matches_status_update_no_identity() {
        let s = sub_for(EVENT_ACR_COMPLETE, "eec-1", &["eas-t.example.com"], None);
        assert!(s.matches(EVENT_ACR_COMPLETE, None, None, Some("eas-t.example.com")));
        assert!(!s.matches(EVENT_ACR_COMPLETE, None, None, Some("eas-x")));
    }
}
