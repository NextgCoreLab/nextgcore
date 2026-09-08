//! EEC Registration data model (EDGE-1, TS 24.558 §5.2 / `Eees_EECRegistration`).
//!
//! eesd-06: the EES exposes the `eees-eecregistration` service API so an Edge
//! Enabler Client can register, update and deregister itself before consuming
//! discovery / ACR services. The resource is identified by a server-minted
//! `registrationId` (distinct from the consumer's immutable `eecId`) and is
//! subject to an `expTime` lifecycle (eesd-12): when the consumer supplies no
//! `expTime`, the EES mints one; lapsed registrations are dropped by the
//! periodic sweep.
//!
//! #105 added the service-continuity / relocation IEs (`yaml:253-281`) and the
//! partial-fulfilment report ([`UnfulfilledAcProfile`]). Two ceilings on the
//! EdgeApp_2 members: `ueMobilityReq` and `ueType` are stored but drive nothing —
//! §5.2.2.2 step 4 would have the EES subscribe to UE location via NEF/NWDAF on
//! `ueMobilityReq: true`, and this EES has no such subscription path — and
//! `easBundleInfos` is not modelled, so bundle matching and ECSP-triggered EAS
//! instantiation are absent.

use serde::{Deserialize, Serialize};

/// Default validity (seconds) the EES assigns to an EEC registration that
/// arrives without a consumer-supplied `expTime`.
pub const DEFAULT_EEC_REG_LIFETIME_SECS: i64 = 3600;

/// TS 24.558 `EECRegistration` (subset) — body of `CreateEECReg` /
/// `UpdateIndEECReg`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EecRegistration {
    /// Edge Enabler Client identifier (mandatory, consumer-provided, immutable).
    pub eec_id: String,
    /// UE identifier (GPSI, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Application Client profiles served by this EEC (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_profs: Option<Vec<AcProfile>>,
    /// Registration expiration time (RFC 3339). Server-managed: minted when the
    /// consumer omits it (eesd-12).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional, TS 29.558 §7.8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
    // ---- service-continuity / relocation IEs (#105) ----
    //
    // `TS24558_Eees_EECRegistration.yaml:253-281` defines all six, and every one was
    // DROPPED. Two consequences: the TS 29.558 §5.10 EEC-context pull could never be
    // triggered from the registration path even though the transport types already
    // exist in `services.rs`, and an EES had no way to know a registration was part
    // of a relocation at all.
    /// `eecSvcContSupp` — the ACR scenarios this EEC supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_svc_cont_supp: Option<Vec<String>>,
    /// `eecCntxId` — the EEC context to be relocated. With `srcEesId`, this is what
    /// makes a registration a relocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eec_cntx_id: Option<String>,
    /// `srcEesId` — the S-EES holding that context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ees_id: Option<String>,
    /// `endPt` — the EEC's own endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_pt: Option<crate::types::EndPoint>,
    /// `easSelReqInd` — the EEC asks the EES to select EASes for its AC profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_sel_req_ind: Option<bool>,
    /// `discoveredEas` — on the way in, EASes the EEC already discovered; on the
    /// way out, the EASes this EES selected for the AC profiles when the EEC set
    /// `easSelReqInd` (§5.2.2.2 step 1 iii B). `minItems: 1`, so an empty
    /// selection omits the member rather than emitting `[]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_eas: Option<Vec<crate::types::DiscoveredEas>>,
    /// `ueMobilityReq` — UE mobility support required (default false when
    /// omitted). Stored only; see the module note on EdgeApp_2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_mobility_req: Option<bool>,
    /// `ueType` — `DeviceType` (`CONSTRAINED_UE` / `NORMAL_UE`), stored so a
    /// UE-type-specific local policy has an input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_type: Option<String>,
    // ---- partial-fulfilment report (response-only; §5.2.2.2 step 1) --------
    //
    // Mutually exclusive by `yaml:299-300`'s `not: required: [both]`, and NOTE 2
    // narrows which one applies: the SINGULAR member may be used only when there is
    // exactly one unfulfilled profile. Never set these directly — go through
    // [`EecRegistration::set_unfulfilled`], which is what encodes that rule.
    /// `unfulfillAcProfs` — the AC profiles the EES could not fulfil (2..N).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unfulfill_ac_profs: Option<Vec<UnfulfilledAcProfile>>,
    /// `unfulfilledAcProfs` — the single unfulfilled AC profile (NOTE 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unfulfilled_ac_profs: Option<UnfulfilledAcProfile>,
    /// Server-minted resource identifier (read-only; never supplied by the
    /// consumer). Populated on registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
}

/// `UnfulfillACProfRsn` (`TS24558_Eees_EECRegistration.yaml:424-437`) — why an
/// AC profile's requirements could not be met. Open enumeration (`anyOf` with a
/// free-form string), so it is carried as a `String`.
pub mod unfulfill_reason {
    /// No registered EAS answers to the `easId`s the AC profile named.
    pub const EAS_NOT_AVAILABLE: &str = "EAS_NOT_AVAILABLE";
    /// An EAS answers to the `easId`, but it does not suffice the profile's
    /// `minimumReqSvcKPIs`.
    pub const REQ_UNFULFILLED: &str = "REQ_UNFULFILLED";
}

/// `UnfulfilledAcProfile` (`TS24558_Eees_EECRegistration.yaml:412-423`).
///
/// `acId` is `Option` because the schema declares no `required` list — the spec's
/// own description says it "shall be present, although it is not specified as a
/// mandatory due to backward compatibility reasons". This EES always sets it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UnfulfilledAcProfile {
    /// The `acId` of the AC profile that could not be fulfilled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_id: Option<String>,
    /// One of [`unfulfill_reason`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl UnfulfilledAcProfile {
    /// An entry naming `ac_id` and `reason`.
    pub fn new(ac_id: &str, reason: &str) -> Self {
        Self {
            ac_id: Some(ac_id.to_string()),
            reason: Some(reason.to_string()),
        }
    }
}

impl EecRegistration {
    /// The `(eecCntxId, srcEesId)` pair that makes this registration a relocation
    /// (TS 29.558 §5.10), when both are present.
    ///
    /// Both or neither: a context id with no source EES names a context nobody can
    /// be asked for, and a source EES with no context id names no context. Treating
    /// either alone as a relocation would produce a pull request that cannot succeed.
    pub fn relocation_source(&self) -> Option<(&str, &str)> {
        match (self.eec_cntx_id.as_deref(), self.src_ees_id.as_deref()) {
            (Some(cntx), Some(ees)) if !cntx.is_empty() && !ees.is_empty() => Some((cntx, ees)),
            _ => None,
        }
    }

    /// Set the partial-fulfilment report, honouring NOTE 2 of TS 24.558 §5.2.2.2:
    /// the singular `unfulfilledAcProfs` **only** for exactly one entry, the
    /// `unfulfillAcProfs` array for two or more, and neither for none.
    ///
    /// Always clears the other member first. The two are mutually exclusive by
    /// `yaml:299-300`'s `not: required: [unfulfilledAcProfs, unfulfillAcProfs]`,
    /// so a body carrying both is invalid against the schema and a conformant EEC
    /// may reject it outright — which would turn a partial-fulfilment report into
    /// a failed registration.
    pub fn set_unfulfilled(&mut self, mut list: Vec<UnfulfilledAcProfile>) {
        self.unfulfill_ac_profs = None;
        self.unfulfilled_ac_profs = None;
        match list.len() {
            0 => {}
            1 => self.unfulfilled_ac_profs = Some(list.remove(0)),
            _ => self.unfulfill_ac_profs = Some(list),
        }
    }

    /// The partial-fulfilment report as a flat slice view, whichever member
    /// carries it. Lets a reader ask "what did the EES refuse?" without
    /// re-implementing the NOTE 2 split.
    pub fn unfulfilled(&self) -> Vec<&UnfulfilledAcProfile> {
        match (&self.unfulfilled_ac_profs, &self.unfulfill_ac_profs) {
            (Some(one), _) => vec![one],
            (None, Some(many)) => many.iter().collect(),
            (None, None) => Vec::new(),
        }
    }

    /// Validate the mandatory IEs (TS 24.558 §5.2.x). Returns `Err(detail)` when
    /// `eecId` (or any `acProfs[].acId`) is missing/empty.
    pub fn validate(&self) -> Result<(), String> {
        if self.eec_id.trim().is_empty() {
            return Err("Mandatory IE eecId is empty".to_string());
        }
        if let Some(profs) = &self.ac_profs {
            for p in profs {
                if p.ac_id.trim().is_empty() {
                    return Err("Mandatory IE acProfs[].acId is empty".to_string());
                }
            }
        }
        Ok(())
    }
}

/// TS 24.558 `ACProfile` (subset) — an Application Client profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcProfile {
    /// Application Client identifier (mandatory).
    pub ac_id: String,
    /// AC type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_type: Option<String>,
    /// `eass` — the EASes the AC needs, each with its KPI requirements
    /// (`yaml:331-336`, `minItems: 1`).
    ///
    /// This is the member the §5.2.2.2 matching rule is conditioned on: *"if
    /// `eass` attribute is included in the AC Profile, the EES identifies the
    /// matching EAS"*. The previous spelling was a bare `easIds: [String]`, which
    /// no conformant EEC sends and which cannot carry `minimumReqSvcKPIs` — so
    /// requirement (B) of that rule had nothing to read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eass: Option<Vec<EasDetail>>,
    /// `acSvcContSupp` — ACR scenarios the AC supports (`yaml:324-329`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_svc_cont_supp: Option<Vec<String>>,
    /// `expAcGeoServArea` — expected AC geographical service area (passthrough;
    /// the `LocationArea5G` model is deferred). Previously mis-spelled
    /// `expsacInfo`, which is not a member of `ACProfile`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_ac_geo_serv_area: Option<serde_json::Value>,
}

/// `EasDetail` (`TS24558_Eees_EECRegistration.yaml:354-366`) — one EAS an AC
/// needs, with the KPIs it expects and the KPIs it minimally requires.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EasDetail {
    /// Application identifier of the EAS (mandatory).
    pub eas_id: String,
    /// KPIs the AC expects. Per NOTE 1 of §5.2.2.2 how these bear on matching is
    /// implementation-defined, so this EES stores them and matches on
    /// `minimumReqSvcKPIs` only.
    ///
    /// Renamed explicitly: the spec spells the acronym `KPIs`, and `rename_all =
    /// "camelCase"` would emit `expectedSvcKpis`, which no conformant EEC sends.
    #[serde(rename = "expectedSvcKPIs", skip_serializing_if = "Option::is_none")]
    pub expected_svc_kpis: Option<AcServiceKpis>,
    /// KPIs the matching EAS must suffice — requirement (B) of §5.2.2.2 step 1 ii).
    /// Explicitly renamed for the same reason as `expectedSvcKPIs`.
    #[serde(rename = "minimumReqSvcKPIs", skip_serializing_if = "Option::is_none")]
    pub minimum_req_svc_kpis: Option<AcServiceKpis>,
}

/// `ACServiceKPIs` (`TS24558_Eees_EECRegistration.yaml:368-393`) — what the AC
/// asks of an EAS. The mirror-image of `types::EasServiceKpi`, which is what the
/// EAS advertises.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AcServiceKpis {
    /// Required connection bandwidth (`BitRate`, e.g. `"100 Mbps"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_band: Option<String>,
    /// Required request rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_rate: Option<u32>,
    /// Required response time (`DurationSec`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp_time: Option<u32>,
    /// Required availability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avail: Option<u32>,
    /// Required compute resources (free-form).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_comp: Option<String>,
    /// Required graphical compute resources (free-form).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_grap_comp: Option<String>,
    /// Required memory (free-form).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_mem: Option<String>,
    /// Required storage (free-form).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_strg: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eec_registration_deserialize_example() {
        let body = r#"{"eecId":"eec1.example.com","acProfs":[{"acId":"ac1","acType":"V2X"}]}"#;
        let reg: EecRegistration = serde_json::from_str(body).expect("deserializes");
        assert_eq!(reg.eec_id, "eec1.example.com");
        assert_eq!(reg.ac_profs.as_ref().unwrap()[0].ac_id, "ac1");
        assert!(reg.registration_id.is_none());
        assert!(reg.validate().is_ok());
    }

    #[test]
    fn test_eec_registration_missing_eec_id_fails() {
        // eecId absent → deserialization fails (handler maps to 400).
        let body = r#"{"acProfs":[{"acId":"ac1"}]}"#;
        assert!(serde_json::from_str::<EecRegistration>(body).is_err());
    }

    #[test]
    fn test_eec_registration_empty_eec_id_invalid() {
        let reg = EecRegistration {
            eec_id: "".into(),
            ue_id: None,
            ac_profs: None,
            exp_time: None,
            supp_feat: None,
            registration_id: None,
            ..Default::default()
        };
        assert!(reg.validate().is_err());
    }

    #[test]
    fn test_eec_registration_roundtrip_camelcase() {
        let reg = EecRegistration {
            eec_id: "eec1".into(),
            ue_id: Some("gpsi-12345".into()),
            ac_profs: Some(vec![AcProfile {
                ac_id: "ac1".into(),
                ac_type: Some("V2X".into()),
                eass: Some(vec![EasDetail {
                    eas_id: "eas1".into(),
                    minimum_req_svc_kpis: Some(AcServiceKpis {
                        resp_time: Some(20),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }]),
            exp_time: Some("2026-01-01T00:00:00Z".into()),
            supp_feat: Some("1".into()),
            registration_id: Some("reg-1".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"eecId\":\"eec1\""));
        assert!(json.contains("\"ueId\":\"gpsi-12345\""));
        assert!(json.contains("\"acProfs\""));
        assert!(json.contains("\"registrationId\""));
        assert!(
            json.contains("\"eass\""),
            "ACProfile.eass must be on the wire"
        );
        assert!(
            json.contains("\"minimumReqSvcKPIs\""),
            "matching rule (B) reads minimumReqSvcKPIs; got {json}"
        );
        let back: EecRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }

    /// #105 criterion 4: the six service-continuity / relocation IEs
    /// (`yaml:253-281`) survive a wire round trip under their spec spellings,
    /// plus `ueMobilityReq`/`ueType` from the same block.
    ///
    /// Deserializes from a hand-written spec-shaped body rather than from our own
    /// serialization: a `serialize -> deserialize` round trip of our own struct
    /// passes even when every field name is wrong, because both directions use the
    /// same (wrong) name. Only a hand-written body pins the spelling.
    #[test]
    fn relocation_ies_deserialize_from_a_spec_shaped_body() {
        let body = r#"{
            "eecId": "eec1.example.com",
            "eecSvcContSupp": ["SERVICE_CONTINUITY_SCENARIO_1"],
            "eecCntxId": "cntx-77",
            "srcEesId": "http://s-ees.example.com:8080",
            "endPt": {"fqdn": "eec1.example.com", "port": 9000},
            "easSelReqInd": true,
            "discoveredEas": [{"eas": {"easId": "eas1", "endPt": {"fqdn": "eas1.example.com"}}}],
            "ueMobilityReq": true,
            "ueType": "CONSTRAINED_UE"
        }"#;
        let reg: EecRegistration = serde_json::from_str(body).expect("deserializes");
        assert_eq!(
            reg.eec_svc_cont_supp.as_deref(),
            Some(&["SERVICE_CONTINUITY_SCENARIO_1".to_string()][..])
        );
        assert_eq!(reg.eec_cntx_id.as_deref(), Some("cntx-77"));
        assert_eq!(
            reg.src_ees_id.as_deref(),
            Some("http://s-ees.example.com:8080")
        );
        assert_eq!(
            reg.end_pt.as_ref().and_then(|e| e.fqdn.as_deref()),
            Some("eec1.example.com")
        );
        assert_eq!(reg.eas_sel_req_ind, Some(true));
        assert_eq!(
            reg.discovered_eas
                .as_ref()
                .map(|d| d[0].eas.eas_id.as_str()),
            Some("eas1"),
            "discoveredEas is an array of DiscoveredEas, whose required member is `eas`"
        );
        assert_eq!(reg.ue_mobility_req, Some(true));
        assert_eq!(reg.ue_type.as_deref(), Some("CONSTRAINED_UE"));
        // Both present and non-empty -> this registration is a relocation.
        assert_eq!(
            reg.relocation_source(),
            Some(("cntx-77", "http://s-ees.example.com:8080"))
        );
        // And it survives re-serialization under the same spellings.
        let json = serde_json::to_string(&reg).unwrap();
        for name in [
            "eecSvcContSupp",
            "eecCntxId",
            "srcEesId",
            "endPt",
            "easSelReqInd",
            "discoveredEas",
            "ueMobilityReq",
            "ueType",
        ] {
            assert!(
                json.contains(&format!("\"{name}\"")),
                "{name} missing: {json}"
            );
        }
    }

    /// `relocation_source` is both-or-neither: half a pair names a context nobody
    /// can be asked for, or a source EES holding no named context.
    #[test]
    fn a_half_present_relocation_pair_is_not_a_relocation() {
        let only_cntx = EecRegistration {
            eec_id: "eec1".into(),
            eec_cntx_id: Some("cntx-1".into()),
            ..Default::default()
        };
        assert_eq!(only_cntx.relocation_source(), None);
        let only_ees = EecRegistration {
            eec_id: "eec1".into(),
            src_ees_id: Some("ees-1".into()),
            ..Default::default()
        };
        assert_eq!(only_ees.relocation_source(), None);
        // Present-but-empty is absent: an empty string addresses nothing.
        let empty = EecRegistration {
            eec_id: "eec1".into(),
            eec_cntx_id: Some("".into()),
            src_ees_id: Some("ees-1".into()),
            ..Default::default()
        };
        assert_eq!(empty.relocation_source(), None);
    }

    /// NOTE 2 of TS 24.558 §5.2.2.2: the SINGULAR `unfulfilledAcProfs` only for
    /// exactly one entry, the array for two or more, never both, neither for none.
    #[test]
    fn set_unfulfilled_honours_note_2_and_never_sets_both_members() {
        let mut reg = EecRegistration {
            eec_id: "eec1".into(),
            ..Default::default()
        };

        reg.set_unfulfilled(vec![]);
        assert!(reg.unfulfilled_ac_profs.is_none());
        assert!(reg.unfulfill_ac_profs.is_none());
        assert!(reg.unfulfilled().is_empty());
        let json = serde_json::to_string(&reg).unwrap();
        assert!(
            !json.contains("unfulfil"),
            "a fully fulfilled registration must carry neither member; got {json}"
        );

        // Exactly one -> singular member ONLY.
        reg.set_unfulfilled(vec![UnfulfilledAcProfile::new(
            "ac1",
            unfulfill_reason::EAS_NOT_AVAILABLE,
        )]);
        assert!(
            reg.unfulfill_ac_profs.is_none(),
            "one entry must NOT use the array member (NOTE 2)"
        );
        assert_eq!(
            reg.unfulfilled_ac_profs.as_ref().unwrap().ac_id.as_deref(),
            Some("ac1")
        );
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"unfulfilledAcProfs\""), "{json}");
        assert!(!json.contains("\"unfulfillAcProfs\""), "{json}");

        // Two -> array member ONLY, and the singular one is cleared.
        reg.set_unfulfilled(vec![
            UnfulfilledAcProfile::new("ac1", unfulfill_reason::EAS_NOT_AVAILABLE),
            UnfulfilledAcProfile::new("ac2", unfulfill_reason::REQ_UNFULFILLED),
        ]);
        assert!(
            reg.unfulfilled_ac_profs.is_none(),
            "the singular member must be cleared when the array is used, or the \
             body violates yaml:299-300's mutual exclusion"
        );
        assert_eq!(reg.unfulfill_ac_profs.as_ref().unwrap().len(), 2);
        assert_eq!(
            reg.unfulfilled()
                .iter()
                .map(|u| u.ac_id.clone().unwrap_or_default())
                .collect::<Vec<_>>(),
            vec!["ac1", "ac2"]
        );
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"unfulfillAcProfs\""), "{json}");
        assert!(!json.contains("\"unfulfilledAcProfs\""), "{json}");

        // Back to none -> both cleared again.
        reg.set_unfulfilled(vec![]);
        assert!(reg.unfulfilled().is_empty());
    }
}
