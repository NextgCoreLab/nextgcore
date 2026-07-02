//! EES Edge Enabler Layer data model (TS 29.558 / TS 24.558).
//!
//! camelCase serde structs for the `eees-easregistration` service API. These
//! replace the bespoke flat JSON shape the EES previously parsed. Field naming
//! follows `TS29558_Eees_EASRegistration.yaml`.
//!
//! Scope note (bounded chunk eesd-02/03): the EAS Registration data model is
//! implemented here. The full fidelity of `ServiceArea` (TS 29.558
//! GeographicalServiceArea) and the discovery request/response model
//! (`EasDiscoveryReq`/`EasDiscoveryResp`, eesd-05) are intentionally DEFERRED;
//! nested geo/cell structures are carried as passthrough `serde_json::Value`.

use serde::{Deserialize, Serialize};

/// TS 29.558 §8.1.5.2.2 `EASRegistration`.
///
/// `easProf` is mandatory; `expTime` and `suppFeat` are optional/conditional.
/// `registrationId` is a server-assigned, read-only resource identifier
/// (TS 29.558 §5.2.2.2) carried in the response body and `Location` header — it
/// is distinct from the consumer-provided immutable `easProf.easId` (eesd-03).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasRegistration {
    /// EAS profile (mandatory).
    pub eas_prof: EasProfile,
    /// Registration expiration time (optional; absent ⇒ never expires).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features bitmask string (conditional, TS 29.558 §7.8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
    /// Server-minted resource identifier (read-only; never supplied by the
    /// consumer). Populated on registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
}

/// TS 29.558 §8.1.5.2.3 `EASProfile`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasProfile {
    /// EAS application identifier (URI/FQDN). Mandatory, consumer-provided,
    /// immutable (TS 29.558 §8.1.5.2.3, lines 6953-6956).
    pub eas_id: String,
    /// EAS endpoint (mandatory).
    pub end_pt: EndPoint,
    /// EAS provider identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov_id: Option<String>,
    /// EAS category/type (optional). Wire field name is `type`.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub eas_type: Option<String>,
    /// Vendor-specific flexible EAS type (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flex_eas_type: Option<String>,
    /// Application client identifiers served by this EAS (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_ids: Option<Vec<String>>,
    /// Service area the EAS serves (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svc_area: Option<ServiceArea>,
    /// Service KPIs (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svc_kpi: Option<EasServiceKpi>,
}

/// Common `EndPoint` type (TS 29.558). One of `uri`/`fqdn`/`ipv4Addrs`/
/// `ipv6Addrs` must be present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EndPoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_addrs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
}

impl EndPoint {
    /// True when no address form (uri/fqdn/ipv4/ipv6) is set — an `EndPoint`
    /// that carries no reachable address is not a valid mandatory IE.
    pub fn is_empty(&self) -> bool {
        self.uri.is_none()
            && self.fqdn.is_none()
            && self.ipv4_addrs.as_ref().is_none_or(|v| v.is_empty())
            && self.ipv6_addrs.as_ref().is_none_or(|v| v.is_empty())
    }
}

/// `EASServiceKPI` (TS 29.558 §8.1.5.x) — a representative subset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EasServiceKpi {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_req_rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_resp_time: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<u32>,
    /// Available compute (TS 29.558 `avlComp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_comp: Option<u32>,
    /// Available graphical compute (`avlGraComp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_gra_comp: Option<u32>,
    /// Available memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_mem: Option<u32>,
    /// Available storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avl_stor: Option<u32>,
    /// Connection bandwidth (`BitRate` string, e.g. "100 Mbps").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub con_bdwth: Option<String>,
}

/// `ServiceArea` (TS 29.558) — simplified subset. The full GeographicalService
/// Area / Ncgi / Tai models are DEFERRED (eesd-05/13); nested entries are
/// carried as passthrough JSON values to preserve the wire body losslessly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServiceArea {
    /// Tracking Area Identities (passthrough; full `Tai` model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tais: Option<Vec<serde_json::Value>>,
    /// NR Cell Global Identities (passthrough; full `Ncgi` model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ncgis: Option<Vec<serde_json::Value>>,
    /// Geographic area (passthrough; full `GeographicArea` model deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_area: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// eesd-05: EAS Discovery request/response/filter model (TS 24.558 §5.3).
// ---------------------------------------------------------------------------

/// TS 24.558 `EasDiscoveryReq` — body of `GetEASDiscInfo`
/// (`POST .../eas-profiles/request-discovery`).
///
/// `requestorId` is mandatory; `ueId`, `easDiscoveryFilter`, `locInf` and
/// `suppFeat` are optional. `locInf` is carried as passthrough JSON — fetching
/// UE location from the 5GC (NEF/GMLC) is DEFERRED (eesd-09).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasDiscoveryReq {
    /// Identifier of the entity requesting discovery (mandatory).
    pub requestor_id: String,
    /// Target UE identifier (GPSI/SUPI, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_id: Option<String>,
    /// Discovery filter (optional; absent ⇒ return all served EASs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_discovery_filter: Option<EasDiscoveryFilter>,
    /// UE location info (passthrough; NEF retrieval DEFERRED, eesd-09).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loc_inf: Option<serde_json::Value>,
    /// Supported features (optional, TS 29.558 §7.8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// TS 24.558 `EasDiscoveryFilter`.
///
/// NOTE (bounded scope): `easChars` is modelled as a single
/// `EASCharacteristics` object (matching the matched-stack shape and the
/// remediation acceptance `easDiscoveryFilter.easChars.easType`); the spec's
/// array cardinality is a documented simplification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EasDiscoveryFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_chars: Option<EasCharacteristics>,
}

impl EasDiscoveryFilter {
    /// True when `eas` satisfies this filter (an absent `easChars` matches all).
    pub fn matches(&self, eas: &EasProfile) -> bool {
        self.eas_chars.as_ref().is_none_or(|c| c.matches(eas))
    }
}

/// TS 24.558 `EASCharacteristics` — the discovery match criteria.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EasCharacteristics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_id: Option<String>,
    /// EAS category/type. Wire field is `easType`; `type` is accepted as an
    /// alias for compatibility with the matched-stack discovery body.
    #[serde(
        rename = "easType",
        alias = "type",
        skip_serializing_if = "Option::is_none"
    )]
    pub eas_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ac_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svc_area: Option<ServiceArea>,
}

impl EasCharacteristics {
    /// AND-combine each present criterion against `eas`.
    pub fn matches(&self, eas: &EasProfile) -> bool {
        if let Some(id) = &self.eas_id {
            if &eas.eas_id != id {
                return false;
            }
        }
        if let Some(t) = &self.eas_type {
            if eas.eas_type.as_deref() != Some(t.as_str()) {
                return false;
            }
        }
        if let Some(acs) = &self.ac_ids {
            if !acs.is_empty() {
                let eas_acs = eas.ac_ids.as_deref().unwrap_or(&[]);
                if !acs.iter().any(|a| eas_acs.contains(a)) {
                    return false;
                }
            }
        }
        if let Some(area) = &self.svc_area {
            match &eas.svc_area {
                Some(eas_area) => {
                    if !service_area_overlap(area, eas_area) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// Overlap test for two `ServiceArea`s: any shared TAI, any shared NCGI, or an
/// equal `geoArea`. The nested entries are compared as opaque JSON values
/// (the full `Tai`/`Ncgi`/`GeographicArea` models are passthrough, eesd-13).
pub fn service_area_overlap(a: &ServiceArea, b: &ServiceArea) -> bool {
    fn list_overlap(
        x: &Option<Vec<serde_json::Value>>,
        y: &Option<Vec<serde_json::Value>>,
    ) -> bool {
        match (x, y) {
            (Some(x), Some(y)) => x.iter().any(|e| y.contains(e)),
            _ => false,
        }
    }
    list_overlap(&a.tais, &b.tais)
        || list_overlap(&a.ncgis, &b.ncgis)
        || (a.geo_area.is_some() && a.geo_area == b.geo_area)
}

/// TS 24.558 `EasDiscoveryResp` — body of a successful `GetEASDiscInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasDiscoveryResp {
    /// Discovered EAS entries (mandatory; empty when nothing matches).
    pub discovered_eas: Vec<DiscoveredEas>,
    /// Negotiated supported features (echoed, eesd-11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// TS 24.558 `DiscoveredEAS` — one discovered EAS (full `EASProfile`, no
/// invented scoring).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredEas {
    pub eas: EasProfile,
}

/// TS 24.558 `EASDiscEventIDs` value: an EAS became available (a fresh
/// registration matching the subscription filter). The only discovery event
/// this EES emits today (`TS24558_Eees_EASDiscovery.yaml:664-679`).
pub const EAS_AVAILABILITY_CHANGE: &str = "EAS_AVAILABILITY_CHANGE";
/// TS 24.558 `EASDiscEventIDs` value: an EAS's dynamic information changed
/// (`TS24558_Eees_EASDiscovery.yaml:664-679`; modelled for completeness).
pub const EAS_DYNAMIC_INFO_CHANGE: &str = "EAS_DYNAMIC_INFO_CHANGE";

/// TS 24.558 `EasDiscoveryNotification`
/// (`TS24558_Eees_EASDiscovery.yaml:475-513`) — the callback body the EES POSTs
/// to a discovery subscription's `notificationUri` when a matching EAS changes.
///
/// Required IEs (yaml:510-513): `subId`, `eventType`, `discoveredEas`
/// (minItems 1). Cross-spec optional maps (`easInstInfos`, `edgeLoadAnalytics`)
/// are not emitted by this EES and are therefore omitted rather than
/// fabricated (the yaml marks them optional).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EasDiscoveryNotification {
    /// Identifier of the individual discovery subscription — the server-minted
    /// `subscriptionId` (yaml:479-483; REQUIRED).
    pub sub_id: String,
    /// The discovery event being reported (`EASDiscEventIDs`, yaml:484-485;
    /// REQUIRED, open-enum string).
    pub event_type: String,
    /// The discovered EAS entries (`DiscoveredEas`, yaml:486-491, minItems 1;
    /// REQUIRED).
    pub discovered_eas: Vec<DiscoveredEas>,
}

/// TS 24.558 `EASDiscoverySubscription` (subset) — discovery-change
/// subscription resource. `notificationUri` is mandatory; `subscriptionId`
/// and `expTime` are server-managed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EasDiscoverySubscription {
    /// Callback URI the EES POSTs discovery notifications to (mandatory).
    pub notification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requestor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_discovery_filter: Option<EasDiscoveryFilter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Server-minted resource identifier (read-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
}

impl EasDiscoverySubscription {
    /// True when this subscription's filter would select `eas`.
    pub fn filter_matches(&self, eas: &EasProfile) -> bool {
        self.eas_discovery_filter
            .as_ref()
            .is_none_or(|f| f.matches(eas))
    }
}

// ---------------------------------------------------------------------------
// eesd-11: SupportedFeatures negotiation + valid 3GPP ProblemDetails causes.
// ---------------------------------------------------------------------------

/// Feature bitmask the EES supports (TS 29.558 §7.8). Bit 0 is reserved here as
/// a representative negotiable feature so the negotiation path is exercised; no
/// optional *behaviour* is gated on it yet.
pub const EES_SUPPORTED_FEATURES: u64 = 0x1;

/// Negotiate the `suppFeat` to echo: the hex AND of the consumer's requested
/// mask and [`EES_SUPPORTED_FEATURES`]. Returns `None` when the consumer sent
/// no (or an unparseable) `suppFeat`, so it is omitted from the response.
pub fn negotiate_supp_feat(requested: Option<&str>) -> Option<String> {
    let req = requested?.trim();
    if req.is_empty() {
        return None;
    }
    let req_bits = u64::from_str_radix(req, 16).ok()?;
    Some(format!("{:x}", req_bits & EES_SUPPORTED_FEATURES))
}

/// Valid 3GPP `cause` values (TS 29.500 §5.2.7 / TS 29.571) for ProblemDetails.
pub mod cause {
    pub const MANDATORY_IE_MISSING: &str = "MANDATORY_IE_MISSING";
    pub const INVALID_MSG_FORMAT: &str = "INVALID_MSG_FORMAT";
    pub const MODIFICATION_NOT_ALLOWED: &str = "MODIFICATION_NOT_ALLOWED";
    pub const SUBSCRIPTION_NOT_FOUND: &str = "SUBSCRIPTION_NOT_FOUND";
    pub const INSUFFICIENT_RESOURCES: &str = "INSUFFICIENT_RESOURCES";
}

// ---------------------------------------------------------------------------
// eesd-04: RFC 7396 JSON merge-patch (used by PATCH update handlers).
// ---------------------------------------------------------------------------

/// Apply an RFC 7396 (`application/merge-patch+json`) `patch` onto `target`
/// in place. A `null` member removes the key; an object recurses; any other
/// value replaces.
pub fn apply_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    if let Value::Object(patch_map) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        let tmap = target.as_object_mut().expect("target coerced to object");
        for (k, v) in patch_map {
            if v.is_null() {
                tmap.remove(k);
            } else {
                let entry = tmap.entry(k.clone()).or_insert(Value::Null);
                apply_merge_patch(entry, v);
            }
        }
    } else {
        *target = patch.clone();
    }
}

// ---------------------------------------------------------------------------
// eesd-12: expTime (RFC 3339) parsing + epoch helpers for the lifecycle sweep.
// ---------------------------------------------------------------------------

/// Current wall-clock time as Unix epoch seconds.
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether `exp_time` (RFC 3339) is at/before `now_epoch`.
///
/// `None` ⇒ never expires (spec-sanctioned, TS 29.558 §8.1.5.2.2). An
/// unparseable timestamp is treated as never-expires (fail-open: do not drop a
/// registration we cannot evaluate).
pub fn is_expired(exp_time: Option<&str>, now_epoch: i64) -> bool {
    match exp_time {
        None => false,
        Some(s) => parse_rfc3339_to_epoch(s).is_some_and(|e| e <= now_epoch),
    }
}

/// Howard Hinnant's `days_from_civil`: days since 1970-01-01 for a proleptic
/// Gregorian (year, month, day).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse an RFC 3339 / ISO 8601 timestamp into Unix epoch seconds. Handles a
/// trailing `Z`, a numeric `±HH:MM`/`±HHMM` offset, and optional fractional
/// seconds (which are truncated). Returns `None` on a malformed input.
pub fn parse_rfc3339_to_epoch(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if s.len() < 19 {
        return None;
    }
    if b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    if !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    let mut rest = &s[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let n = stripped.bytes().take_while(u8::is_ascii_digit).count();
        rest = &stripped[n..];
    }
    let offset_secs: i64 = if rest.is_empty() || rest == "Z" || rest == "z" {
        0
    } else {
        let sign = match rest.as_bytes()[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let tz = &rest[1..];
        let (h, m) = if let Some((h, m)) = tz.split_once(':') {
            (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
        } else if tz.len() >= 4 {
            (tz.get(0..2)?.parse().ok()?, tz.get(2..4)?.parse().ok()?)
        } else {
            (tz.parse::<i64>().ok()?, 0)
        };
        sign * (h * 3600 + m * 60)
    };

    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + minute * 60 + second - offset_secs)
}

/// Format Unix epoch seconds as an RFC 3339 UTC timestamp (`...Z`).
pub fn epoch_to_rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(86400);
    let secs = epoch.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OpenAPI example body (eesd-02 acceptance) round-trips and exposes
    /// the mandatory `easProf.easId` / `easProf.endPt`.
    #[test]
    fn test_eas_registration_deserialize_example() {
        let body =
            r#"{"easProf":{"easId":"eas1.example.com","endPt":{"fqdn":"eas1.example.com"}}}"#;
        let reg: EasRegistration = serde_json::from_str(body).expect("example deserializes");
        assert_eq!(reg.eas_prof.eas_id, "eas1.example.com");
        assert_eq!(
            reg.eas_prof.end_pt.fqdn.as_deref(),
            Some("eas1.example.com")
        );
        assert!(reg.registration_id.is_none());
    }

    /// A body missing the mandatory `endPt` fails to deserialize (mapped to a
    /// 400 MANDATORY_IE_MISSING by the handler).
    #[test]
    fn test_eas_registration_missing_endpt_fails() {
        let body = r#"{"easProf":{"easId":"eas1.example.com"}}"#;
        assert!(serde_json::from_str::<EasRegistration>(body).is_err());
    }

    /// A body missing the mandatory `easProf` fails to deserialize.
    #[test]
    fn test_eas_registration_missing_easprof_fails() {
        let body = r#"{"expTime":"2026-01-01T00:00:00Z"}"#;
        assert!(serde_json::from_str::<EasRegistration>(body).is_err());
    }

    /// Serialization emits the spec camelCase field names (`easId`, `endPt`,
    /// `type`, `svcKpi`, `registrationId`).
    #[test]
    fn test_eas_registration_roundtrip_camelcase() {
        let reg = EasRegistration {
            eas_prof: EasProfile {
                eas_id: "eas1.example.com".into(),
                end_pt: EndPoint {
                    fqdn: Some("eas1.example.com".into()),
                    ..Default::default()
                },
                prov_id: Some("prov-7".into()),
                eas_type: Some("V2X".into()),
                flex_eas_type: None,
                ac_ids: Some(vec!["ac1".into()]),
                svc_area: None,
                svc_kpi: Some(EasServiceKpi {
                    availability: Some(99),
                    ..Default::default()
                }),
            },
            exp_time: None,
            supp_feat: Some("1".into()),
            registration_id: Some("11111111-2222-3333-4444-555555555555".into()),
        };
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"easId\":\"eas1.example.com\""));
        assert!(json.contains("\"endPt\""));
        assert!(json.contains("\"type\":\"V2X\""));
        assert!(json.contains("\"svcKpi\""));
        assert!(json.contains("\"registrationId\""));
        // Round-trips back to an equal value.
        let back: EasRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }

    #[test]
    fn test_endpoint_is_empty() {
        assert!(EndPoint::default().is_empty());
        assert!(!EndPoint {
            fqdn: Some("x".into()),
            ..Default::default()
        }
        .is_empty());
        assert!(EndPoint {
            ipv4_addrs: Some(vec![]),
            ..Default::default()
        }
        .is_empty());
    }

    fn profile(eas_id: &str, eas_type: &str) -> EasProfile {
        EasProfile {
            eas_id: eas_id.into(),
            end_pt: EndPoint {
                fqdn: Some(format!("{eas_id}.edge")),
                ..Default::default()
            },
            prov_id: None,
            eas_type: Some(eas_type.into()),
            flex_eas_type: None,
            ac_ids: Some(vec!["ac1".into(), "ac2".into()]),
            svc_area: None,
            svc_kpi: None,
        }
    }

    /// eesd-05: a `EasDiscoveryReq` deserializes and the filter matches by
    /// easId / easType / acIds.
    #[test]
    fn test_discovery_filter_matches() {
        let body = r#"{"requestorId":"eec-1","easDiscoveryFilter":{"easChars":{"easType":"V2X"}}}"#;
        let req: EasDiscoveryReq = serde_json::from_str(body).unwrap();
        assert_eq!(req.requestor_id, "eec-1");
        let filter = req.eas_discovery_filter.unwrap();
        assert!(filter.matches(&profile("eas1", "V2X")));
        assert!(!filter.matches(&profile("eas1", "AR")));

        // acIds intersection.
        let chars = EasCharacteristics {
            ac_ids: Some(vec!["ac2".into()]),
            ..Default::default()
        };
        assert!(chars.matches(&profile("eas1", "V2X")));
        let chars_miss = EasCharacteristics {
            ac_ids: Some(vec!["acX".into()]),
            ..Default::default()
        };
        assert!(!chars_miss.matches(&profile("eas1", "V2X")));
    }

    /// eesd-05: the legacy `type` alias still deserializes into `easType`.
    #[test]
    fn test_discovery_filter_type_alias() {
        let body = r#"{"easChars":{"type":"AR"}}"#;
        let filter: EasDiscoveryFilter = serde_json::from_str(body).unwrap();
        assert_eq!(filter.eas_chars.unwrap().eas_type.as_deref(), Some("AR"));
    }

    /// eesd-05: service-area overlap (shared TAI) gates discovery.
    #[test]
    fn test_service_area_overlap() {
        let a = ServiceArea {
            tais: Some(vec![serde_json::json!({"tac":"000001"})]),
            ..Default::default()
        };
        let b = ServiceArea {
            tais: Some(vec![serde_json::json!({"tac":"000001"})]),
            ..Default::default()
        };
        let c = ServiceArea {
            tais: Some(vec![serde_json::json!({"tac":"000002"})]),
            ..Default::default()
        };
        assert!(service_area_overlap(&a, &b));
        assert!(!service_area_overlap(&a, &c));
    }

    /// eesd-11: suppFeat is the hex intersection of requested & EES-supported.
    #[test]
    fn test_negotiate_supp_feat() {
        assert_eq!(negotiate_supp_feat(Some("1")).as_deref(), Some("1"));
        // requested bit 1 not supported → masked out.
        assert_eq!(negotiate_supp_feat(Some("3")).as_deref(), Some("1"));
        assert_eq!(negotiate_supp_feat(Some("2")).as_deref(), Some("0"));
        assert_eq!(negotiate_supp_feat(None), None);
        assert_eq!(negotiate_supp_feat(Some("")), None);
    }

    /// eesd-04: RFC 7396 merge-patch replaces, recurses, and removes (null).
    #[test]
    fn test_apply_merge_patch() {
        let mut target = serde_json::json!({
            "easProf": {"easId": "eas1", "type": "V2X", "provId": "p1"},
            "expTime": "2026-01-01T00:00:00Z"
        });
        let patch = serde_json::json!({
            "easProf": {"type": "AR", "provId": null},
            "expTime": "2027-01-01T00:00:00Z"
        });
        apply_merge_patch(&mut target, &patch);
        assert_eq!(target["easProf"]["type"], "AR");
        assert_eq!(target["easProf"]["easId"], "eas1"); // untouched
        assert!(target["easProf"].get("provId").is_none()); // removed by null
        assert_eq!(target["expTime"], "2027-01-01T00:00:00Z");
    }

    /// eesd-12: RFC 3339 parsing round-trips and `is_expired` honours
    /// absent = never-expires.
    #[test]
    fn test_exp_time_parse_and_expiry() {
        let e = parse_rfc3339_to_epoch("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(e, 0);
        let e2 = parse_rfc3339_to_epoch("2000-01-01T00:00:00Z").unwrap();
        assert_eq!(e2, 946_684_800);
        // Offset handling: +01:00 is one hour earlier in UTC.
        assert_eq!(
            parse_rfc3339_to_epoch("2000-01-01T01:00:00+01:00").unwrap(),
            946_684_800
        );
        // Fractional seconds are tolerated.
        assert_eq!(
            parse_rfc3339_to_epoch("2000-01-01T00:00:00.500Z").unwrap(),
            946_684_800
        );
        assert!(parse_rfc3339_to_epoch("not-a-date").is_none());

        assert!(is_expired(Some("2000-01-01T00:00:00Z"), 946_684_801));
        assert!(!is_expired(Some("2000-01-01T00:00:00Z"), 946_684_799));
        assert!(!is_expired(None, 946_684_800)); // never expires
        assert!(!is_expired(Some("garbage"), i64::MAX)); // fail-open
    }

    /// eesd-12: epoch ↔ RFC 3339 round-trips for a representative instant.
    #[test]
    fn test_epoch_to_rfc3339_roundtrip() {
        let s = epoch_to_rfc3339(946_684_800);
        assert_eq!(s, "2000-01-01T00:00:00Z");
        let back = parse_rfc3339_to_epoch(&s).unwrap();
        assert_eq!(back, 946_684_800);
    }
}
