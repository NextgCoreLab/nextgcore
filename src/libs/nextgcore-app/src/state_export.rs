//! Aggregate read-only network-state snapshot (issue #25, `6g-extensions`).
//!
//! Digital-twin foundation: composes the state the NRF and NSACF **already
//! persist to JSON on disk** into one project-defined
//! [`NetworkStateSnapshot`] document. Non-normative: no frozen Rel-20/6G
//! Stage-3 "network digital twin" spec exists; the underlying data models
//! are TS 29.510 (NRF NFProfile) and TS 29.536 (NSACF slice quotas), which
//! the source snapshots already follow.
//!
//! Offline aggregator only: it reads the files written by
//! `nextgcore-nrfd --state-file` (or `NEXTGCORE_NRF_STATE_FILE`) and
//! `nextgcore-nsacfd --state-file`. No live SBI plumbing, no SMF/UPF
//! session enumeration (see [`SessionSummary::note`]), no listening socket.
//! See `docs/network-state-snapshot.md`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The documented `session_summary.note` limitation text.
const SESSION_SUMMARY_NOTE: &str = "UE and PDU-session counts are per-slice \
    admission counters from the persisted NSACF state doc; live per-session \
    SMF/UPF enumeration is a follow-up and is NOT included — no session list \
    is fabricated.";

/// Error building a [`NetworkStateSnapshot`] from persisted state files.
#[derive(Debug, thiserror::Error)]
pub enum StateExportError {
    /// A state file could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A state file was not valid JSON.
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

/// One registered NF instance, distilled from a persisted NRF NFProfile
/// (TS 29.510). `profile` carries the full persisted document verbatim
/// (camelCase wire keys) so nothing is lost by the distillation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NfRegistrationEntry {
    pub nf_instance_id: String,
    pub nf_type: String,
    /// Live status as persisted (e.g. `REGISTERED`, `SUSPENDED`).
    pub nf_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv4_addresses: Vec<String>,
    /// `serviceName`s collected from the profile's `nfServices`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_names: Vec<String>,
    /// The persisted NFProfile document, verbatim.
    pub profile: serde_json::Value,
}

/// One slice quota row from the persisted NSACF state doc (TS 29.536 data).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SliceQuotaEntry {
    pub sst: u8,
    /// Slice differentiator as the NSACF persists it (raw number, not the
    /// 6-hex-digit wire string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd: Option<u32>,
    pub max_ues: u64,
    pub max_pdu_sessions: u64,
    /// Live admitted-UE count (length of the persisted `ues` membership set).
    pub current_ues: u64,
    /// Live PDU-session count (length of the persisted `pduSessions` set).
    pub current_pdu_sessions: u64,
    pub eac_active: bool,
}

/// Per-slice session counters distilled from the NSACF admission state,
/// plus the honest limitation note.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Sum of admitted UEs across all slices.
    pub total_ues: u64,
    /// Sum of active PDU sessions across all slices.
    pub total_pdu_sessions: u64,
    /// Documented limitation of this first cut (no live SMF/UPF data).
    pub note: String,
}

/// The aggregate, read-only, project-defined network-state snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkStateSnapshot {
    /// Capture wall-clock time, ms since the Unix epoch.
    pub captured_at_ms: u64,
    /// Registered NF instances from the persisted NRF snapshot doc.
    pub nf_registrations: Vec<NfRegistrationEntry>,
    /// Slice quotas + live admission counters from the NSACF state doc.
    pub slice_quotas: Vec<SliceQuotaEntry>,
    /// Session counters derived from the slice quotas (see `note`).
    pub session_summary: SessionSummary,
}

impl NetworkStateSnapshot {
    /// Build a snapshot from the two persisted state files
    /// (`nextgcore-nrfd --state-file`, `nextgcore-nsacfd --state-file`).
    pub fn from_persisted(
        nrf_state_path: &Path,
        nsacf_state_path: &Path,
    ) -> Result<Self, StateExportError> {
        let nrf_doc = read_json(nrf_state_path)?;
        let nsacf_doc = read_json(nsacf_state_path)?;
        Ok(Self::from_docs(&nrf_doc, &nsacf_doc))
    }

    /// Pure merge of an already-parsed NRF snapshot doc and NSACF state doc
    /// (the testable core; malformed entries are skipped, mirroring the
    /// NRF's own lenient `restore_from`).
    pub fn from_docs(nrf_doc: &serde_json::Value, nsacf_doc: &serde_json::Value) -> Self {
        let nf_registrations = parse_nrf_profiles(nrf_doc);
        let slice_quotas = parse_nsacf_quotas(nsacf_doc);
        let session_summary = SessionSummary {
            total_ues: slice_quotas.iter().map(|q| q.current_ues).sum(),
            total_pdu_sessions: slice_quotas.iter().map(|q| q.current_pdu_sessions).sum(),
            note: SESSION_SUMMARY_NOTE.to_string(),
        };
        Self {
            captured_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            nf_registrations,
            slice_quotas,
            session_summary,
        }
    }
}

fn read_json(path: &Path) -> Result<serde_json::Value, StateExportError> {
    let content = std::fs::read_to_string(path).map_err(|source| StateExportError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&content).map_err(|source| StateExportError::Parse {
        path: path.display().to_string(),
        source,
    })
}

/// Distill `{ "version", "profiles": [NFProfile...] }` (the doc
/// `NfInstanceManager::persist` writes). Profiles missing the mandatory
/// `nfInstanceId`/`nfType`/`nfStatus` string trio are skipped, like the
/// NRF's own restore path.
fn parse_nrf_profiles(nrf_doc: &serde_json::Value) -> Vec<NfRegistrationEntry> {
    let Some(profiles) = nrf_doc.get("profiles").and_then(|p| p.as_array()) else {
        return Vec::new();
    };
    profiles
        .iter()
        .filter_map(|p| {
            let get_str = |k: &str| {
                p.get(k)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            };
            let (Some(nf_instance_id), Some(nf_type), Some(nf_status)) = (
                get_str("nfInstanceId"),
                get_str("nfType"),
                get_str("nfStatus"),
            ) else {
                log::warn!(
                    "state_export: skipping malformed persisted NFProfile \
                     (missing nfInstanceId/nfType/nfStatus)"
                );
                return None;
            };
            let entry = NfRegistrationEntry {
                nf_instance_id,
                nf_type,
                nf_status,
                fqdn: get_str("fqdn"),
                ipv4_addresses: str_array(p.get("ipv4Addresses")),
                service_names: p
                    .get("nfServices")
                    .and_then(|s| s.as_array())
                    .map(|svcs| {
                        svcs.iter()
                            .filter_map(|s| s.get("serviceName").and_then(|n| n.as_str()))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                profile: p.clone(),
            };
            Some(entry)
        })
        .collect()
}

/// Distill `{ "nextQuotaId", "quotas": [...] }` (the doc the NSACF's
/// `save_state` writes). Counters are membership-derived: `ues` /
/// `pduSessions` array lengths.
fn parse_nsacf_quotas(nsacf_doc: &serde_json::Value) -> Vec<SliceQuotaEntry> {
    let Some(quotas) = nsacf_doc.get("quotas").and_then(|q| q.as_array()) else {
        return Vec::new();
    };
    quotas
        .iter()
        .filter_map(|q| {
            let Some(sst) = q
                .get("sst")
                .and_then(|v| v.as_u64())
                .and_then(|v| u8::try_from(v).ok())
            else {
                log::warn!(
                    "state_export: skipping malformed NSACF quota row (missing/invalid \
                     sst); its UE/PDU counts are excluded from session_summary totals"
                );
                return None;
            };
            let entry = SliceQuotaEntry {
                sst,
                // try_from, not `as`: an out-of-range sd from a corrupted file
                // must become None, never a silently wrapped wrong value.
                sd: q
                    .get("sd")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok()),
                max_ues: q.get("maxUes").and_then(|v| v.as_u64()).unwrap_or(0),
                max_pdu_sessions: q
                    .get("maxPduSessions")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                current_ues: array_len(q.get("ues")),
                current_pdu_sessions: array_len(q.get("pduSessions")),
                eac_active: q
                    .get("eacActive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };
            Some(entry)
        })
        .collect()
}

fn str_array(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn array_len(v: Option<&serde_json::Value>) -> u64 {
    v.and_then(|v| v.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0)
}

/// Group registrations by NF type (convenience for consumers/UIs).
pub fn registrations_by_type(
    snapshot: &NetworkStateSnapshot,
) -> BTreeMap<String, Vec<&NfRegistrationEntry>> {
    let mut map: BTreeMap<String, Vec<&NfRegistrationEntry>> = BTreeMap::new();
    for r in &snapshot.nf_registrations {
        map.entry(r.nf_type.clone()).or_default().push(r);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_nrf_doc() -> serde_json::Value {
        json!({
            "version": 1,
            "profiles": [
                {
                    "nfInstanceId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "nfType": "AMF",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                    "plmnList": [{"mcc": "001", "mnc": "01"}],
                    "ipv4Addresses": ["10.0.0.3"],
                    "fqdn": "amf.example.com",
                    "nfServices": [{
                        "serviceInstanceId": "amf-svc-1",
                        "serviceName": "namf-comm",
                        "versions": [{"apiVersionInUri": "v1"}],
                        "scheme": "http",
                        "ipEndPoints": [{"ipv4Address": "10.0.0.3", "port": 7777}]
                    }]
                },
                {
                    "nfInstanceId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    "nfType": "SMF",
                    "nfStatus": "SUSPENDED",
                    "ipv4Addresses": ["10.0.0.5"],
                    "nfServices": [{
                        "serviceInstanceId": "smf-svc-1",
                        "serviceName": "nsmf-pdusession",
                        "versions": ["v1"],
                        "scheme": "http"
                    }]
                },
                { "nfType": "UPF", "nfStatus": "REGISTERED" }
            ],
            "subscriptions": []
        })
    }

    fn fixture_nsacf_doc() -> serde_json::Value {
        json!({
            "nextQuotaId": 3,
            "quotas": [
                {
                    "id": 1,
                    "sst": 1,
                    "sd": 66051,
                    "maxUes": 100,
                    "maxPduSessions": 500,
                    "maxUes3gpp": 80,
                    "maxUesN3gpp": 20,
                    "maxPdu3gpp": null,
                    "maxPduN3gpp": null,
                    "ues": ["imsi-001010000000001", "imsi-001010000000002"],
                    "pduSessions": ["imsi-001010000000001:1"],
                    "uesAccess": {
                        "imsi-001010000000001": "3GPP_ACCESS",
                        "imsi-001010000000002": "NON_3GPP_ACCESS"
                    },
                    "pduSessionsAccess": {"imsi-001010000000001:1": "3GPP_ACCESS"},
                    "eacActive": false
                },
                {
                    "id": 2,
                    "sst": 2,
                    "sd": null,
                    "maxUes": 10,
                    "maxPduSessions": 20,
                    "maxUes3gpp": null,
                    "maxUesN3gpp": null,
                    "maxPdu3gpp": null,
                    "maxPduN3gpp": null,
                    "ues": [],
                    "pduSessions": [],
                    "uesAccess": {},
                    "pduSessionsAccess": {},
                    "eacActive": true
                }
            ]
        })
    }

    /// Issue #25 acceptance: fixture NRF + NSACF docs yield the expected NF
    /// instances and slice quotas; session_summary carries the honest note.
    #[test]
    fn from_docs_merges_fixture_state() {
        let snap = NetworkStateSnapshot::from_docs(&fixture_nrf_doc(), &fixture_nsacf_doc());

        // Malformed third profile (no nfInstanceId) is skipped, like the
        // NRF's own restore path.
        assert_eq!(snap.nf_registrations.len(), 2);
        let amf = &snap.nf_registrations[0];
        assert_eq!(amf.nf_instance_id, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        assert_eq!(amf.nf_type, "AMF");
        assert_eq!(amf.nf_status, "REGISTERED");
        assert_eq!(amf.fqdn.as_deref(), Some("amf.example.com"));
        assert_eq!(amf.ipv4_addresses, vec!["10.0.0.3"]);
        assert_eq!(amf.service_names, vec!["namf-comm"]);
        assert_eq!(amf.profile["heartBeatTimer"], 10);
        let smf = &snap.nf_registrations[1];
        assert_eq!(smf.nf_type, "SMF");
        assert_eq!(smf.nf_status, "SUSPENDED");
        assert_eq!(smf.service_names, vec!["nsmf-pdusession"]);

        assert_eq!(snap.slice_quotas.len(), 2);
        let s1 = &snap.slice_quotas[0];
        assert_eq!((s1.sst, s1.sd), (1, Some(66051)));
        assert_eq!((s1.max_ues, s1.max_pdu_sessions), (100, 500));
        assert_eq!((s1.current_ues, s1.current_pdu_sessions), (2, 1));
        assert!(!s1.eac_active);
        let s2 = &snap.slice_quotas[1];
        assert_eq!((s2.sst, s2.sd), (2, None));
        assert!(s2.eac_active);

        assert_eq!(snap.session_summary.total_ues, 2);
        assert_eq!(snap.session_summary.total_pdu_sessions, 1);
        assert!(snap.session_summary.note.contains("follow-up"));
        assert!(snap.session_summary.note.contains("NOT included"));

        let by_type = registrations_by_type(&snap);
        assert_eq!(by_type["AMF"].len(), 1);
        assert_eq!(by_type["SMF"].len(), 1);
    }

    /// Issue #25 acceptance: NetworkStateSnapshot round-trips through serde.
    #[test]
    fn network_state_snapshot_serde_round_trip() {
        let snap = NetworkStateSnapshot::from_docs(&fixture_nrf_doc(), &fixture_nsacf_doc());
        let text = serde_json::to_string_pretty(&snap).expect("serialize");
        let back: NetworkStateSnapshot = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(snap, back);
    }

    /// Issue #25 acceptance: NfStateSnapshot (nf_hooks) round-trips through
    /// serde now that the derives exist.
    #[test]
    fn nf_state_snapshot_serde_round_trip() {
        let snap = crate::nf_hooks::NfStateSnapshot {
            nf_instance_id: "amf-1".to_string(),
            nf_type: "AMF".to_string(),
            timestamp_ms: 1_700_000_000_000,
            status: crate::nf_hooks::NfStatus::Registered,
            load: 0.6,
            active_sessions: 100,
            cpu_utilization: 0.4,
            memory_utilization: 0.5,
            kpis: std::collections::HashMap::from([("ue_count".to_string(), 42.0)]),
        };
        let text = serde_json::to_string(&snap).expect("serialize");
        let back: crate::nf_hooks::NfStateSnapshot = serde_json::from_str(&text).expect("parse");
        assert_eq!(back.nf_instance_id, snap.nf_instance_id);
        assert_eq!(back.status, snap.status);
        assert_eq!(back.kpis["ue_count"], 42.0);
    }

    #[test]
    fn missing_or_empty_sections_yield_empty_snapshot() {
        let snap = NetworkStateSnapshot::from_docs(&json!({}), &json!({}));
        assert!(snap.nf_registrations.is_empty());
        assert!(snap.slice_quotas.is_empty());
        assert_eq!(snap.session_summary.total_ues, 0);
        assert!(snap.session_summary.note.contains("follow-up"));
    }

    #[test]
    fn corrupt_rows_are_skipped_not_wrapped() {
        let doc = json!({ "quotas": [
            { "id": 9, "sst": 300, "maxUes": 5, "maxPduSessions": 5,
              "ues": ["imsi-x"], "pduSessions": [], "eacActive": false },
            { "id": 10, "sst": 3, "sd": 4_294_967_297u64, "maxUes": 5, "maxPduSessions": 5,
              "ues": [], "pduSessions": [], "eacActive": false }
        ]});
        let snap = NetworkStateSnapshot::from_docs(&json!({}), &doc);
        // The sst-300 row is skipped wholesale (its UE count excluded from
        // the totals); an out-of-range sd becomes None, never a silently
        // wrapped wrong value.
        assert_eq!(snap.slice_quotas.len(), 1);
        assert_eq!(snap.slice_quotas[0].sst, 3);
        assert_eq!(snap.slice_quotas[0].sd, None);
        assert_eq!(snap.session_summary.total_ues, 0);
    }

    #[test]
    fn from_persisted_reads_fixture_files() {
        // Unique-per-test temp names (same-pid parallel tests race on a
        // shared name — the pqc-tls lesson), cleaned up at the end.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let nrf_path = dir.join(format!("nextgcore-app-issue25-nrf-{pid}.json"));
        let nsacf_path = dir.join(format!("nextgcore-app-issue25-nsacf-{pid}.json"));
        std::fs::write(&nrf_path, fixture_nrf_doc().to_string()).expect("write nrf");
        std::fs::write(&nsacf_path, fixture_nsacf_doc().to_string()).expect("write nsacf");

        let snap = NetworkStateSnapshot::from_persisted(&nrf_path, &nsacf_path).expect("build");
        assert_eq!(snap.nf_registrations.len(), 2);
        assert_eq!(snap.slice_quotas.len(), 2);
        assert!(snap.captured_at_ms > 0);

        let err = NetworkStateSnapshot::from_persisted(
            &dir.join(format!("nextgcore-app-issue25-missing-{pid}.json")),
            &nsacf_path,
        )
        .expect_err("missing file must error");
        assert!(matches!(err, StateExportError::Io { .. }));

        let _ = std::fs::remove_file(&nrf_path);
        let _ = std::fs::remove_file(&nsacf_path);
    }
}
