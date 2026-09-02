//! Wave-6 E3 strict-peer test: pcfd's REAL URSP rule source (UDR ue-policy-set)
//! against udrd's REAL persistence — no lenient JSON mock of the UDR.
//!
//! udrd's SBI dispatch (`udr_sbi_request_handler`) is crate-private, but its
//! ue-policy-set PUT/GET handler delegates to the PUBLIC data_store
//! (`nextgcore_udrd::data_store::store().policy_ue_put/get` — main.rs:1327/1272);
//! that store IS the real udrd persistence. This test round-trips the operator
//! provisioning document through it and drives pcfd's REAL mapping + E2 encoder
//! (`resolve_ursp_rules` / `map_ue_policy_set_to_rules` /
//! `build_manage_ue_policy_command`), asserting the delivered MANAGE UE POLICY
//! COMMAND bytes byte-exactly match the E3 golden vector. The HTTP GET wiring
//! (`pcf_udr_get_ue_policy_set`) is covered separately by the mock-NRF/UDR unit
//! test in `sbi_path.rs` (`discover_and_send_udr_mock`).
//!
//! Specs: TS 29.519 §5.4 UePolicySet (`GET /nudr-dr/v2/policy-data/ues/{ueId}/
//! ue-policy-set`); TS 23.503 §6.6.2.2 (URSP configuration/provision);
//! TS 24.501 Table D.5.1.1.1 (MANAGE UE POLICY COMMAND) + TS 24.526 §5.2 (URSP
//! contents).
//!
//! Falsifiable acceptance (E3): with a provisioned ue-policy-set the delivered
//! command reflects the provisioned DNN/S-NSSAI (== E3 golden); with none the
//! static default (== E1(f)) is delivered; with a malformed doc the fallback
//! fires (== E1(f)) and the error names the offending component.

use nextgcore_pcfd::ue_policy::{
    build_manage_ue_policy_command, map_ue_policy_set_to_rules, resolve_ursp_rules,
};
use nextgcore_udrd::data_store;
use serde_json::json;

/// E3 golden vector, re-cited verbatim from the pcfd unit-test copy
/// (`ue_policy.rs::VEC_IMS_MANAGE_UE_POLICY_COMMAND`). PTI 0x80, PLMN 001-01,
/// UPSC 1, one URSP part = the E1 vector (b) DNN-ims rule.
const VEC_IMS: &[u8] = &[
    0x80, 0x01, 0x00, 0x2D, 0x00, 0x2B, 0x00, 0xF1, 0x10, 0x00, 0x26, 0x00, 0x01, 0x00, 0x22, 0x01,
    0x00, 0x1F, 0x0A, 0x00, 0x06, 0x88, 0x04, 0x03, 0x69, 0x6D, 0x73, 0x00, 0x14, 0x00, 0x12, 0x0A,
    0x00, 0x0F, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x04, 0x03, 0x69, 0x6D, 0x73, 0x08, 0x03, 0x10,
    0x01,
];

/// E1 golden vector (f) — the static catch-all default command, re-cited
/// verbatim (delivered when no provisioning / a malformed doc is present).
const VEC_F: &[u8] = &[
    0x80, 0x01, 0x00, 0x2B, 0x00, 0x29, 0x00, 0xF1, 0x10, 0x00, 0x24, 0x00, 0x01, 0x00, 0x20, 0x01,
    0x00, 0x1D, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x17, 0x00, 0x15, 0xFF, 0x00, 0x12, 0x01, 0x01, 0x02,
    0x01, 0x01, 0x04, 0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, 0x08, 0x03,
];

/// The documented `urspRules` provisioning extension mapping to the DNN "ims"
/// rule (mirrors the pcfd unit-test doc; independence is fine — the golden
/// vector is the shared contract).
fn provisioned_ims_doc() -> serde_json::Value {
    json!({
        "subscPolicySections": {},
        "urspRules": [{
            "precedence": 10,
            "trafficDescriptor": { "dnn": "ims" },
            "routeSelectionDescriptors": [{
                "precedence": 10, "sscMode": 1, "snssai": {"sst": 1},
                "dnn": "ims", "pduSessionType": "ipv4v6", "preferredAccess": "3gpp"
            }]
        }]
    })
}

/// E3 primary acceptance: a UePolicySet PUT through udrd's REAL data_store, read
/// back through it, and compiled by pcfd's REAL pipeline == the E3 golden
/// command vector (reflects the provisioned DNN "ims" / S-NSSAI SST=1).
#[test]
fn provisioned_via_real_udrd_store_matches_golden() {
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("PCF_URSP_RULES");
    let supi = "imsi-001010000003001";
    let ds = data_store::store();

    // PUT: the exact persistence udrd's ue-policy-set PUT handler delegates to.
    let created = ds.policy_ue_put(supi, provisioned_ims_doc());
    assert!(created, "first PUT creates the ue-policy-set");

    // GET: exactly what udrd's ue-policy-set GET handler returns for a stored doc.
    let stored = ds.policy_ue_get(supi).expect("udrd returns the stored doc");

    // pcfd's REAL mapping + E2 encoder.
    let rules = map_ue_policy_set_to_rules(&stored)
        .expect("provisioned doc maps")
        .expect("urspRules present");
    let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules)
        .expect("provisioned command encodes");
    assert_eq!(
        bytes, VEC_IMS,
        "provisioned MANAGE UE POLICY COMMAND must be byte-exact E3 golden vector"
    );
    // Proves the provisioned source changed the wire artifact vs the default.
    assert_ne!(
        bytes, VEC_F,
        "provisioned command must differ from the catch-all default"
    );
}

/// No provisioning for a SUPI → pcfd delivers the static default (E1(f)).
#[test]
fn no_provisioning_delivers_static_default() {
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("PCF_URSP_RULES");
    let supi = "imsi-001010000003002";
    let ds = data_store::store();
    // udrd's GET for an unprovisioned SUPI yields no stored doc (derived
    // default carries no urspRules extension → pcfd falls back to static).
    let stored = ds.policy_ue_get(supi);
    let rules = resolve_ursp_rules(stored.as_ref());
    let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules).expect("encode");
    assert_eq!(
        bytes, VEC_F,
        "no provisioning → static catch-all default (E1(f))"
    );
}

/// A malformed provisioning doc round-tripped through udrd's REAL store → pcfd
/// falls back to the static default (E1(f)) and the map error names the
/// offending component (grep-able WARN source).
#[test]
fn malformed_provisioning_falls_back_via_real_store() {
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("PCF_URSP_RULES");
    let supi = "imsi-001010000003003";
    let ds = data_store::store();
    ds.policy_ue_put(
        supi,
        json!({
            "urspRules": [{
                "precedence": 1,
                "trafficDescriptor": { "dnn": "ims" },
                "routeSelectionDescriptors": [{ "precedence": 1, "pduSessionType": "carrier-pigeon" }]
            }]
        }),
    );
    let stored = ds.policy_ue_get(supi).expect("stored");
    let err = map_ue_policy_set_to_rules(&stored).expect_err("malformed urspRules must err");
    assert!(
        err.contains("carrier-pigeon"),
        "error must name the component: {err}"
    );
    let rules = resolve_ursp_rules(Some(&stored));
    let bytes = build_manage_ue_policy_command(0x80, 1, "001", "01", &rules).expect("encode");
    assert_eq!(
        bytes, VEC_F,
        "malformed provisioning → static default fallback (E1(f))"
    );
}
