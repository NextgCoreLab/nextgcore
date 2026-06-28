//! External byte-equality test vectors for the NAS codec (ogs-nas).
//!
//! Two classes of vectors are provided:
//!
//! ## Spec-derived vectors (TS 24.501 byte tables)
//!
//! Hand-encoded from 3GPP TS 24.501 normative byte tables.  Each vector:
//!   1. Decodes the raw bytes and asserts specific **field values** (message
//!      type, cause, PLMN, etc.) — guarding against the self-validation trap.
//!   2. Re-encodes the decoded message and asserts byte-equality against the
//!      original vector.
//!
//! Vectors that could not be hand-derived with full confidence are OMITTED
//! rather than shipped as guesses (see "OMITTED" comments below).
//!
//! ## References
//! - 3GPP TS 24.501 v18.4.0 — 5GS NAS protocol
//! - 3GPP TS 24.301 v18.4.0 — EPS NAS protocol

use bytes::Bytes;
use ogs_nas::eps::*;
use ogs_nas::fiveg::*;

// ============================================================================
// Helper: hex literal → Bytes
// ============================================================================

/// Convert a compile-time hex string (no spaces) into owned Bytes for decoding.
/// Retained for future hand-derived vectors; not all are wired up yet.
#[allow(unused_macros)]
macro_rules! hex_bytes {
    ($s:expr) => {{
        let s: &str = $s;
        assert!(s.len() % 2 == 0, "hex string must have even length");
        let mut v = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = char::from(bytes[i]).to_digit(16).expect("valid hex") as u8;
            let lo = char::from(bytes[i + 1]).to_digit(16).expect("valid hex") as u8;
            v.push((hi << 4) | lo);
            i += 2;
        }
        Bytes::from(v)
    }};
}

// ============================================================================
// Spec-derived 5GMM vectors  (TS 24.501)
// ============================================================================

/// Vector SV-NAS-01: 5GMM Registration Reject
///
/// Source: TS 24.501 §8.2.7 (Registration reject message format).
///
/// Wire bytes (plain NAS, EPD=0x7E, SH=0x00, MT=0x44):
///   7E 00 44 76
///   MT 0x44 = Registration Reject  (Table 9.7.1)
///   IE 0x76 = 5GMM Cause, value 0x0B = PLMN not allowed  (Table 9.11.3.2.1)
///
/// Fields asserted:
///   - message type byte = 0x44
///   - gmm_cause = 0x0B (PLMN not allowed, TS 24.501 §9.11.3.2)
#[test]
fn sv_nas_01_registration_reject_plmn_not_allowed() {
    // TS 24.501 §8.2.7: Registration reject
    // Byte 0: EPD=0x7E (5GMM)
    // Byte 1: Security header type = 0x00 (plain NAS, no security)
    // Byte 2: Message type = 0x44 (Registration reject)
    // Byte 3: 5GMM cause = 0x0B (PLMN not allowed)
    const VECTOR: &[u8] = &[0x7E, 0x00, 0x44, 0x0B];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_5gmm_message(&mut buf).expect("SV-NAS-01 must decode");

    match &decoded {
        FiveGmmMessage::RegistrationReject(rr) => {
            // Assert specific field value — not just "decoded OK"
            assert_eq!(
                rr.gmm_cause, 0x0B,
                "gmm_cause must be 0x0B (PLMN not allowed)"
            );
        }
        other => panic!("SV-NAS-01: expected RegistrationReject, got {other:?}"),
    }

    // Byte-equality: re-encode and compare
    let re_encoded = build_5gmm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-01: re-encoded bytes must equal the original vector"
    );
}

/// Vector SV-NAS-02: 5GMM Deregistration Accept (UE-terminated, network→UE)
///
/// Source: TS 24.501 §8.2.14.  This message carries no IEs beyond the header.
///
/// Wire bytes (plain NAS):
///   7E 00 48
///   MT 0x48 = Deregistration accept (UE terminated)  (Table 9.7.1; 0x47 is the
///   Deregistration *request* UE-terminated, which is NOT header-only).
///
/// Fields asserted:
///   - variant = DeregistrationAcceptToUe (no IE content to assert)
#[test]
fn sv_nas_02_deregistration_accept_to_ue() {
    // TS 24.501 §8.2.14: Deregistration accept (UE terminated, network → UE)
    const VECTOR: &[u8] = &[0x7E, 0x00, 0x48];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_5gmm_message(&mut buf).expect("SV-NAS-02 must decode");

    assert!(
        matches!(decoded, FiveGmmMessage::DeregistrationAcceptToUe),
        "SV-NAS-02: expected DeregistrationAcceptToUe, got {decoded:?}"
    );

    let re_encoded = build_5gmm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-02: re-encoded bytes must equal the original vector"
    );
}

/// Vector SV-NAS-03: 5GMM Configuration Update Complete
///
/// Source: TS 24.501 §8.2.30.  Header-only message (no mandatory IEs).
///
/// Wire bytes:
///   7E 00 55
///   MT 0x55 = Configuration update complete  (Table 9.7.1)
#[test]
fn sv_nas_03_configuration_update_complete() {
    // TS 24.501 §8.2.30: Configuration update complete
    const VECTOR: &[u8] = &[0x7E, 0x00, 0x55];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_5gmm_message(&mut buf).expect("SV-NAS-03 must decode");

    assert!(
        matches!(decoded, FiveGmmMessage::ConfigurationUpdateComplete),
        "SV-NAS-03: expected ConfigurationUpdateComplete, got {decoded:?}"
    );

    let re_encoded = build_5gmm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-03: re-encoded bytes must equal the original vector"
    );
}

/// Vector SV-NAS-04: 5GMM Status
///
/// Source: TS 24.501 §8.2.32.
///
/// Wire bytes:
///   7E 00 64 62
///   MT 0x64 = 5GMM status  (Table 9.7.1)
///   IE: 5GMM cause = 0x62 (Semantically incorrect message, §9.11.3.2)
///
/// Fields asserted:
///   - gmm_cause = 0x62
#[test]
fn sv_nas_04_5gmm_status_semantically_incorrect() {
    // TS 24.501 §8.2.32: 5GMM status
    // 5GMM cause 0x62 = Semantically incorrect message (Table 9.11.3.2.1)
    const VECTOR: &[u8] = &[0x7E, 0x00, 0x64, 0x62];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_5gmm_message(&mut buf).expect("SV-NAS-04 must decode");

    match &decoded {
        FiveGmmMessage::FiveGmmStatus(st) => {
            assert_eq!(
                st.gmm_cause, 0x62,
                "gmm_cause must be 0x62 (Semantically incorrect message)"
            );
        }
        other => panic!("SV-NAS-04: expected FiveGmmStatus, got {other:?}"),
    }

    let re_encoded = build_5gmm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-04: re-encoded bytes must equal the original vector"
    );
}

// ============================================================================
// Spec-derived EPS NAS vectors  (TS 24.301)
// ============================================================================

/// Vector SV-NAS-05: EMM Authentication Reject
///
/// Source: TS 24.301 §8.2.5.  Header-only message.
///
/// Wire bytes:
///   07 54
///   Byte 0: SH=0x0 | PD=0x7 (EMM)
///   Byte 1: MT = 0x54 (Authentication reject, Table 9.9.3.13-1)
#[test]
fn sv_nas_05_emm_authentication_reject() {
    // TS 24.301 §8.2.5: Authentication reject (network → UE, no IEs)
    // PD=07 (EPS Mobility Management), SH=0 (plain), MT=0x54
    const VECTOR: &[u8] = &[0x07, 0x54];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_emm_message(&mut buf).expect("SV-NAS-05 must decode");

    assert!(
        matches!(decoded, EmmMessage::AuthenticationReject),
        "SV-NAS-05: expected AuthenticationReject, got {decoded:?}"
    );

    let re_encoded = build_emm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-05: re-encoded bytes must equal the original vector"
    );
}

/// Vector SV-NAS-06: EMM Tracking Area Update Complete
///
/// Source: TS 24.301 §8.2.27.  Header-only message.
///
/// Wire bytes:
///   07 4A
///   MT = 0x4A (Tracking area update complete, Table 9.9.3.37a-1)
#[test]
fn sv_nas_06_emm_tau_complete() {
    // TS 24.301 §8.2.27: Tracking area update complete
    const VECTOR: &[u8] = &[0x07, 0x4A];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_emm_message(&mut buf).expect("SV-NAS-06 must decode");

    assert!(
        matches!(decoded, EmmMessage::TrackingAreaUpdateComplete),
        "SV-NAS-06: expected TrackingAreaUpdateComplete, got {decoded:?}"
    );

    let re_encoded = build_emm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-06: re-encoded bytes must equal the original vector"
    );
}

/// Vector SV-NAS-07: EMM Status (cause = No EPS bearer context activated)
///
/// Source: TS 24.301 §8.2.30.
///
/// Wire bytes:
///   07 60 30
///   MT = 0x60 (EMM status, Table 9.9.3.13-1)
///   EMM cause = 0x30 = No EPS bearer context activated (Table A.1)
///
/// Fields asserted:
///   - emm_cause = 0x30
#[test]
fn sv_nas_07_emm_status_no_eps_bearer_context() {
    // TS 24.301 §8.2.30: EMM status
    // EMM cause 0x30 = No EPS bearer context activated
    const VECTOR: &[u8] = &[0x07, 0x60, 0x30];

    let mut buf = Bytes::from_static(VECTOR);
    let decoded = parse_emm_message(&mut buf).expect("SV-NAS-07 must decode");

    match &decoded {
        EmmMessage::EmmStatus(st) => {
            assert_eq!(
                st.emm_cause, 0x30,
                "emm_cause must be 0x30 (No EPS bearer context activated)"
            );
        }
        other => panic!("SV-NAS-07: expected EmmStatus, got {other:?}"),
    }

    let re_encoded = build_emm_message(&decoded);
    assert_eq!(
        re_encoded.as_ref(),
        VECTOR,
        "SV-NAS-07: re-encoded bytes must equal the original vector"
    );
}

// ============================================================================
// OMITTED vectors
// ============================================================================
// The following were considered but omitted to avoid shipping guessed bytes:
//
// - 5GMM Registration Request (complex variable-length mobile identity SUCI
//   encoding; field-level encoding of SUCI home-network keys is non-trivial
//   to hand-derive without a reference trace).
//
// - 5GMM Authentication Request (RAND/AUTN are 16-byte random values; any
//   specific byte choice would be fabricated, not spec-derived).
//
// - 5GSM PDU Session Establishment Accept (QoS rules encoding is complex and
//   version-dependent; byte-table examples in TS 24.501 Annex F are
//   informative only and omit several length fields).
//
// - EMM Attach Accept / TAU Accept (TAI list encoding has three list types
//   with compact bit-fields whose exact hand-derivation requires care;
//   deferred to avoid shipping incorrect vectors).
//
// ## Captured (pcap) vectors — documented next step
//
// The repo bundles real Open5GS captures at `open5gs/docs/assets/pcapng/`
// (testregistration.pcapng, etc.). These carry NGAP-over-SCTP and SBI HTTP/2
// traffic and are the authoritative source for byte-equality vectors of the
// NGAP/S1AP/SBI paths (and NAS PDUs embedded in NGAP). They are NOT yet
// extracted here: tshark does not auto-dissect the SCTP payload as NGAP, so a
// capture-to-vector step must force the dissector, e.g.
//   tshark -r testregistration.pcapng -d 'sctp.ppi==60,ngap' \
//          -Y 'ngap' -T fields -e ngap.NGAP_PDU
// then embed the resulting octet string as a `const` and assert decode + field
// values. Tracked as the remaining half of T6.1.
