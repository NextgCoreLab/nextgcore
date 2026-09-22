//! Issue #187: a pinned `nfInstanceId` set in the ENVIRONMENT actually reaches
//! the NF, and reaches the CCA subject the NRF authenticates against.
//!
//! # Why this is an integration test and not a unit test
//!
//! `nf_instance_id::nf_instance_id` memoizes into a process-wide `OnceLock` — by
//! design, because two call sites in one process disagreeing about this NF's
//! identity is the defect issue #187 exists to close. A unit test therefore
//! cannot exercise the environment path: whichever test resolves the lock first
//! decides the value for the whole binary, and `cargo test` gives no ordering.
//!
//! Each `tests/*.rs` file is its own binary and so its own process, which is the
//! only place a one-shot process-wide resolution can be observed honestly.
//! There is exactly ONE resolving test here for that reason.
//!
//! # Why it asserts POSITIVELY
//!
//! Four config keys in this tree have been found declared-and-never-read. A test
//! that only checked "the resolver returns something" would pass against a
//! resolver that ignored the environment entirely. So this asserts the *specific
//! pinned value* arrives, and that it arrives all the way at
//! `OAuth2Client`'s CCA subject — the value the NRF looks up in
//! `cca_trusted_keys` (TS 33.501 §13.3.8.3).

use nextgcore_sbi::nf_instance_id::{nf_instance_id, type_env_var, ANY_NF_INSTANCE_ID_ENV};
use nextgcore_sbi::types::NfType;

/// A literal no UUID generator could produce, so a regression cannot pass by
/// coincidence and a failure message names the source it came from.
const PINNED: &str = "issue-187-pinned-by-the-container-environment";

#[test]
fn a_pinned_id_in_the_environment_reaches_the_nf_and_its_cca_subject() {
    // SAFETY: set before the first resolution in this process, and this is the
    // only test in this binary (see the module docs), so no other thread is
    // reading the environment concurrently.
    unsafe {
        std::env::set_var(ANY_NF_INSTANCE_ID_ENV, PINNED);
    }

    // 1. The resolver honours the pin, rather than generating.
    let resolved = nf_instance_id(NfType::Amf);
    assert_eq!(
        resolved, PINNED,
        "{ANY_NF_INSTANCE_ID_ENV} was set to {PINNED:?} but the NF resolved {resolved:?}; \
         a pin that does not arrive means no NRF-side CCA trust store can be provisioned"
    );

    // 2. It reaches the CCA subject. This is the assertion that matters: the
    //    NRF verifies the CCA signature against the key it trusts for THIS
    //    value (TS 33.501 §13.3.8.3), so a pin that stopped short of here would
    //    look configured and still be refused `invalid_client`.
    let key = std::sync::Arc::new(nextgcore_sbi::oauth::generate_es256_key());
    let client = nextgcore_sbi::oauth::OAuth2Client::new(
        "http://127.0.0.1:7777",
        nf_instance_id(NfType::Amf),
        NfType::Amf,
    )
    .with_cca_signing_key(key.clone());
    let cca = client
        .build_cca()
        .expect("a signing key was installed, so a CCA must be minted");

    // Decode the CCA payload and read `sub` — what the NRF matches.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload = cca.split('.').nth(1).expect("a JWS has three parts");
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url payload"))
            .expect("JSON claims");
    assert_eq!(
        claims["sub"], PINNED,
        "the CCA subject must be the pinned nfInstanceId; the NRF looks this exact string \
         up in cca_trusted_keys"
    );
    assert_eq!(
        claims["iss"], PINNED,
        "TS 29.510 6.7.5: the assertion is self-issued, so iss equals sub"
    );

    // 3. Memoized: a second call site in the same process sees the same value.
    //    This is what makes the CCA subject equal the REGISTERED nfInstanceId.
    assert_eq!(nf_instance_id(NfType::Udm), PINNED);

    // 4. The per-type variable is a real, distinct name (the lower-precedence
    //    source). Checked as a pure string so it needs no second resolution.
    assert_eq!(type_env_var(NfType::Amf), "NEXTGCORE_AMF_INSTANCE_ID");
    assert_ne!(type_env_var(NfType::Amf), ANY_NF_INSTANCE_ID_ENV);
}
