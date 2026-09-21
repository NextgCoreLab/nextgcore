//! Issue #187, criterion 4: the whole NF-side CCA provisioning chain, driven
//! only by environment variables — which is all a container gets.
//!
//! # Why this is its own test binary
//!
//! The provisioning path writes to THREE process-global pieces of state: the
//! memoized `nf_instance_id`, the `CCA_KEY_FROM_ENV` `OnceLock`, and the
//! `CCA_KEY_OVERRIDE` lock. Sharing a binary with any other test that touches
//! them means whichever runs first decides the values for both, and `cargo test`
//! runs a binary's tests in PARALLEL with no ordering.
//!
//! This was found the hard way: this test originally lived alongside
//! `nf_instance_id_from_env.rs`'s test and failed roughly 1 run in 10 under a
//! looped workspace run — both tests published a JWK under the same `PINNED`
//! filename into different directories, and each raced the other's
//! `remove_dir_all`. A single green run said nothing about it. Separate binaries
//! are separate processes, which is the only way a one-shot process-wide
//! resolution can be exercised honestly.
//!
//! Keep exactly ONE test here, for the same reason.

use nextgcore_sbi::types::NfType;

/// The pinned id under test. Deliberately DIFFERENT from the literal in
/// `nf_instance_id_from_env.rs`: the published JWK is named after it, so a
/// shared literal would have the two binaries writing the same filename if they
/// were ever merged back together.
const PINNED: &str = "issue-187-provisioned-from-the-environment";

/// Issue #187, criterion 4: the whole NF-side provisioning chain, driven only by
/// environment variables — which is all a container gets.
///
/// This is the end-to-end shape the docker overlay depends on: set two env vars,
/// and the NF generates a private key, keeps it across restarts, and leaves a
/// public JWK where the NRF's `cca_trusted_keys_dir` will find it, named after
/// this NF's `nfInstanceId`. Nothing is committed and no shell script templates
/// any YAML.
///
/// Revert-verified: with the `publish_cca_public_jwk_if_configured` calls removed
/// from BOTH publishing sites (`init_cca_client_credentials` and
/// `OAuth2Client::new`) this fails at the "the NRF must find" assertion.
///
/// Removing only the `OAuth2Client::new` call does NOT fail it — checked, and
/// stated here rather than left as an overclaim — because this test drives
/// `init_cca_client_credentials` first and that publishes too. The two sites are
/// deliberately redundant: an NF that eagerly initialises at startup and one that
/// only ever constructs a client must both end up trusted. The constructor site
/// is covered on its own by
/// `nf_instance_id_from_env::a_pinned_id_in_the_environment_reaches_the_nf_and_its_cca_subject`,
/// which never calls the init helper.
#[test]
fn the_environment_alone_provisions_a_key_and_a_trust_store_entry() {
    let base = std::env::temp_dir().join(format!("sbi-187-provision-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let key_file = base.join("private").join("cca.key");
    let jwk_dir = base.join("public");

    // SAFETY: single-threaded test body, set before the first key resolution.
    unsafe {
        std::env::set_var(nextgcore_sbi::oauth::CCA_SIGNING_KEY_FILE_ENV, &key_file);
        std::env::set_var(nextgcore_sbi::oauth::CCA_PUBLIC_JWK_DIR_ENV, &jwk_dir);
    }

    // What an NF does at startup.
    let configured = nextgcore_sbi::oauth::init_cca_client_credentials(PINNED)
        .expect("an absent key file means generate one, not fail");
    assert!(
        configured,
        "with {} set, a signing key must be configured",
        nextgcore_sbi::oauth::CCA_SIGNING_KEY_FILE_ENV
    );
    assert!(key_file.exists(), "the private key must be generated");

    // The NRF's side: a JWK named after this NF's instance ID, parseable by the
    // loader the NRF uses.
    let published = jwk_dir.join(format!("{PINNED}.jwk"));
    assert!(
        published.exists(),
        "the NRF must find {} to trust this NF; without it the CCA cannot be verified",
        published.display()
    );
    let jwk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&published).expect("read")).expect("json");
    let verifying = nextgcore_sbi::oauth::parse_es256_jwk(&jwk).expect("the NRF's loader");

    // And it verifies what this NF actually signs, through the constructor every
    // NF uses — the path that matters, not a hand-built client.
    let client =
        nextgcore_sbi::oauth::OAuth2Client::new("http://127.0.0.1:7777", PINNED, NfType::Amf);
    assert!(
        client.has_cca_signing_key(),
        "OAuth2Client::new must pick up the env-resolved key"
    );
    let cca = client.build_cca().expect("a key is configured");
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;
    let (signing_input, sig_b64) = cca.rsplit_once('.').expect("JWS");
    let sig = p256::ecdsa::Signature::from_slice(
        &URL_SAFE_NO_PAD.decode(sig_b64).expect("base64url sig"),
    )
    .expect("r||s");
    assert!(
        verifying.verify(signing_input.as_bytes(), &sig).is_ok(),
        "the published JWK must verify the CCA this NF signs, or the NRF refuses it"
    );

    // Idempotent across a restart: same private key, same published public key.
    let before = std::fs::read_to_string(&published).expect("read");
    let reloaded = nextgcore_sbi::oauth::load_or_create_es256_key(&key_file).expect("reload");
    nextgcore_sbi::oauth::publish_cca_public_jwk(&reloaded, PINNED, &jwk_dir).expect("republish");
    assert_eq!(
        before,
        std::fs::read_to_string(&published).expect("read"),
        "a second start must reuse the key, not rotate it out from under the NRF"
    );

    let _ = std::fs::remove_dir_all(&base);
}
