//! Drive a live NRF access-token endpoint with a real, signed Client Credentials
//! Assertion, and report whether the authenticated exchange succeeded.
//!
//! # Why this exists
//!
//! Issue #187's criterion 2 asks that a full overlay run show every consumer
//! presenting a signature-verified CCA. The first attempt at asserting that in CI
//! grepped the container logs for `invalid_client` and passed when it found none —
//! which a **dispatched run proved vacuous**: the log had zero token requests in
//! it, because none of the NFs needed a token during a bring-up-only run. A
//! negative assertion is satisfied by every path that never arrives.
//!
//! So this makes the assertion POSITIVE: it mints a CCA with the same
//! [`nextgcore_sbi::oauth::mint_cca`] the NFs use, presents it to the running
//! NRF over the wire, and requires a 200 with a usable token. It also presents a
//! CCA signed by an UNTRUSTED key and requires `invalid_client`, so a "success"
//! cannot come from an NRF that accepts anything.
//!
//! An example rather than a test: it needs a live NRF and a populated trust-store
//! directory, neither of which exists under `cargo test`.
//!
//! # Usage
//!
//! ```text
//! cca_token_probe <nrf-uri> <private-key-file> <nf-instance-id> <nf-type> <target-nf-type> <scope>
//! ```
//!
//! Exits 0 only when BOTH the positive and negative expectations hold.

use nextgcore_sbi::oauth::OAuth2Client;
use nextgcore_sbi::types::NfType;
use std::sync::Arc;

fn nf_type(s: &str) -> NfType {
    // Only the handful the overlay exercises; an unknown value is a usage error
    // rather than a silent default that would probe the wrong audience.
    match s.to_ascii_uppercase().as_str() {
        "NRF" => NfType::Nrf,
        "AMF" => NfType::Amf,
        "SMF" => NfType::Smf,
        "UDM" => NfType::Udm,
        "UDR" => NfType::Udr,
        "AUSF" => NfType::Ausf,
        "PCF" => NfType::Pcf,
        "NSSF" => NfType::Nssf,
        "BSF" => NfType::Bsf,
        other => {
            eprintln!("unsupported NF type {other:?}");
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: {} <nrf-uri> <private-key-file> <nf-instance-id> <nf-type> \
             <target-nf-type> <scope>",
            args[0]
        );
        std::process::exit(2);
    }
    let (nrf_uri, key_file, instance_id) = (&args[1], &args[2], &args[3]);
    let (own_type, target_type, scope) = (nf_type(&args[4]), nf_type(&args[5]), &args[6]);

    // Issue #187: for a consumer whose NF type no producer lists in
    // `allowedNfTypes`, a token is CORRECTLY withheld — that is the SBA
    // authorization decision (TS 33.501 §13.4.1.1.2 step 2), which happens AFTER
    // client authentication and is a different question.
    //
    // The NRF itself is exactly that case: every producer in the overlay restricts
    // `allowedNfTypes` to its real consumers (the UDM's is [AMF, SMF, AUSF, PCF,
    // SCP]) and none lists NRF, correctly. A dispatched run proved it, returning
    // `unauthorized_client ... "NRF" is not in allowedNfTypes of any UDM producer`.
    //
    // So in this mode a 200 OR an `unauthorized_client` both count as
    // authentication having SUCCEEDED, while `invalid_client` — the
    // authentication failure — still fails the probe. This asserts criterion 5
    // (the NRF authenticates to itself) without asserting an authorization grant
    // that ought not to be given.
    let auth_only = std::env::var("CCA_PROBE_AUTH_ONLY").is_ok_and(|v| v == "1");

    // The NF's real signing key, loaded with the same loader the NF used to create
    // it. Absent would mean "generate", so refuse rather than probe with a key the
    // NRF has never seen — that failure would look like a rejection.
    if !std::path::Path::new(key_file).exists() {
        eprintln!("FAIL: {key_file} does not exist, so this NF never provisioned a CCA key");
        std::process::exit(1);
    }
    let key = match nextgcore_sbi::oauth::load_or_create_es256_key(std::path::Path::new(key_file)) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            eprintln!("FAIL: cannot load {key_file}: {e}");
            std::process::exit(1);
        }
    };

    // POSITIVE: the real key the NRF holds the public half of.
    let trusted =
        OAuth2Client::new(nrf_uri, instance_id.clone(), own_type).with_cca_signing_key(key.clone());

    // Issue #393: state WHICH of the two binding mechanisms this run exercises, so
    // a green log cannot be read as proving the conformant one. `x5c` is attached
    // only when NEXTGCORE_SBI_CCA_CERT_FILE names a chain over this CCA signing
    // key; the docker overlay sets no such file, because no CA in that overlay can
    // certify a key the NF generates at startup. A reader who sees "trust store"
    // here knows the x5c coverage is the in-process nrfd tests, not this stage.
    if trusted.has_cca_cert_chain() {
        println!(
            "binding mechanism: x5c certificate chain (TS 33.501 §13.3.8.2); the NRF binds the \
             leaf certificate's URI SAN to this assertion's sub (§13.3.8.3)"
        );
    } else {
        println!(
            "binding mechanism: cca_trusted_keys store (NEXTGCORE_SBI_CCA_CERT_FILE unset). This \
             is the no-PKI path and a documented deviation from TS 33.501 §13.3.8.2 -- this run \
             does NOT exercise the x5c certificate binding."
        );
    }

    match trusted.request_token(target_type, scope).await {
        Ok(resp) => {
            // A token that is not a JWS is not a token; check shape, not just 200.
            if resp.access_token.split('.').count() != 3 {
                eprintln!(
                    "FAIL: the NRF returned a 200 but the access_token is not a JWS: {:?}",
                    resp.access_token
                );
                std::process::exit(1);
            }
            println!(
                "PASS positive: the NRF issued a token to {instance_id} against a \
                 signature-verified CCA (scope {:?})",
                resp.scope.as_deref().unwrap_or(scope)
            );
        }
        Err(e) if auth_only && e.to_string().contains("unauthorized_client") => {
            // Authentication SUCCEEDED and authorization declined. The NRF got past
            // `invalid_client`, which is the only thing criterion 5 claims: it
            // presented a CCA its own token endpoint verified against its own trust
            // store, from its own registry entry.
            println!(
                "PASS positive (auth-only): the NRF authenticated {instance_id} via a \
                 signature-verified CCA; the token was then withheld by SBA authorization \
                 (unauthorized_client), which is the correct allowedNfTypes decision and a \
                 different question from authentication"
            );
        }
        Err(e) => {
            // Name the LIKELY cause from the NRF's own wording rather than
            // guessing one. Validated locally: a probe run against a live nrfd
            // whose registry did not have the NF returned "is not registered",
            // and an earlier draft of this message blamed the trust store — which
            // would have sent a reader to the wrong place. Criterion 3 of #187 is
            // specifically about the failure being diagnosable.
            let msg = e.to_string();
            let hint = if msg.contains("unauthorized_client") {
                "authentication SUCCEEDED; the token was withheld by SBA authorization \
                 (allowedNfTypes). If that is the expected outcome for this consumer/producer \
                 pair, set CCA_PROBE_AUTH_ONLY=1"
            } else if msg.contains("not registered") {
                "the CCA verified, but this nfInstanceId is not in the NRF's registry: the NF \
                 never completed NF registration, or it registered under a different id"
            } else if msg.contains("no trusted") {
                "the NRF has no trusted key for this nfInstanceId: the public JWK never reached \
                 its cca_trusted_keys_dir (check the shared volume and its ownership)"
            } else if msg.contains("signature") {
                "the CCA signature did not verify against the key the NRF holds for this \
                 nfInstanceId: the published JWK is stale relative to the private key"
            } else {
                "neither a registry nor a trust-store problem; read the NRF log"
            };
            eprintln!("FAIL positive: the NRF refused a CCA signed with this NF's OWN key: {e}");
            eprintln!("  likely cause: {hint}");
            std::process::exit(1);
        }
    }

    // NEGATIVE: a fresh key the NRF cannot possibly trust. Without this half, a
    // 200 above would also be produced by an NRF that authenticates nobody --
    // which is exactly the posture issue #187 removed.
    let untrusted = Arc::new(nextgcore_sbi::oauth::generate_es256_key());
    let forger =
        OAuth2Client::new(nrf_uri, instance_id.clone(), own_type).with_cca_signing_key(untrusted);
    match forger.request_token(target_type, scope).await {
        Ok(_) => {
            eprintln!(
                "FAIL negative: the NRF issued a token for a CCA signed with a key it does \
                 NOT trust. Client authentication is not being enforced."
            );
            std::process::exit(1);
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("invalid_client") {
                eprintln!(
                    "FAIL negative: the request was refused, but NOT with invalid_client, so \
                     the cause is not diagnosable as an authentication failure: {msg}"
                );
                std::process::exit(1);
            }
            println!("PASS negative: an untrusted CCA key is refused invalid_client");
        }
    }
}
