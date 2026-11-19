//! #1795: the one assertion every NF's listener test makes about the SBI
//! security profile, so seventeen NFs pin the same posture rather than
//! seventeen slightly different readings of it.

use std::net::SocketAddr;

use crate::security::{SbiProfile, SbiSecurityPolicy, TlsPaths};
use crate::server::SbiServerConfig;
use crate::types::{NfType, UriScheme};
use crate::SbiResult;

/// Assert that `build`, an NF's own listener-configuration step, follows the
/// SBI security profile (#1795, TS 33.501 §13.1.0, §13.3, §13.4.1):
///
/// - `production`: TLS from the policy's certificate paths whatever the NF's
///   own TLS setting said, the client certificate verified against the
///   policy's CA (mTLS), and an access token required, with `nf_type` as the
///   expected audience and `nrf_uri`'s JWKS as the verification source. A
///   missing certificate is an error naming it, never cleartext.
/// - `dev`: the configuration `build` was handed, untouched: cleartext stays
///   cleartext, and the NF's own `--tls` still serves TLS, without mTLS or a
///   token requirement.
///
/// `build(config, profile, policy, nrf_uri)` must be the function the NF's
/// `main` uses, so reverting the NF's call to the profile fails its test.
///
/// # Panics
///
/// On any deviation, naming `nf_type` and the property.
pub fn assert_listener_follows_sbi_profile(
    nf_type: NfType,
    build: impl Fn(SbiServerConfig, SbiProfile, &SbiSecurityPolicy, &str) -> SbiResult<SbiServerConfig>,
) {
    let nf = nf_type.to_str();
    let dir = std::env::temp_dir().join(format!(
        "sbi-profile-1795-{nf}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = |n: &str| {
        let p = dir.join(n);
        std::fs::write(&p, "pem").expect("write placeholder");
        p.display().to_string()
    };
    let policy = SbiSecurityPolicy {
        tls_paths: TlsPaths {
            cert: file("server.crt"),
            key: file("server.key"),
            ca_cert: file("ca.crt"),
            client_cert: Some(file("client.crt")),
            client_key: Some(file("client.key")),
        },
        ..SbiSecurityPolicy::production()
    };
    let addr: SocketAddr = "127.0.0.1:7777".parse().expect("addr");
    let nrf = "https://127.0.0.10:7777";
    let jwks = crate::oauth::JwksCache::for_nrf(nrf).jwks_uri().to_string();

    // Production, from a cleartext base and from one the NF's own TLS set up.
    for (base, what) in [
        (SbiServerConfig::new(addr), "a cleartext base"),
        (
            SbiServerConfig::new(addr).with_tls("/nf/own.key", "/nf/own.crt"),
            "the NF's own TLS",
        ),
    ] {
        let prod = build(base, SbiProfile::Production, &policy, nrf)
            .unwrap_or_else(|e| panic!("{nf}: production applies over {what}: {e}"));
        assert_eq!(
            prod.scheme,
            UriScheme::Https,
            "{nf}: production serves TLS over {what}"
        );
        assert_eq!(
            prod.cert.as_deref(),
            Some(policy.tls_paths.cert.as_str()),
            "{nf}: production's certificate is the policy's, over {what}"
        );
        assert_eq!(
            prod.private_key.as_deref(),
            Some(policy.tls_paths.key.as_str()),
            "{nf}: and its key"
        );
        assert!(
            prod.verify_client,
            "{nf}: production verifies the client certificate"
        );
        assert_eq!(
            prod.verify_client_cacert.as_deref(),
            Some(policy.tls_paths.ca_cert.as_str()),
            "{nf}: against the policy's CA"
        );
        assert!(
            prod.require_oauth2,
            "{nf}: production requires an access token"
        );
        assert_eq!(
            prod.oauth2_expected_audience.as_deref(),
            Some(nf),
            "{nf}: a token for another producer is refused"
        );
        assert_eq!(
            prod.oauth2_jwks_uri.as_deref(),
            Some(jwks.as_str()),
            "{nf}: tokens are verified against the NRF's JWKS"
        );
    }

    // A missing certificate fails closed, naming it.
    let missing = SbiSecurityPolicy {
        tls_paths: TlsPaths {
            cert: dir.join("absent.crt").display().to_string(),
            ..policy.tls_paths.clone()
        },
        ..SbiSecurityPolicy::production()
    };
    let err = build(
        SbiServerConfig::new(addr),
        SbiProfile::Production,
        &missing,
        nrf,
    )
    .err()
    .unwrap_or_else(|| panic!("{nf}: a missing certificate must not fall back to cleartext"));
    assert!(err.to_string().contains("absent.crt"), "{nf}: {err}");

    // Dev: untouched.
    let dev = build(SbiServerConfig::new(addr), SbiProfile::Dev, &policy, nrf)
        .unwrap_or_else(|e| panic!("{nf}: dev applies: {e}"));
    assert_eq!(dev.scheme, UriScheme::Http, "{nf}: dev stays cleartext");
    assert!(!dev.verify_client, "{nf}: dev adds no mTLS");
    assert!(!dev.require_oauth2, "{nf}: dev adds no token requirement");
    let dev_tls = build(
        SbiServerConfig::new(addr).with_tls("/nf/own.key", "/nf/own.crt"),
        SbiProfile::Dev,
        &policy,
        nrf,
    )
    .unwrap_or_else(|e| panic!("{nf}: dev applies over the NF's own TLS: {e}"));
    assert_eq!(
        dev_tls.scheme,
        UriScheme::Https,
        "{nf}: dev keeps the NF's own TLS"
    );
    assert_eq!(
        dev_tls.cert.as_deref(),
        Some("/nf/own.crt"),
        "{nf}: its own certificate"
    );
    assert!(!dev_tls.verify_client, "{nf}: and adds no mTLS");

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_step_passes() {
        assert_listener_follows_sbi_profile(NfType::Nef, |c, p, policy, nrf| {
            crate::security::apply_sbi_security_policy(c, p, policy, NfType::Nef, nrf)
        });
    }

    /// The helper bites: a listener that ignores the profile is refused.
    #[test]
    #[should_panic(expected = "NEF: production serves TLS over a cleartext base")]
    fn a_listener_that_ignores_the_profile_fails() {
        assert_listener_follows_sbi_profile(NfType::Nef, |c, _, _, _| Ok(c));
    }

    /// And so does one that names the wrong audience.
    #[test]
    #[should_panic(expected = "NEF: a token for another producer is refused")]
    fn a_listener_with_the_wrong_audience_fails() {
        assert_listener_follows_sbi_profile(NfType::Nef, |c, p, policy, nrf| {
            crate::security::apply_sbi_security_policy(c, p, policy, NfType::Af, nrf)
        });
    }
}
