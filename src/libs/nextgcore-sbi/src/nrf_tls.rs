//! NRF-scoped client TLS (#1617, step a).
//!
//! The NRF binds NFRegister / NFUpdate / NFDeregister to the caller's verified
//! client certificate: the `urn:uuid:<nfInstanceId>` URI SAN and the RFC 9310
//! NFTypes (TS 33.310 §6.1.3c.3, TS 33.501 §13.1.0; nrfd #1611). Even when a
//! first NFRegister carries a token (#1667), that token was granted on a proven
//! identity, so the certificate is the identity the registration binds to.
//! Every request an NF sends to its NRF therefore has to go over TLS
//! with this NF's client certificate, whatever the SBI profile says about the
//! other peers.
//!
//! The process-wide SBI profile ([`crate::security::SbiProfile`]) cannot say
//! that: it is all-TLS or all-h2c. This module is the one place that decides
//! how this NF dials **its NRF**:
//!
//! - **Scheme.** `https` when the configured NRF URI is `https://`, or when the
//!   profile is `production` (as before: production dials every peer over TLS).
//!   An `http://` NRF URI under the `dev` profile stays cleartext, unchanged.
//! - **Trust anchor** for the NRF's server certificate: [`NRF_TLS_CA_ENV`], else
//!   `NEXTGCORE_SBI_TLS_CA`, else `/etc/nextgcore/tls/ca.crt`. There is no
//!   fallback to public roots: a missing file fails the handshake.
//! - **Client certificate** presented to the NRF: the pair
//!   [`NRF_TLS_CLIENT_CERT_ENV`] / [`NRF_TLS_CLIENT_KEY_ENV`], else the SBI pair
//!   `NEXTGCORE_SBI_TLS_CLIENT_CERT` / `_KEY`, else
//!   `/etc/nextgcore/tls/client.{crt,key}` when both files exist. With none of
//!   them the NF dials without a client certificate (the NRF then sees no
//!   verified identity). Half a pair (a certificate without its key, or the
//!   reverse) is a configuration error: every NRF connection fails with it,
//!   rather than silently presenting no certificate.
//! - **Server name** the NRF's certificate is verified against:
//!   [`NRF_TLS_SERVER_NAME_ENV`] when set, else the NRF URI's host. The dev PKI
//!   does not name `localhost` / `127.0.0.1` in any certificate, so a client on
//!   the NRF's host that dials `https://127.0.0.1:7777` sets this to `nrf`.
//!
//! Every NRF-facing transport uses it: [`crate::context::SbiContext::get_client`]
//! for the NRF's authority, the registration / heartbeat / deregistration paths
//! in [`crate::heartbeat`], [`crate::client::SbiClient::for_nrf_uri`] for daemon
//! code that dials the NRF directly, and the OAuth2 access-token and JWKS
//! transports in [`crate::oauth`] (the NRF is the authorization server,
//! TS 33.501 §13.4.1.1).

use std::sync::{Arc, RwLock};

use tokio_rustls::TlsConnector;

use crate::client::SbiClientConfig;
use crate::error::{SbiError, SbiResult};
use crate::security::{SbiProfile, TlsPaths};
use crate::types::UriScheme;

/// Trust anchor (PEM) for the NRF's server certificate.
pub const NRF_TLS_CA_ENV: &str = "NEXTGCORE_NRF_TLS_CA";
/// Certificate (PEM) this NF presents to the NRF.
pub const NRF_TLS_CLIENT_CERT_ENV: &str = "NEXTGCORE_NRF_TLS_CLIENT_CERT";
/// Private key (PEM) of [`NRF_TLS_CLIENT_CERT_ENV`].
pub const NRF_TLS_CLIENT_KEY_ENV: &str = "NEXTGCORE_NRF_TLS_CLIENT_KEY";
/// Name the NRF's server certificate is verified against, when the NRF URI's
/// host is not one of its SANs (a loopback or bare-IP NRF URI).
pub const NRF_TLS_SERVER_NAME_ENV: &str = "NEXTGCORE_NRF_TLS_SERVER_NAME";

/// The TLS material this NF uses toward its NRF (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrfClientTls {
    /// PEM trust anchor for the NRF's server certificate.
    pub ca_cert: String,
    /// PEM client certificate presented to the NRF, if any.
    pub client_cert: Option<String>,
    /// PEM private key of `client_cert`.
    pub client_key: Option<String>,
    /// Name to verify the NRF's certificate against instead of the URI host.
    pub server_name: Option<String>,
    /// Why this configuration cannot be used (half a certificate/key pair).
    /// Set, every TLS connection to the NRF fails with it.
    pub error: Option<String>,
}

impl NrfClientTls {
    /// Resolve from the process environment.
    pub fn from_env() -> Self {
        Self::resolve(
            |var| {
                std::env::var(var)
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
            },
            |path| std::path::Path::new(path).is_file(),
        )
    }

    /// Pure resolution over an env lookup and a file-existence probe.
    pub fn resolve(env: impl Fn(&str) -> Option<String>, exists: impl Fn(&str) -> bool) -> Self {
        let defaults = TlsPaths::default();
        let ca_cert = env(NRF_TLS_CA_ENV)
            .or_else(|| env(TlsPaths::CA_ENV))
            .unwrap_or(defaults.ca_cert);

        let pair = |cert_var: &str, key_var: &str| -> Option<(Option<String>, Option<String>)> {
            let (c, k) = (env(cert_var), env(key_var));
            (c.is_some() || k.is_some()).then_some((c, k))
        };
        // The SBI pair keeps `TlsPaths::from_env`'s rule: an unset half is
        // its compiled-in default path.
        let sbi_pair = pair(TlsPaths::CLIENT_CERT_ENV, TlsPaths::CLIENT_KEY_ENV).map(|(c, k)| {
            (
                c.or_else(|| defaults.client_cert.clone()),
                k.or_else(|| defaults.client_key.clone()),
            )
        });
        let (client_cert, client_key) = pair(NRF_TLS_CLIENT_CERT_ENV, NRF_TLS_CLIENT_KEY_ENV)
            .or(sbi_pair)
            .unwrap_or_else(|| match (defaults.client_cert, defaults.client_key) {
                (Some(c), Some(k)) if exists(&c) && exists(&k) => (Some(c), Some(k)),
                _ => (None, None),
            });

        let error = match (&client_cert, &client_key) {
            (Some(c), None) => Some(format!(
                "NRF client TLS: certificate {c} is configured without its private key \
                 (set {NRF_TLS_CLIENT_KEY_ENV} or {})",
                TlsPaths::CLIENT_KEY_ENV
            )),
            (None, Some(k)) => Some(format!(
                "NRF client TLS: private key {k} is configured without its certificate \
                 (set {NRF_TLS_CLIENT_CERT_ENV} or {})",
                TlsPaths::CLIENT_CERT_ENV
            )),
            _ => None,
        };

        Self {
            ca_cert,
            client_cert,
            client_key,
            server_name: env(NRF_TLS_SERVER_NAME_ENV),
            error,
        }
    }

    /// The rustls connector for this material (ALPN `h2`).
    pub fn connector(&self) -> SbiResult<TlsConnector> {
        if let Some(e) = &self.error {
            return Err(SbiError::TlsError(e.clone()));
        }
        let config = match (&self.client_cert, &self.client_key) {
            (Some(c), Some(k)) => crate::tls::build_client_config_mtls(
                crate::tls::load_certs(c)?,
                crate::tls::load_private_key(k)?,
                Some(&self.ca_cert),
                false,
            )?,
            _ => crate::tls::build_client_config(Some(&self.ca_cert), false)?,
        };
        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// Programmatic replacement for [`NrfClientTls::from_env`] (tests, and a daemon
/// that reads the same settings from its YAML).
static NRF_CLIENT_TLS_OVERRIDE: RwLock<Option<NrfClientTls>> = RwLock::new(None);

/// Serialises tests that set [`set_nrf_client_tls_override`] or the NRF TLS
/// environment. Declared beside the global it guards; `pub` because daemon
/// crates' tests share the global.
pub static NRF_CLIENT_TLS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Replace the environment-derived NRF client TLS for this process (`None`
/// restores [`NrfClientTls::from_env`]).
pub fn set_nrf_client_tls_override(tls: Option<NrfClientTls>) {
    *NRF_CLIENT_TLS_OVERRIDE
        .write()
        .unwrap_or_else(|e| e.into_inner()) = tls;
}

/// #1667: the OAuth2 client this NF's own NRF calls (Nnrf_NFManagement,
/// Nnrf_NFDiscovery) take their access token from, with target NF type NRF.
/// Installed by a daemon when its `sbi.oauth2.require` is on, beside the one it
/// gives its peer clients; `None` (the default) sends NRF calls without a token,
/// as before. TS 29.510 §6.1.8 / §6.2.8: when OAuth2 is used on these APIs the
/// consumer obtains the token before consuming them, so before NFRegister.
///
/// No test lock: tests do not set it. They drive
/// [`crate::client::SbiClient::for_nrf_uri_with`] instead, because any test that
/// set this would make every concurrent [`crate::client::SbiClient::for_nrf_uri`]
/// in its binary attach tokens, and fail closed without a token endpoint.
static NRF_OAUTH2_CLIENT: RwLock<Option<Arc<crate::oauth::OAuth2Client>>> = RwLock::new(None);

/// Install (or, with `None`, remove) the OAuth2 client of this NF's NRF calls.
pub fn set_nrf_oauth2_client(client: Option<Arc<crate::oauth::OAuth2Client>>) {
    *NRF_OAUTH2_CLIENT.write().unwrap_or_else(|e| e.into_inner()) = client;
}

/// The OAuth2 client of this NF's NRF calls, if one is installed.
pub fn nrf_oauth2_client() -> Option<Arc<crate::oauth::OAuth2Client>> {
    NRF_OAUTH2_CLIENT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The NRF client TLS in force: the override, else the environment.
pub fn nrf_client_tls() -> NrfClientTls {
    NRF_CLIENT_TLS_OVERRIDE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(NrfClientTls::from_env)
}

/// Scheme, host (IPv6 without brackets) and port of an NRF URI such as
/// `https://nrf:7777` or `http://[fd00::10]:7777/nnrf-nfm/v1`. The port defaults
/// to the scheme's. A bare `host:port` is `http`, as the NRF URI parsers this
/// replaces read it. `None` for another scheme or no host.
pub fn parse_nrf_uri(uri: &str) -> Option<(UriScheme, String, u16)> {
    let uri = uri.trim();
    let (scheme, rest) = if let Some(r) = strip_prefix_ci(uri, "https://") {
        (UriScheme::Https, r)
    } else if let Some(r) = strip_prefix_ci(uri, "http://") {
        (UriScheme::Http, r)
    } else if uri.contains("://") {
        return None;
    } else {
        (UriScheme::Http, uri)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (h, after) = inner.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => scheme.default_port(),
            None => return None,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), scheme.default_port()),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port))
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &s[prefix.len()..])
}

/// Whether `host:port` is the authority of `nrf_uri` (host compared
/// case-insensitively, IPv6 brackets ignored).
pub fn is_nrf_authority(nrf_uri: &str, host: &str, port: u16) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    parse_nrf_uri(nrf_uri).is_some_and(|(_, h, p)| p == port && h.eq_ignore_ascii_case(host))
}

/// The scheme this NF dials its NRF with: `https` for an `https://` NRF URI or
/// under the `production` profile, else `http`.
pub fn nrf_scheme(uri_scheme: UriScheme, profile: SbiProfile) -> UriScheme {
    if uri_scheme == UriScheme::Https || profile.is_production() {
        UriScheme::Https
    } else {
        UriScheme::Http
    }
}

/// The client configuration for dialling the NRF at `host:port` with
/// `scheme` (already decided by [`nrf_scheme`]). `http` is exactly
/// `SbiClientConfig::new`; `https` carries [`nrf_client_tls`].
/// #1681: the largest NRF answer a client built from [`nrf_client_config`] reads:
/// an NFProfile echo is a few tens of KiB and a discovery SearchResult a few MiB at
/// most (amfd's own NRF discovery bound, #1674). A larger body, announced or
/// streamed, is refused rather than buffered.
pub const NRF_MAX_RESPONSE_BODY: usize = 4 * 1024 * 1024;

pub fn nrf_client_config(scheme: UriScheme, host: &str, port: u16) -> SbiClientConfig {
    let mut config = SbiClientConfig::new(host, port).with_max_response_body(NRF_MAX_RESPONSE_BODY);
    // #1667: whatever builds the client from this, its requests to the NRF carry
    // the process's NRF access token when one is installed.
    config.nrf_oauth2 = true;
    if scheme == UriScheme::Http {
        return config;
    }
    let tls = nrf_client_tls();
    let mut config = config.with_https();
    config.ca_cert = Some(tls.ca_cert);
    config.client_cert = tls.client_cert;
    config.client_key = tls.client_key;
    config.tls_server_name = tls.server_name;
    config.tls_config_error = tls.error;
    config
}

/// [`nrf_client_config`] for an NRF URI, with the scheme from [`nrf_scheme`]
/// under the resolved profile. `None` when the URI does not parse.
pub fn nrf_client_config_for_uri(nrf_uri: &str) -> Option<SbiClientConfig> {
    let (scheme, host, port) = parse_nrf_uri(nrf_uri)?;
    Some(nrf_client_config(
        nrf_scheme(scheme, SbiProfile::resolve()),
        &host,
        port,
    ))
}

/// Log, once per call, how this NF will dial the NRF at `nrf_uri`. Called when
/// an NRF URI is configured, so a broken setting shows at startup rather than as
/// a handshake failure on the first registration.
pub fn log_nrf_client_tls(nrf_uri: &str) {
    let Some((scheme, host, port)) = parse_nrf_uri(nrf_uri) else {
        return;
    };
    if nrf_scheme(scheme, SbiProfile::resolve()) == UriScheme::Http {
        return;
    }
    let tls = nrf_client_tls();
    let authority = crate::uri_encode::uri_authority(&host, port);
    let server_name = tls.server_name.as_deref().unwrap_or(&host);
    match nrf_client_tls_log_level(&tls) {
        log::Level::Error => log::error!(
            "{}: every request to the NRF at {authority} will fail",
            tls.error.as_deref().unwrap_or("NRF client TLS is unusable")
        ),
        // #1690 review m3: the NRF binds NFRegister / NFUpdate / NFDeregister to
        // the client certificate (TS 33.310 §6.1.3c.3), so dialling it without
        // one is a misconfiguration an operator must see, not routine.
        log::Level::Warn => log::warn!(
            "NRF client TLS for {authority}: CA={} server name={server_name}, but NO client \
             certificate: the NRF sees no verified identity for this NF and will refuse its \
             registration. Set {NRF_TLS_CLIENT_CERT_ENV} / {NRF_TLS_CLIENT_KEY_ENV}.",
            tls.ca_cert,
        ),
        _ => log::info!(
            "NRF client TLS for {authority}: CA={} client certificate={} server name={server_name}",
            tls.ca_cert,
            tls.client_cert.as_deref().unwrap_or_default(),
        ),
    }
}

/// The level [`log_nrf_client_tls`] reports `tls` at over https: an error for an
/// unusable configuration, a warning without a client certificate, else info.
pub fn nrf_client_tls_log_level(tls: &NrfClientTls) -> log::Level {
    if tls.error.is_some() {
        log::Level::Error
    } else if tls.client_cert.is_none() {
        log::Level::Warn
    } else {
        log::Level::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// #1681: a client for the NRF (heartbeat, NFUpdate, deregistration,
    /// discovery: every `SbiClient::for_nrf_uri`) reads the NRF's answers with a
    /// bound, over plain `http` and `https` alike.
    ///
    /// REVERT-VERIFIED: with `with_max_response_body` dropped from
    /// `nrf_client_config`, both are `None`.
    #[test]
    fn nrf_clients_read_answers_with_a_bound_1681() {
        for scheme in [UriScheme::Http, UriScheme::Https] {
            assert_eq!(
                nrf_client_config(scheme, "127.0.0.10", 7777).max_response_body,
                Some(NRF_MAX_RESPONSE_BODY),
                "{scheme:?}"
            );
        }
        assert_eq!(
            nrf_client_config_for_uri("http://127.0.0.10:7777").and_then(|c| c.max_response_body),
            Some(NRF_MAX_RESPONSE_BODY)
        );
    }

    fn resolve(env: &[(&str, &str)], files: &[&str]) -> NrfClientTls {
        let env: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let files: Vec<String> = files.iter().map(|f| f.to_string()).collect();
        NrfClientTls::resolve(|v| env.get(v).cloned(), |p| files.iter().any(|f| f == p))
    }

    #[test]
    fn nrf_settings_win_over_the_sbi_ones_1617() {
        let t = resolve(
            &[
                (NRF_TLS_CA_ENV, "/n/ca.crt"),
                (NRF_TLS_CLIENT_CERT_ENV, "/n/amf.crt"),
                (NRF_TLS_CLIENT_KEY_ENV, "/n/amf.key"),
                (NRF_TLS_SERVER_NAME_ENV, "nrf"),
                (TlsPaths::CA_ENV, "/s/ca.crt"),
                (TlsPaths::CLIENT_CERT_ENV, "/s/c.crt"),
                (TlsPaths::CLIENT_KEY_ENV, "/s/c.key"),
            ],
            &[],
        );
        assert_eq!(t.ca_cert, "/n/ca.crt");
        assert_eq!(t.client_cert.as_deref(), Some("/n/amf.crt"));
        assert_eq!(t.client_key.as_deref(), Some("/n/amf.key"));
        assert_eq!(t.server_name.as_deref(), Some("nrf"));
        assert_eq!(t.error, None);
    }

    #[test]
    fn the_sbi_settings_are_the_fallback_1617() {
        let t = resolve(
            &[
                (TlsPaths::CA_ENV, "/s/ca.crt"),
                (TlsPaths::CLIENT_CERT_ENV, "/s/c.crt"),
                (TlsPaths::CLIENT_KEY_ENV, "/s/c.key"),
            ],
            &[],
        );
        assert_eq!(t.ca_cert, "/s/ca.crt");
        assert_eq!(t.client_cert.as_deref(), Some("/s/c.crt"));
        assert_eq!(t.server_name, None);
        assert_eq!(t.error, None);
    }

    #[test]
    fn the_compiled_in_client_pair_is_used_only_when_both_files_exist_1617() {
        let d = TlsPaths::default();
        let (c, k) = (d.client_cert.unwrap(), d.client_key.unwrap());
        let none = resolve(&[], &[&c]);
        assert_eq!(
            none.ca_cert, d.ca_cert,
            "the CA never falls back to public roots"
        );
        assert_eq!((none.client_cert, none.client_key), (None, None));
        let both = resolve(&[], &[&c, &k]);
        assert_eq!(both.client_cert, Some(c));
        assert_eq!(both.client_key, Some(k));
    }

    #[test]
    fn half_a_client_pair_is_an_error_not_an_anonymous_client_1617() {
        let t = resolve(&[(NRF_TLS_CLIENT_CERT_ENV, "/n/amf.crt")], &[]);
        assert!(t.error.as_deref().unwrap().contains(NRF_TLS_CLIENT_KEY_ENV));
        assert!(t.connector().is_err());
        // An NRF key does not borrow the SBI certificate.
        let t = resolve(
            &[
                (NRF_TLS_CLIENT_KEY_ENV, "/n/amf.key"),
                (TlsPaths::CLIENT_CERT_ENV, "/s/c.crt"),
            ],
            &[],
        );
        assert!(t
            .error
            .as_deref()
            .unwrap()
            .contains("without its certificate"));
        // The SBI pair keeps TlsPaths' rule: an unset half is its default.
        let t = resolve(&[(TlsPaths::CLIENT_CERT_ENV, "/s/c.crt")], &[]);
        assert_eq!(t.client_key, TlsPaths::default().client_key);
        assert_eq!(t.error, None);
    }

    #[test]
    fn nrf_uris_parse_to_scheme_host_and_port_1617() {
        assert_eq!(
            parse_nrf_uri("https://nrf:7777"),
            Some((UriScheme::Https, "nrf".into(), 7777))
        );
        assert_eq!(
            parse_nrf_uri("HTTP://10.0.0.1/nnrf-nfm/v1"),
            Some((UriScheme::Http, "10.0.0.1".into(), 80))
        );
        assert_eq!(
            parse_nrf_uri("https://[fd00::10]:7777/x"),
            Some((UriScheme::Https, "fd00::10".into(), 7777))
        );
        assert_eq!(
            parse_nrf_uri("https://[fd00::10]"),
            Some((UriScheme::Https, "fd00::10".into(), 443))
        );
        assert_eq!(
            parse_nrf_uri("nrf:7777"),
            Some((UriScheme::Http, "nrf".into(), 7777))
        );
        assert_eq!(parse_nrf_uri("ftp://nrf:7777"), None);
        assert_eq!(parse_nrf_uri("https://"), None);
        assert_eq!(parse_nrf_uri("https://nrf:notaport"), None);
        assert_eq!(parse_nrf_uri("https://[fd00::10]x"), None);
    }

    #[test]
    fn only_the_nrf_authority_matches_1617() {
        assert!(is_nrf_authority("https://NRF:7777", "nrf", 7777));
        assert!(is_nrf_authority(
            "https://[fd00::10]:7777",
            "[fd00::10]",
            7777
        ));
        assert!(is_nrf_authority(
            "https://[fd00::10]:7777",
            "fd00::10",
            7777
        ));
        assert!(!is_nrf_authority("https://nrf:7777", "nrf", 7778));
        assert!(!is_nrf_authority("https://nrf:7777", "amf", 7777));
        assert!(!is_nrf_authority("ftp://nrf:7777", "nrf", 7777));
    }

    #[test]
    fn the_scheme_is_https_for_an_https_uri_or_the_production_profile_1617() {
        assert_eq!(
            nrf_scheme(UriScheme::Https, SbiProfile::Dev),
            UriScheme::Https
        );
        assert_eq!(
            nrf_scheme(UriScheme::Http, SbiProfile::Production),
            UriScheme::Https
        );
        assert_eq!(
            nrf_scheme(UriScheme::Http, SbiProfile::Dev),
            UriScheme::Http
        );
    }

    /// #1690 review m3: an https NRF dialled without a client certificate is a
    /// WARN (the NRF will refuse the registration), not routine INFO.
    #[test]
    fn no_client_certificate_toward_the_nrf_is_a_warning_1617() {
        let full = resolve(
            &[
                (NRF_TLS_CLIENT_CERT_ENV, "/n/amf.crt"),
                (NRF_TLS_CLIENT_KEY_ENV, "/n/amf.key"),
            ],
            &[],
        );
        assert_eq!(nrf_client_tls_log_level(&full), log::Level::Info);
        let none = resolve(&[], &[]);
        assert_eq!(none.client_cert, None);
        assert_eq!(nrf_client_tls_log_level(&none), log::Level::Warn);
        let half = resolve(&[(NRF_TLS_CLIENT_CERT_ENV, "/n/amf.crt")], &[]);
        assert_eq!(nrf_client_tls_log_level(&half), log::Level::Error);
    }
}
