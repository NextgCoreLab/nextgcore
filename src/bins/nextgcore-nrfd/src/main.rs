//! NextGCore NRF (Network Repository Function)
//!
//! The NRF is a 5G core network function responsible for:
//! - NF registration and deregistration
//! - NF discovery
//! - NF status notifications
//! - Subscription management

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_nrfd::nnrf_handler::{canonical_nf_instance_id, same_nf_instance_id};
use nextgcore_nrfd::{
    apply_json_patch, discover_profiles, json_merge_patch, nf_manager, nrf_context_final,
    nrf_context_init, nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async,
    nrf_nnrf_nfm_send_nf_status_notify_all_async, nrf_sbi_close, nrf_sbi_open, timer_manager,
    ChangeItem, DiscoveryQuery, NfProfile, NotificationEventType, NrfSmContext, PatchError,
    SbiServerConfig,
};
// The canonical TS 29.571 `DateTime` conversion. nrfd's own copies of these two
// were the ones this module was derived from; see the note where they used to live.
use nextgcore_sbi::datetime::{epoch_to_rfc3339, rfc3339_to_epoch};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::{AccessTokenResponse, OAuth2Client};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_sbi::types::NfType;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Typed YAML configuration structs for the SBI OAuth2 knob
// ---------------------------------------------------------------------------

/// SBI OAuth2 enforcement knob (`nrf.sbi.oauth2.require`).
///
/// Defaults to disabled. NOTE (TS 33.501 / TS 29.510): the NRF is itself the
/// OAuth2 Authorization Server — its `/nnrf-oauth2/v1/access-token` and
/// `/nnrf-oauth2/v1/jwks` endpoints must stay reachable WITHOUT a token (no NF
/// can obtain a token before calling the token endpoint). L1's SBI server
/// middleware has no per-path exemption, so blanket server-side enforcement is
/// NOT applied on the NRF; this knob drives the CLIENT-side token acquisition
/// for the NRF's own outbound calls (status notifications to consumers).
#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    /// Client-side: the NRF attaches NRF-issued Bearer tokens on its own
    /// outbound calls (status notifications). Existing knob.
    require: Option<bool>,
    /// nrfd-06: server-side enforcement of OAuth2 on the NRF's own
    /// nnrf-nfm / nnrf-disc producer endpoints (the /nnrf-oauth2 token and
    /// /jwks endpoints stay exempt). Default OFF so the matched simulator —
    /// whose NFs may not all attach tokens yet — is never locked out.
    require_server: Option<bool>,
    /// nrfd-05: require the token endpoint to authenticate the requesting NF.
    /// Client authentication is satisfied by EITHER a signature-verified CCA
    /// bound to the body `nfInstanceId` OR a transport-authenticated mTLS client
    /// identity bound to it (see `require_client_cert_binding`). A request
    /// carrying NEITHER is rejected (`invalid_client`).
    ///
    /// **Default ON** (issue #64 gap 1, TS 33.501 §13.3.1). Setting this to
    /// `false` is the documented escape hatch for non-TLS dev and the matched
    /// simulator: it makes the token endpoint mint a token for ANY registered
    /// `nfInstanceId` a caller cares to name, so it is announced with a startup
    /// `warn!` rather than being a silent default.
    require_client_auth: Option<bool>,
    /// Whether to trust an `x-forwarded-client-cert` header as proof of the
    /// requester's mTLS identity. **Default OFF** (issue #64 gap 2).
    ///
    /// The header is only meaningful when a TLS-terminating SBI ingress / SCP
    /// sets it and strips any client-supplied copy at the trust boundary. Nothing
    /// establishes that boundary by default here, so trusting the header
    /// unconditionally would let any client that can reach the NRF assert any
    /// identity simply by setting it — which would make
    /// `require_client_cert_binding` security theatre. Turn this on ONLY when
    /// every path to the NRF passes through a terminator that overwrites the
    /// header.
    trust_forwarded_client_cert: Option<bool>,
    /// #1990: the URI SANs (`spiffe://…` or `urn:uuid:…`) of the TLS terminators
    /// whose XFCC header is believed: the client certificate a terminator itself
    /// presents to the NRF over mTLS must carry one of them.
    trusted_xfcc_terminators: Option<Vec<String>>,
    /// I2 (TS 33.501 §13.3.1 / §13.4.1): mandate transport-layer (mTLS)
    /// authentication of the token requester. When ON, the token request MUST
    /// carry a mutually-authenticated TLS client identity whose NF Instance ID
    /// — carried in the certificate URI SubjectAltName (TS 33.310) and conveyed
    /// by the trusted TLS-terminating SBI ingress/SCP in the
    /// `x-forwarded-client-cert` header (Envoy XFCC; RFC 9440 trust model) —
    /// matches the request `nfInstanceId`. Default OFF so non-TLS dev, the
    /// matched simulator, and deployments where the NRF terminates TLS directly
    /// but does not yet surface the verified peer certificate all still
    /// function. The mismatch check itself always runs when an identity is
    /// present, independent of this flag (fail-closed on a forged binding).
    require_client_cert_binding: Option<bool>,
    /// I1 (TS 33.501 §13.3.8.3): cryptographically verify the CCA's ES256 JWS
    /// signature (not just the claim binding).
    ///
    /// **Default ON** (issue #64 gap 2). An unverified CCA is not evidence of
    /// anything: its claims are attacker-chosen, so accepting one as
    /// authentication lets any caller assert any `nfInstanceId`. With this off,
    /// `require_client_auth` demands evidence of identity and then accepts forged
    /// evidence — which is why gaps 1 and 2 had to be fixed together.
    cca_verify_signature: Option<bool>,
    /// I1: the trusted per-NF ES256 public keys the NRF verifies CCA signatures
    /// against, keyed by the signing NF's `nfInstanceId`. Each entry carries an
    /// RFC 7517 EC/P-256 JWK. When signature verification is ON and an issuer
    /// has no trusted key here, its CCA is rejected (fail-closed).
    cca_trusted_keys: Option<Vec<CcaTrustedKeyYaml>>,
    /// Issue #187: a DIRECTORY of RFC 7517 public JWKs to trust, one file per
    /// NF, named `<nfInstanceId>.jwk`. Merged over `cca_trusted_keys`, so an
    /// inline list keeps working unchanged and a directory entry wins for the
    /// same instance ID.
    ///
    /// Why a directory and not only the inline list: an NF's CCA signing key is
    /// generated by that NF on first start (see
    /// `nextgcore_sbi::oauth::CCA_SIGNING_KEY_FILE_ENV`), so its PUBLIC half
    /// does not exist when this config file is written. An inline list therefore
    /// has to quote keys that do not exist yet — which is why the docker OAuth2
    /// overlay could not provision a trust store at all and opted out of client
    /// authentication instead. A directory inverts that: each NF publishes its
    /// own public JWK at startup and the NRF trusts whatever is there.
    ///
    /// An absent or unreadable directory is NOT fatal: the store is then empty
    /// or partial, and a CCA from an NF with no key in it is rejected
    /// fail-closed (TS 33.501 §13.3.8.3) rather than accepted unverified.
    cca_trusted_keys_dir: Option<String>,
    /// Issue #393: PEM file of CA certificates that CCA signing certificates are
    /// validated against, for the `x5c` path of TS 33.501 §13.3.8.2/§13.3.8.3.
    ///
    /// This is the CONFORMANT binding. When a CCA carries `x5c`, the NRF validates
    /// the chain to one of these anchors, requires the leaf's URI SubjectAltName
    /// (TS 33.310: `urn:uuid:<nfInstanceId>`) to equal the assertion's `sub`, and
    /// verifies the JWS against the key the leaf certifies — so the certificate,
    /// not operator configuration, decides who the requester is.
    ///
    /// Precedence is deliberate and is NOT a fallback chain:
    ///
    /// - CCA carries `x5c` **and** this is set ⇒ the certificate is authoritative
    ///   and `cca_trusted_keys[_dir]` is not consulted at all, not even on failure.
    /// - CCA carries `x5c` and this is NOT set ⇒ `invalid_client`. Downgrading to
    ///   the trust store would let a requester CHOOSE the weaker check by attaching
    ///   a certificate.
    /// - CCA carries no `x5c` ⇒ the trust store, exactly as before. This is the
    ///   no-PKI path that keeps plaintext dev and the docker OAuth2 overlay working
    ///   (issue #187); it is a documented deviation from §13.3.8.2, confined here.
    cca_trust_anchors: Option<String>,
}

/// I1: one entry of the CCA trusted-key store. `jwk` is an RFC 7517 EC JWK
/// (`kty=EC, crv=P-256, x, y`) parsed by [`nextgcore_sbi::oauth::parse_es256_jwk`].
#[derive(Debug, Default, Deserialize)]
struct CcaTrustedKeyYaml {
    #[serde(rename = "nfInstanceId")]
    nf_instance_id: String,
    jwk: serde_json::Value,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    oauth2: Option<SbiOauth2Yaml>,
    /// `nrf.sbi.server[]` (#1311): the first entry's `address` / `port` is the
    /// listen address when `--sbi-addr` / `--sbi-port` are not given, and its
    /// `advertise` the host of the NRF's own URI.
    server: Option<Vec<SbiServerYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiServerYaml {
    address: Option<String>,
    advertise: Option<String>,
    port: Option<u16>,
    /// `nrf.sbi.server[0].tls` (#1617 step b): TLS on the one SBI listener.
    tls: Option<SbiServerTlsYaml>,
}

/// `nrf.sbi.server[0].tls`, the shape the shipped `nrf.yaml` files already
/// carry. Every key is optional; see [`resolve_server_tls`].
#[derive(Debug, Default, Deserialize)]
struct SbiServerTlsYaml {
    enabled: Option<bool>,
    cert: Option<String>,
    key: Option<String>,
    /// The CA a client certificate must chain to.
    ca: Option<String>,
    /// `optional` (default) or `required`.
    client_auth: Option<String>,
    /// `"1.2"` or absent: rustls negotiates TLS 1.2 or 1.3 (TS 33.501 §13.1.0,
    /// TS 33.210). Any other value is a startup error rather than ignored.
    min_version: Option<String>,
}

/// #1926 (DECISION 2026-11-19): whether the NRF requires verified callers, for
/// [`NrfPolicy::require_subscriber_identity`] (#1809) and
/// [`NrfPolicy::require_registrant_nf_types`] (#1917). Yes under the production
/// profile, and whenever the listener serves TLS: [`NrfServerTls::apply`] then
/// verifies every presented client certificate against its CA, so the NRF CAN
/// verify its callers, and the profile is only a deployment label. k8s and helm
/// run the NRF on the dev profile (#1897) with TLS, so this is what keeps the
/// refusals on there.
fn verification_required(
    profile: nextgcore_sbi::security::SbiProfile,
    server_tls: Option<&NrfServerTls>,
) -> bool {
    profile.is_production() || server_tls.is_some()
}

/// Whether the NRF's listener demands a client certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientAuth {
    /// Request one; admit a client that presents none (#1617 step 2 decision).
    /// A presented certificate must still verify against the CA.
    Optional,
    /// Refuse the handshake of a client without a valid certificate (`--mtls`).
    Required,
}

/// The TLS the NRF serves its single SBI listener with (#1617 step b).
#[derive(Debug, Clone, PartialEq, Eq)]
struct NrfServerTls {
    cert: String,
    key: String,
    ca: String,
    client_auth: ClientAuth,
}

/// Turns TLS on the NRF's listener on (`true`) or off (`false`).
const NRF_SERVER_TLS_ENV: &str = "NEXTGCORE_NRF_SERVER_TLS";
/// The NRF's server certificate (PEM).
const NRF_SERVER_TLS_CERT_ENV: &str = "NEXTGCORE_NRF_SERVER_TLS_CERT";
/// The private key of [`NRF_SERVER_TLS_CERT_ENV`].
const NRF_SERVER_TLS_KEY_ENV: &str = "NEXTGCORE_NRF_SERVER_TLS_KEY";
/// The CA a client certificate must chain to.
const NRF_SERVER_TLS_CA_ENV: &str = "NEXTGCORE_NRF_SERVER_TLS_CA";
/// `optional` or `required`.
const NRF_SERVER_TLS_CLIENT_AUTH_ENV: &str = "NEXTGCORE_NRF_SERVER_TLS_CLIENT_AUTH";

const DEFAULT_SERVER_CERT: &str = "/etc/nextgcore/tls/server.crt";
const DEFAULT_SERVER_KEY: &str = "/etc/nextgcore/tls/server.key";
const DEFAULT_CLIENT_CA: &str = "/etc/nextgcore/tls/ca.crt";

/// #1795: the NRF's listener under the SBI security profile. Under
/// `production` it must serve TLS (TS 33.501 §13.1.0): with none configured
/// this is a startup error, where it used to be a warning over a cleartext
/// listener every production NF then failed to reach. The TLS itself stays the
/// NRF's own (`nrf.sbi.server[0].tls`, its environment or `--tls`): the NRF is
/// the token issuer and the root its peers bootstrap from, so a client
/// certificate stays optional (#1617 step 2) and its token gate stays
/// `nrf.sbi.oauth2.require_server`. Under `dev` cleartext is still allowed.
fn check_listener_profile(
    profile: nextgcore_sbi::security::SbiProfile,
    server_tls: Option<&NrfServerTls>,
) -> anyhow::Result<()> {
    if profile.is_production() && server_tls.is_none() {
        anyhow::bail!(
            "the SBI profile is production but the NRF has no TLS configured, and it does not \
             serve cleartext under production (TS 33.501 §13.1.0). Enable TLS \
             (nrf.sbi.server[0].tls.enabled, {NRF_SERVER_TLS_ENV}=true or --tls), or select \
             {}=dev explicitly",
            nextgcore_sbi::security::SBI_PROFILE_ENV
        );
    }
    Ok(())
}

/// The TLS command-line flags.
#[derive(Debug, Default, Clone)]
struct TlsFlags {
    tls: bool,
    cert: Option<String>,
    key: Option<String>,
    mtls: bool,
    ca: Option<String>,
}

/// #1617 step b: the NRF listener's TLS, from the command line, else the
/// environment, else `nrf.sbi.server[0].tls`, else the defaults. `None` serves
/// cleartext h2c, as before.
///
/// With TLS on, the listener always requests a client certificate and verifies
/// a presented one against the CA: the NRF binds NFRegister / NFUpdate /
/// NFDeregister to it (TS 33.310 §6.1.3c.3, TS 33.501 §13.1.0). It requires one
/// only with `--mtls` or `client_auth: required`, so discovery, the token
/// endpoint and probes without a certificate still complete the handshake on
/// the one port.
///
/// A value that does not parse, and `--mtls` without TLS, are errors: neither
/// may silently serve weaker than the operator asked.
fn resolve_server_tls(
    flags: &TlsFlags,
    env: impl Fn(&str) -> Option<String>,
    yaml: Option<&SbiServerTlsYaml>,
) -> anyhow::Result<Option<NrfServerTls>> {
    let env = |var: &str| {
        env(var)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let env_enabled = match env(NRF_SERVER_TLS_ENV) {
        None => None,
        Some(v) => Some(match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => anyhow::bail!("{NRF_SERVER_TLS_ENV}={v:?} is not a boolean (true / false)"),
        }),
    };
    let enabled = flags.tls
        || env_enabled
            .or_else(|| yaml.and_then(|y| y.enabled))
            .unwrap_or(false);
    if !enabled {
        if flags.mtls {
            anyhow::bail!("--mtls needs TLS on the SBI listener (--tls, {NRF_SERVER_TLS_ENV}=true or nrf.sbi.server[0].tls.enabled)");
        }
        return Ok(None);
    }
    if let Some(v) = yaml.and_then(|y| y.min_version.as_deref()) {
        if v.trim() != "1.2" {
            anyhow::bail!(
                "nrf.sbi.server[0].tls.min_version {v:?} is not supported: the listener \
                 negotiates TLS 1.2 or 1.3; set \"1.2\" or remove the key"
            );
        }
    }
    let pick = |flag: &Option<String>, var: &str, yaml_value: Option<&String>, default: &str| {
        flag.clone()
            .or_else(|| env(var))
            .or_else(|| yaml_value.cloned())
            .unwrap_or_else(|| default.to_string())
    };
    let client_auth = if flags.mtls {
        ClientAuth::Required
    } else {
        match env(NRF_SERVER_TLS_CLIENT_AUTH_ENV)
            .or_else(|| yaml.and_then(|y| y.client_auth.clone()))
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("optional") => ClientAuth::Optional,
            Some("required") => ClientAuth::Required,
            Some(other) => anyhow::bail!(
                "TLS client_auth {other:?} is not one of optional, required \
                 ({NRF_SERVER_TLS_CLIENT_AUTH_ENV} / nrf.sbi.server[0].tls.client_auth)"
            ),
        }
    };
    Ok(Some(NrfServerTls {
        cert: pick(
            &flags.cert,
            NRF_SERVER_TLS_CERT_ENV,
            yaml.and_then(|y| y.cert.as_ref()),
            DEFAULT_SERVER_CERT,
        ),
        key: pick(
            &flags.key,
            NRF_SERVER_TLS_KEY_ENV,
            yaml.and_then(|y| y.key.as_ref()),
            DEFAULT_SERVER_KEY,
        ),
        ca: pick(
            &flags.ca,
            NRF_SERVER_TLS_CA_ENV,
            yaml.and_then(|y| y.ca.as_ref()),
            DEFAULT_CLIENT_CA,
        ),
        client_auth,
    }))
}

impl NrfServerTls {
    /// Every file must exist at startup, named, rather than as a handshake error.
    fn check_files(&self) -> anyhow::Result<()> {
        for (label, path) in [
            ("certificate", &self.cert),
            ("private key", &self.key),
            ("client CA certificate", &self.ca),
        ] {
            if !std::path::Path::new(path).is_file() {
                anyhow::bail!("NRF SBI TLS: the {label} {path} does not exist");
            }
        }
        Ok(())
    }

    /// Apply to the listener's configuration.
    fn apply(&self, config: NextgcoreSbiServerConfig) -> NextgcoreSbiServerConfig {
        let mut config = config.with_tls(&self.key, &self.cert);
        config.verify_client = true;
        config.verify_client_cacert = Some(self.ca.clone());
        config.verify_client_optional = self.client_auth == ClientAuth::Optional;
        config
    }

    /// The NRF client TLS the NRF uses to dial ITSELF (its OAuth2 client for its
    /// own outbound notifications, `OAuth2Client::new(nrf_self_uri())`).
    ///
    /// Explicit `NEXTGCORE_NRF_TLS_*` / `NEXTGCORE_SBI_TLS_*` settings win; what
    /// they leave unset comes from the NRF's own listener: its CA as the trust
    /// anchor, the first DNS-ID of its own certificate as the server name (the
    /// self URI's host is an address its certificate need not name), and its own
    /// certificate as the client certificate, but only when that certificate's
    /// URN names `own_id`. A certificate naming another instance would be
    /// refused by the token endpoint's binding check, so none is presented then.
    fn self_client_tls(
        &self,
        env: impl Fn(&str) -> Option<String>,
        own_id: &str,
    ) -> nextgcore_sbi::nrf_tls::NrfClientTls {
        use nextgcore_sbi::nrf_tls::{
            NrfClientTls, NRF_TLS_CA_ENV, NRF_TLS_CLIENT_CERT_ENV, NRF_TLS_CLIENT_KEY_ENV,
            NRF_TLS_SERVER_NAME_ENV,
        };
        use nextgcore_sbi::security::TlsPaths;
        let env = |var: &str| {
            env(var)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let leaf = nextgcore_sbi::tls::load_certs(&self.cert)
            .ok()
            .and_then(|chain| chain.into_iter().next());
        let names_own_id = leaf
            .as_ref()
            .and_then(|der| nextgcore_sbi::peer_cert::nf_instance_id_from_der(der.as_ref()))
            .is_some_and(|id| id.eq_ignore_ascii_case(own_id.trim()));
        let dns = leaf.as_ref().and_then(|der| {
            nextgcore_sbi::peer_cert::dns_names_from_der(der.as_ref())
                .into_iter()
                .next()
        });
        let pair_configured = [
            NRF_TLS_CLIENT_CERT_ENV,
            NRF_TLS_CLIENT_KEY_ENV,
            TlsPaths::CLIENT_CERT_ENV,
            TlsPaths::CLIENT_KEY_ENV,
        ]
        .iter()
        .any(|v| env(v).is_some());
        let ca_configured = env(NRF_TLS_CA_ENV).is_some() || env(TlsPaths::CA_ENV).is_some();
        if !pair_configured && !names_own_id {
            log::warn!(
                "the NRF's certificate {} does not name its NF instance {own_id} \
                 (urn:uuid URI SAN), so the NRF presents no client certificate to its own \
                 token endpoint",
                self.cert
            );
        }
        NrfClientTls::resolve(
            |var| {
                env(var).or_else(|| match var {
                    v if v == NRF_TLS_CA_ENV && !ca_configured => Some(self.ca.clone()),
                    v if v == NRF_TLS_SERVER_NAME_ENV => dns.clone(),
                    v if v == NRF_TLS_CLIENT_CERT_ENV && !pair_configured && names_own_id => {
                        Some(self.cert.clone())
                    }
                    v if v == NRF_TLS_CLIENT_KEY_ENV && !pair_configured && names_own_id => {
                        Some(self.key.clone())
                    }
                    _ => None,
                })
            },
            |path| std::path::Path::new(path).is_file(),
        )
    }
}

/// The config file, parsed (#1313 review). `None` when there is no file; a file
/// that cannot be read or does not parse is an error, so a typo does not fall
/// back silently to the defaults.
fn load_config(path: &str) -> anyhow::Result<Option<NrfYaml>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::debug!("Configuration file not found: {path}");
            return Ok(None);
        }
        Err(e) => anyhow::bail!("cannot read the configuration file {path}: {e}"),
    };
    log::info!("Loading configuration from {path}");
    serde_yaml::from_str(&text)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("configuration file {path} does not parse: {e}"))
}

/// Where the SBI server listens and what the NRF advertises as its own URI host.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SbiListen {
    host: String,
    port: u16,
    advertise: String,
}

/// #1311: the command line, else `nrf.sbi.server[0]`, else loopback port 7777
/// (#1308: never a wider default). The advertised host is the YAML `advertise`,
/// else the listen host.
fn resolve_sbi_listen(
    cli_addr: Option<&str>,
    cli_port: Option<u16>,
    yaml: Option<&NrfYaml>,
) -> SbiListen {
    let server = yaml
        .and_then(|y| y.nrf.as_ref())
        .and_then(|n| n.sbi.as_ref())
        .and_then(|s| s.server.as_ref())
        .and_then(|v| v.first());
    let host = cli_addr
        .map(str::to_string)
        .or_else(|| server.and_then(|s| s.address.clone()))
        .unwrap_or_else(|| nextgcore_core::sockaddr::DEFAULT_LISTEN_HOST.to_string());
    let port = cli_port
        .or_else(|| server.and_then(|s| s.port))
        .unwrap_or(7777);
    let advertise = server
        .and_then(|s| s.advertise.clone())
        .unwrap_or_else(|| host.clone());
    SbiListen {
        host,
        port,
        advertise,
    }
}

/// nrfd-10: discovery-time policy (SearchResult validityPeriod and the NRF's
/// own default / maximum page size). All optional; absent => conservative
/// defaults that never truncate the matched simulator's tiny registry.
#[derive(Debug, Default, Deserialize)]
struct DiscoveryYaml {
    validity_period: Option<u32>,
    default_page_size: Option<usize>,
    max_page_size: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfSection {
    sbi: Option<SbiYaml>,
    /// nrfd-03: NRF-preconfigured heartbeat default (seconds) used when the NF
    /// proposes none or proposes an out-of-range value.
    #[serde(rename = "heartBeatTimer")]
    heart_beat_timer: Option<u32>,
    /// nrfd-03: accepted heartbeat negotiation bounds (seconds).
    #[serde(rename = "heartBeatTimerMin")]
    heart_beat_timer_min: Option<u32>,
    #[serde(rename = "heartBeatTimerMax")]
    heart_beat_timer_max: Option<u32>,
    discovery: Option<DiscoveryYaml>,
    /// #1719: the NF Set IDs a registrant may claim in its `nfSetIdList`, and
    /// who may claim each. Absent: every set is accepted as registered (the
    /// behaviour before #1719), with a startup warning. Present, even empty:
    /// NFRegister and NFUpdate refuse any set not listed for the registrant.
    nf_set_allowlist: Option<Vec<NfSetAllowYaml>>,
}

/// #1719: one `nrf.nf_set_allowlist` entry. The NF Set ID itself names the PLMN
/// (`set<Set ID>.<nftype>set.5gc.mnc<MNC>.mcc<MCC>`, TS 23.003 §28.12), so an
/// entry per set is already per PLMN.
#[derive(Debug, Clone, Deserialize)]
struct NfSetAllowYaml {
    /// The NF Set ID, compared case-insensitively (TS 23.003 §28.12).
    nf_set_id: String,
    /// The NF types that may claim it; any type when absent.
    nf_types: Option<Vec<String>>,
    /// The NF instances that may claim it; any instance when absent. An NF
    /// Instance ID compares as the registry keys it (#1633).
    nf_instance_ids: Option<Vec<String>>,
}

impl NfSetAllowYaml {
    /// Whether this entry lets NF instance `nf_instance_id` of type `nf_type`
    /// claim set `set_id`.
    fn admits(&self, set_id: &str, nf_type: &str, nf_instance_id: &str) -> bool {
        nextgcore_nrfd::nnrf_handler::same_nf_set_id(&self.nf_set_id, set_id)
            && self
                .nf_types
                .as_ref()
                .is_none_or(|types| types.iter().any(|t| t.trim().eq_ignore_ascii_case(nf_type)))
            && self.nf_instance_ids.as_ref().is_none_or(|ids| {
                ids.iter()
                    .any(|id| same_nf_instance_id(id.trim(), nf_instance_id))
            })
    }
}

#[derive(Debug, Default, Deserialize)]
struct NrfYaml {
    nrf: Option<NrfSection>,
}

// ---------------------------------------------------------------------------
// Runtime policy (nrfd-03 / -05 / -06 / -08 / -10)
// ---------------------------------------------------------------------------

/// NRF-preconfigured heartbeat default (TS 29.510 Table 6.1.6.2.2-1: the NRF
/// "may override" the proposed value "using a preconfigured value").
const NRF_HEARTBEAT_DEFAULT: u32 = 10;
/// Accepted heartbeat negotiation bounds. A proposal outside `[min,max]` is
/// overridden to the default.
const NRF_HEARTBEAT_MIN: u32 = 1;
const NRF_HEARTBEAT_MAX: u32 = 3600;
/// Discovery SearchResult `validityPeriod` default (seconds).
const NRF_DISC_VALIDITY_PERIOD: u32 = 3600;
/// Discovery default / maximum page size. Deliberately generous so default
/// config never truncates the matched simulator (≈1 producer per NF type).
const NRF_DISC_DEFAULT_PAGE_SIZE: usize = 100;
const NRF_DISC_MAX_PAGE_SIZE: usize = 1000;
/// Subscription validity default (seconds) when the consumer proposes none.
const NRF_SUBSCRIPTION_DEFAULT_VALIDITY: u64 = 86400;

/// Resolved runtime policy. Defaults preserve the legacy / matched-sim
/// behaviour exactly; YAML knobs only widen or tighten where explicitly set.
#[derive(Debug, Clone)]
struct NrfPolicy {
    hb_default: u32,
    hb_min: u32,
    hb_max: u32,
    disc_validity_period: u32,
    disc_default_page_size: usize,
    disc_max_page_size: usize,
    /// nrfd-06: enforce OAuth2 on own nnrf-nfm/nnrf-disc endpoints.
    require_oauth2_server: bool,
    /// nrfd-05: enforce CCA (or, per I2, mTLS) client authentication at the
    /// token endpoint. Default ON (issue #64 gap 1).
    require_client_auth: bool,
    /// I2 (TS 33.501 §13.3.1/§13.4.1): mandate a transport-authenticated (mTLS)
    /// client identity bound to the request `nfInstanceId`.
    require_client_cert_binding: bool,
    /// Issue #64 gap 2: whether an `x-forwarded-client-cert` header is trusted as
    /// proof of mTLS identity. Default OFF — without a TLS terminator that
    /// overwrites the header, any client can set it.
    trust_forwarded_client_cert: bool,
    /// #1990: the URI SANs of the terminators whose XFCC header is believed
    /// ([`from_trusted_terminator`]). Empty: no header is believed.
    trusted_xfcc_terminators: Vec<String>,
    /// #1617: refuse NFRegister / NFUpdate / NFDeregister from a caller with no
    /// verified certificate identity ([`RegistrantIdentity::require_certificate`]),
    /// `400 INVALID_CLIENT`. Always ON: the operator decision on #1617 refuses
    /// such a caller on every listener, plaintext included, and there is no
    /// opt-out (every shipped deployment presents NF certificates since steps
    /// d1-d3). A field rather than a constant only so the handlers read one policy.
    require_registrant_identity: bool,
    /// #1809: NFStatusSubscribe needs a verified consumer identity, and an
    /// ownerless subscription (restored from a state file written before
    /// #1809) cannot be updated or removed. ON under the `production` SBI
    /// profile (set in `main`), OFF under `dev`, where a plaintext stack has no
    /// identity to bind to. Default ON: a policy nobody set fails closed.
    require_subscriber_identity: bool,
    /// #1917: NFRegister / NFUpdate / NFDeregister need the NF type from the
    /// caller's OWN verified certificate (RFC 9310 NFTypes, TS 33.310 §6.1.3c.3),
    /// and the profile's `nfType` must be one of them. Refused `400
    /// INVALID_CLIENT` when the certificate names no NF type, or when the identity
    /// came only through a forwarded header (the connection's certificate is then
    /// the terminator's). Without this an SMF whose certificate carried no NFTypes
    /// could register as AUSF and be granted nudm-ueau tokens (#1866). ON under the
    /// `production` SBI profile (set in `main`), OFF under `dev`. Default ON: a
    /// policy nobody set fails closed.
    require_registrant_nf_types: bool,
    /// I1 (TS 33.501 §13.3.8.3): cryptographically verify the CCA ES256 JWS
    /// signature (not just the claim binding). Default ON (issue #64 gap 2).
    cca_verify_signature: bool,
    /// I1: `nfInstanceId` -> trusted ES256 verifying key used to check the CCA
    /// signature. Populated from `nrf.sbi.oauth2.cca_trusted_keys` and, when
    /// configured, from `cca_trusted_keys_dir` at startup.
    cca_trusted_keys: std::collections::HashMap<String, p256::ecdsa::VerifyingKey>,
    /// #1633: canonical NF IDs whose trust-store entries conflicted at load
    /// (case variants with different keys). Trusted with no key, from any source,
    /// for the NRF's life: the on-disk lookup refuses them too.
    cca_conflicted: std::collections::HashSet<String>,
    /// Issue #187: the directory `cca_trusted_keys` may be RE-read from when an
    /// issuer is not already in the map.
    ///
    /// Necessary rather than merely convenient: the NRF starts FIRST (every other
    /// NF `depends_on` it), and each NF publishes its own public JWK when it
    /// starts — so at the NRF's startup the directory is legitimately empty or
    /// partial. A startup-only read would therefore trust nobody, which is the
    /// same dead end as the inline list having to quote keys that do not exist
    /// yet. Re-reading on a miss is the same shape as `JwksCache`'s refresh on an
    /// unknown `kid`.
    ///
    /// This does not weaken the fail-closed posture: a miss consults the
    /// directory and, finding nothing, still rejects (TS 33.501 §13.3.8.3). It
    /// only removes a startup-ordering dependency.
    cca_trusted_keys_dir: Option<std::path::PathBuf>,
    /// Issue #393: DER CA certificates a CCA's `x5c` chain is validated against
    /// (TS 33.501 §13.3.8.3). Loaded once at startup from
    /// `nrf.sbi.oauth2.cca_trust_anchors`.
    ///
    /// Empty means the `x5c` path is not configured, and a CCA that carries `x5c`
    /// is then REFUSED rather than downgraded to the trust store — see the
    /// precedence rules on the YAML field.
    cca_trust_anchors: Vec<Vec<u8>>,
    /// #1719: `nrf.nf_set_allowlist`. `None` accepts every registrant's
    /// `nfSetIdList` as sent.
    nf_set_allowlist: Option<Vec<NfSetAllowYaml>>,
}

impl Default for NrfPolicy {
    fn default() -> Self {
        Self {
            hb_default: NRF_HEARTBEAT_DEFAULT,
            hb_min: NRF_HEARTBEAT_MIN,
            hb_max: NRF_HEARTBEAT_MAX,
            disc_validity_period: NRF_DISC_VALIDITY_PERIOD,
            disc_default_page_size: NRF_DISC_DEFAULT_PAGE_SIZE,
            disc_max_page_size: NRF_DISC_MAX_PAGE_SIZE,
            require_oauth2_server: false,
            // Issue #64 gaps 1+2 (TS 33.501 §13.3.1/§13.4.1.1): the token
            // endpoint authenticates the requester, and the only evidence it
            // accepts is unforgeable. These two defaults are one decision: an
            // enforced requirement that accepts an unsigned CCA is no
            // requirement at all.
            require_client_auth: true,
            cca_verify_signature: true,
            // Requiring mTLS *specifically* remains opt-in: a plaintext dev
            // deployment cannot satisfy it, and a signed CCA is the TS 33.501
            // §13.3.8 alternative for exactly that case.
            require_client_cert_binding: false,
            // The forwarded-cert header is only as trustworthy as the terminator
            // that sets it, and nothing here guarantees one exists.
            trust_forwarded_client_cert: false,
            trusted_xfcc_terminators: Vec::new(),
            // #1617 step f: no knob. TS 33.501 §13.3.1.1 permits implicit NF-NRF
            // authentication; the operator chose not to rely on it.
            require_registrant_identity: true,
            require_subscriber_identity: true,
            require_registrant_nf_types: true,
            cca_trusted_keys: std::collections::HashMap::new(),
            cca_conflicted: std::collections::HashSet::new(),
            cca_trusted_keys_dir: None,
            // Issue #393: no PKI by default. An NF that presents `x5c` against
            // this is refused (not downgraded), and an NF that presents none takes
            // the trust-store path — so the shipped default is byte-compatible
            // with #187's overlay.
            cca_trust_anchors: Vec::new(),
            // #1719: existing deployments keep working; startup warns.
            nf_set_allowlist: None,
        }
    }
}

impl NrfPolicy {
    /// #1719: the NF Set IDs in `sets` that NF instance `nf_instance_id` of type
    /// `nf_type` may not claim under `nrf.nf_set_allowlist`; empty when every one
    /// is allowed, or when no allowlist is configured.
    fn unallowed_nf_sets<'a>(
        &self,
        sets: impl IntoIterator<Item = &'a str>,
        nf_type: &str,
        nf_instance_id: &str,
    ) -> Vec<&'a str> {
        let Some(allow) = self.nf_set_allowlist.as_ref() else {
            return Vec::new();
        };
        sets.into_iter()
            .filter(|set| !allow.iter().any(|a| a.admits(set, nf_type, nf_instance_id)))
            .collect()
    }
}

/// #1719 (R19): strip from each of `profiles` (at startup, every profile restored
/// from the state file) each NF Set `policy` does not allow it, and store the
/// result. Returns each changed profile with its change items, for the
/// NF_PROFILE_CHANGED notification.
///
/// Stripping, not deregistering, is the spec-safe choice: the issue's option 1
/// allows "refuses or strips", and the NF keeps serving its services, which are
/// not in question. Only the unauthorised membership claim goes. A deregistered
/// NF would get 404 on its next heartbeat, re-register with the same claim, and
/// be refused 403, so it would leave service altogether. A stripped NF that
/// re-sends the claim on a later NFRegister or NFUpdate is refused as any other
/// registrant is.
fn strip_unallowed_restored_nf_sets(
    policy: &NrfPolicy,
    profiles: Vec<NfProfile>,
) -> Vec<(NfProfile, Vec<ChangeItem>)> {
    let manager = nf_manager();
    let mut changed = Vec::new();
    for profile in profiles {
        let pre = profile.to_json();
        let refused: Vec<String> = policy
            .unallowed_nf_sets(
                nf_set_ids_of(&pre),
                &profile.nf_type,
                &profile.nf_instance_id,
            )
            .into_iter()
            .map(String::from)
            .collect();
        if refused.is_empty() {
            continue;
        }
        let kept: Vec<serde_json::Value> = pre
            .get("nfSetIdList")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter(|v| v.as_str().is_none_or(|s| !refused.iter().any(|r| r == s)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut post = pre.clone();
        let patch = if kept.is_empty() {
            if let Some(obj) = post.as_object_mut() {
                obj.remove("nfSetIdList");
            }
            serde_json::json!([{"op": "remove", "path": "/nfSetIdList"}])
        } else {
            post["nfSetIdList"] = serde_json::Value::Array(kept.clone());
            serde_json::json!([{"op": "replace", "path": "/nfSetIdList", "value": kept}])
        };
        let updated = match NfProfile::from_json(&post) {
            Ok(p) => p,
            Err(missing) => {
                log::error!(
                    "nrfd-1719: restored NF instance {} no longer parses after stripping \
                     NF Set(s) {refused:?} (missing {missing:?}); left unchanged",
                    profile.nf_instance_id
                );
                continue;
            }
        };
        if let Err(e) = manager.register(updated.clone()) {
            log::error!(
                "nrfd-1719: cannot store restored NF instance {} without NF Set(s) \
                 {refused:?}: {e}",
                profile.nf_instance_id
            );
            continue;
        }
        log::warn!(
            "nrfd-1719: restored NF instance {} ({}) claimed NF Set(s) {refused:?} that \
             nrf.nf_set_allowlist does not allow for it; the claim is removed from its \
             profile, and an NFRegister or NFUpdate re-adding it is refused 403",
            profile.nf_instance_id,
            profile.nf_type
        );
        let changes = compute_profile_changes(&pre, &post, &patch, true);
        changed.push((updated, changes));
    }
    changed
}

/// #1719 (R19): what `main` does with the profiles the state file restored, once
/// the allowlist is known: strip each set it may not claim
/// ([`strip_unallowed_restored_nf_sets`]) and tell the subscribers to each changed
/// profile NF_PROFILE_CHANGED with its change items (TS 29.510 §5.2.2.6). One
/// function rather than a loop in `main`, so the notification is tested
/// (#1822 item 4).
fn enforce_nf_set_allowlist_at_restore(policy: &NrfPolicy, restored: Vec<NfProfile>) {
    for (profile, changes) in strip_unallowed_restored_nf_sets(policy, restored) {
        let server_uri = nrf_self_uri().to_string();
        tokio::spawn(async move {
            if let Err(e) = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
                &profile,
                &server_uri,
                changes,
            )
            .await
            {
                log::error!("Failed to send NF_PROFILE_CHANGED (nf_set_allowlist): {e}");
            }
        });
    }
}

/// The `nfSetIdList` strings of an NFProfile document (TS 29.510 §6.1.6.2.2).
fn nf_set_ids_of(doc: &serde_json::Value) -> Vec<&str> {
    doc.get("nfSetIdList")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
}

/// #1719: refuse an NFRegister or NFUpdate whose profile claims an NF Set the
/// registrant is not provisioned for in `nrf.nf_set_allowlist`. 403, because the
/// request is well formed and the operator's policy forbids it; nothing is
/// stored. `Some` is the refusal to send.
fn refuse_unallowed_nf_sets(
    operation: &str,
    nf_instance_id: &str,
    nf_type: &str,
    claimed: Vec<&str>,
) -> Option<SbiResponse> {
    #[cfg(test)]
    let test_policy = tests_nf_set_ids_1719::ALLOWLIST
        .try_with(|allow| NrfPolicy {
            nf_set_allowlist: allow.clone(),
            ..NrfPolicy::default()
        })
        .ok();
    #[cfg(not(test))]
    let test_policy: Option<NrfPolicy> = None;
    let refused = test_policy
        .as_ref()
        .unwrap_or_else(|| nrf_policy())
        .unallowed_nf_sets(claimed, nf_type, nf_instance_id);
    if refused.is_empty() {
        return None;
    }
    log::warn!(
        "{operation} for NF instance {nf_instance_id} ({nf_type}) refused: nfSetIdList claims \
         {refused:?}, which nrf.nf_set_allowlist does not allow for it"
    );
    Some(send_error(
        403,
        "Forbidden",
        &format!(
            "{operation}: NF instance {nf_instance_id:?} ({nf_type}) may not claim NF Set(s) \
             {refused:?} (nrf.nf_set_allowlist)"
        ),
        None,
    ))
}

/// #2035: refuse an NFRegister or NFUpdate of an AMF whose `amfInfo.guamiList`
/// adds a GUAMI another AMF, outside its AMF Set, already lists. A GUAMI
/// identifies one AMF (TS 23.003 §2.10.1), shared only within an AMF Set; an
/// AMF listing another's would be believed to serve it (pcfd's AMF-relocation
/// check, #2013). `backupInfoAmfFailure` / `backupInfoAmfRemoval` are not
/// checked: there an AMF names the GUAMIs it backs up. 403, nothing stored.
fn refuse_guami_of_another_set(
    operation: &str,
    nf_instance_id: &str,
    nf_type: &str,
    doc: &serde_json::Value,
    added: &[&serde_json::Value],
) -> Option<SbiResponse> {
    if !nf_type.eq_ignore_ascii_case("AMF") || added.is_empty() {
        return None;
    }
    let others = nf_manager().list();
    let (guami, holder) =
        nextgcore_nrfd::sbi_path::guami_listed_by_another_set(nf_instance_id, doc, added, &others)?;
    log::warn!(
        "{operation} for AMF {nf_instance_id} refused: its guamiList has {guami}, which AMF          {holder} of another AMF Set already lists"
    );
    Some(send_error(
        403,
        "Forbidden",
        &format!(
            "{operation}: AMF {nf_instance_id:?} may not list GUAMI {guami}: another AMF              outside its AMF Set lists it (TS 23.003 §2.10.1)"
        ),
        None,
    ))
}

/// The CCA trusted keys one source configures, keyed canonically (#1633).
///
/// Since #1657 an NF's UUID in either case is one key. Two entries that spell
/// one UUID differently and hold different keys are therefore a conflict, and
/// neither is trusted: keeping one would let the file or list order decide which
/// key verifies that NF (key confusion). The NF's CCA then fails closed, and the
/// WARN names both entries. The same key twice is kept.
struct TrustedKeySet {
    source: &'static str,
    keys: std::collections::HashMap<String, p256::ecdsa::VerifyingKey>,
    conflicted: std::collections::HashSet<String>,
}

impl TrustedKeySet {
    /// Every `<nfInstanceId>.jwk` in `dir`, or only those whose ID names the NF
    /// `only` (any case of its UUID) when given (#1633).
    fn read_dir(dir: &std::path::Path, only: Option<&str>) -> std::io::Result<Self> {
        let mut found = Self::new("cca_trusted_keys_dir");
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            // The extension is the contract with `publish_cca_public_jwk`; skip
            // anything else so a README or a private key sitting alongside is
            // not misread as a trust-store entry.
            if path.extension().and_then(|e| e.to_str())
                != Some(nextgcore_sbi::oauth::CCA_PUBLIC_JWK_EXTENSION)
            {
                continue;
            }
            let Some(nf_instance_id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if only.is_some_and(|nf| canonical_nf_instance_id(nf_instance_id) != nf) {
                continue;
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    log::warn!("nrfd-187: cannot read {}: {e}", path.display());
                    continue;
                }
            };
            let jwk: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("nrfd-187: {} is not valid JSON: {e}", path.display());
                    continue;
                }
            };
            match nextgcore_sbi::oauth::parse_es256_jwk(&jwk) {
                // Keyed canonically, as the inline keys are (#1633).
                Ok(key) => found.add(nf_instance_id, key),
                Err(e) => log::warn!(
                    "nrfd-187: {} does not hold a usable ES256 public JWK: {e}. The CCA of \
                     nfInstanceId {nf_instance_id:?} cannot be verified and will be rejected.",
                    path.display()
                ),
            }
        }
        Ok(found)
    }

    /// Fold this source into `policy`: its keys extend (and, for the directory,
    /// override) the store, and a conflicted NF is removed from it and recorded,
    /// so no other source keeps a key for it either (#1633).
    fn merge_into(self, policy: &mut NrfPolicy) {
        policy.cca_trusted_keys.extend(self.keys);
        policy.cca_conflicted.extend(self.conflicted);
        for id in &policy.cca_conflicted {
            policy.cca_trusted_keys.remove(id);
        }
    }

    fn new(source: &'static str) -> Self {
        Self {
            source,
            keys: std::collections::HashMap::new(),
            conflicted: std::collections::HashSet::new(),
        }
    }

    fn add(&mut self, nf_instance_id: &str, key: p256::ecdsa::VerifyingKey) {
        let id = canonical_nf_instance_id(nf_instance_id);
        if self.conflicted.contains(&id) {
            return;
        }
        match self.keys.get(&id) {
            Some(held) if *held != key => {
                report_cca_key_conflict(self.source, &id, nf_instance_id);
                self.keys.remove(&id);
                self.conflicted.insert(id);
            }
            Some(_) => {}
            None => {
                self.keys.insert(id, key);
            }
        }
    }
}

impl NrfPolicy {
    /// Fold parsed YAML over the defaults (only set knobs take effect).
    fn from_yaml(yaml: &NrfYaml) -> Self {
        let mut p = Self::default();
        let Some(nrf) = yaml.nrf.as_ref() else {
            return p;
        };
        if let Some(hb) = nrf.heart_beat_timer {
            p.hb_default = hb;
        }
        if let Some(min) = nrf.heart_beat_timer_min {
            p.hb_min = min;
        }
        if let Some(max) = nrf.heart_beat_timer_max {
            p.hb_max = max;
        }
        p.nf_set_allowlist = nrf.nf_set_allowlist.clone();
        if let Some(d) = nrf.discovery.as_ref() {
            if let Some(v) = d.validity_period {
                p.disc_validity_period = v;
            }
            if let Some(v) = d.default_page_size.filter(|n| *n > 0) {
                p.disc_default_page_size = v;
            }
            if let Some(v) = d.max_page_size.filter(|n| *n > 0) {
                p.disc_max_page_size = v;
            }
        }
        if let Some(o) = nrf.sbi.as_ref().and_then(|s| s.oauth2.as_ref()) {
            // Only an EXPLICITLY set knob overrides the default. `unwrap_or(false)`
            // would silently undo a secure default for every config file that has
            // an `oauth2:` section at all but omits the key -- which is most of
            // them -- so the default would look secure in code and be off in
            // every deployment (issue #64 gaps 1+2).
            if let Some(v) = o.require_server {
                p.require_oauth2_server = v;
            }
            if let Some(v) = o.require_client_auth {
                p.require_client_auth = v;
            }
            // I2 (TS 33.501 §13.3.1/§13.4.1): mTLS client-cert binding.
            if let Some(v) = o.require_client_cert_binding {
                p.require_client_cert_binding = v;
            }
            // Issue #64 gap 2: trusting the forwarded-cert header is opt-in.
            if let Some(v) = o.trust_forwarded_client_cert {
                p.trust_forwarded_client_cert = v;
            }
            if let Some(v) = o.trusted_xfcc_terminators.as_ref() {
                p.trusted_xfcc_terminators = v.iter().map(|t| t.trim().to_string()).collect();
            }
            // I1 (TS 33.501 §13.3.8.3): CCA ES256 JWS signature verification.
            if let Some(v) = o.cca_verify_signature {
                p.cca_verify_signature = v;
            }
            if let Some(keys) = o.cca_trusted_keys.as_ref() {
                let mut inline = TrustedKeySet::new("cca_trusted_keys");
                for entry in keys {
                    match nextgcore_sbi::oauth::parse_es256_jwk(&entry.jwk) {
                        Ok(key) => {
                            // Keyed as the registry keys an NF (#1633), so a
                            // UUID configured in either case is found.
                            inline.add(&entry.nf_instance_id, key);
                        }
                        // A malformed key is dropped (not fatal): the issuer
                        // then has no trusted key and its CCA is rejected at
                        // runtime when verification is ON — i.e. fail-closed.
                        Err(e) => log::warn!(
                            "nrfd-I1: ignoring malformed CCA trusted key for nfInstanceId {:?}: {e}",
                            entry.nf_instance_id
                        ),
                    }
                }
                inline.merge_into(&mut p);
            }
            // Issue #187: merge the directory store over the inline list. Done
            // second so a live, NF-published key wins over a stale inline one.
            if let Some(dir) = o
                .cca_trusted_keys_dir
                .as_deref()
                .map(str::trim)
                .filter(|d| !d.is_empty())
            {
                let dir = std::path::PathBuf::from(dir);
                p.load_cca_trusted_keys_dir(&dir);
                // Kept so a key published AFTER the NRF started is still found:
                // the NRF boots before the NFs that publish into this directory.
                p.cca_trusted_keys_dir = Some(dir);
            }
            // Issue #393: the CCA certificate trust anchors for the `x5c` path
            // (TS 33.501 §13.3.8.3).
            if let Some(path) = o
                .cca_trust_anchors
                .as_deref()
                .map(str::trim)
                .filter(|p| !p.is_empty())
            {
                p.load_cca_trust_anchors(std::path::Path::new(path));
            }
        }
        p
    }

    /// Issue #393: load the CA certificates a CCA's `x5c` chain is validated
    /// against (TS 33.501 §13.3.8.3).
    ///
    /// A failure is a `warn!` and not fatal, which is NOT a weakening: with no
    /// anchors loaded, `authenticate_token_client` refuses every `x5c`-bearing CCA
    /// rather than falling back to the trust store. So a misconfigured anchor file
    /// makes the conformant path unavailable and fail-closed, instead of making the
    /// NRF trust chains it cannot validate. The log names that consequence, because
    /// the symptom at the far end is a bare `invalid_client`.
    fn load_cca_trust_anchors(&mut self, path: &std::path::Path) {
        match nextgcore_sbi::tls::load_certs(&path.display().to_string()) {
            Ok(certs) if certs.is_empty() => log::warn!(
                "nrfd-393: the CCA trust-anchor file {} holds no certificates. Every CCA that \
                 carries an x5c chain will be refused invalid_client (TS 33.501 §13.3.8.3); NFs \
                 with no x5c still use the cca_trusted_keys store.",
                path.display()
            ),
            Ok(certs) => {
                self.cca_trust_anchors = certs.into_iter().map(|c| c.as_ref().to_vec()).collect();
                log::info!(
                    "nrfd-393: loaded {} CCA trust anchor(s) from {}; a CCA carrying x5c is now \
                     bound to its certificate's NF Instance ID (TS 33.501 §13.3.8.3, TS 33.310)",
                    self.cca_trust_anchors.len(),
                    path.display()
                );
            }
            Err(e) => log::warn!(
                "nrfd-393: cannot read the CCA trust-anchor file {}: {e}. Every CCA that carries \
                 an x5c chain will be refused invalid_client; NFs with no x5c still use the \
                 cca_trusted_keys store.",
                path.display()
            ),
        }
    }

    /// Issue #187: load every `<nfInstanceId>.jwk` in `dir` into the CCA trust
    /// store, keyed by the file stem.
    ///
    /// Every failure is a `warn!` and not fatal, at each granularity — a missing
    /// directory, an unreadable entry, a malformed JWK. The reason is the same one
    /// the inline loader gives: an issuer with no trusted key has its CCA rejected
    /// fail-closed at runtime (TS 33.501 §13.3.8.3), so a partial store is safe,
    /// while refusing to start would take the whole core's Authorization Server
    /// down over one bad file. The `warn!` names the consequence so the operator
    /// is not left guessing why one NF gets `invalid_client`.
    fn load_cca_trusted_keys_dir(&mut self, dir: &std::path::Path) {
        let found = match TrustedKeySet::read_dir(dir, None) {
            Ok(found) => found,
            Err(e) => {
                log::warn!(
                    "nrfd-187: cannot read the CCA trusted-key directory {}: {e}. No NF's CCA \
                     can be verified from it, so those NFs will be refused invalid_client \
                     unless an inline cca_trusted_keys entry covers them.",
                    dir.display()
                );
                return;
            }
        };
        log::info!(
            "nrfd-187: loaded {} CCA trusted key(s) from {}",
            found.keys.len(),
            dir.display()
        );
        found.merge_into(self);
    }

    /// I2: runtime overrides for the client-authentication knobs so a posture
    /// change can be A/B-tested in docker WITHOUT a code edit (mirrors the H9
    /// NAS-security canary runtime-knob pattern). An absent or non-truthy value
    /// leaves the knob at whatever config resolved, so these are additive.
    ///
    /// Tightening (`NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH`,
    /// `NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING`,
    /// `NRF_SBI_OAUTH2_TRUST_FORWARDED_CLIENT_CERT`) forces the knob ON.
    ///
    /// `NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED` is the one LOOSENING override
    /// (issue #64 gap 1's documented escape hatch): it turns client
    /// authentication off for non-TLS dev and the matched simulator. It is
    /// applied last so it wins over the tightening knob, and the caller
    /// announces it with a `warn!` — the insecure posture stays reachable, but
    /// only when asked for by name.
    fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_under(nextgcore_sbi::security::SbiProfile::resolve());
    }

    /// [`Self::apply_env_overrides`] under `profile` (#1990: the trusted-terminator
    /// variable is ignored under production).
    fn apply_env_overrides_under(&mut self, profile: nextgcore_sbi::security::SbiProfile) {
        let forced_on = |key: &str| {
            matches!(
                std::env::var(key).ok().as_deref().map(str::trim),
                Some("1") | Some("true") | Some("TRUE")
            )
        };
        if forced_on("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH") {
            self.require_client_auth = true;
        }
        if forced_on("NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING") {
            self.require_client_cert_binding = true;
        }
        if forced_on("NRF_SBI_OAUTH2_TRUST_FORWARDED_CLIENT_CERT") {
            // #1990: an environment variable is not where a production NRF learns
            // to trust a header any client can send. Under the production profile
            // only the YAML (`nrf.sbi.oauth2.trust_forwarded_client_cert`), which
            // the operator deploys with the terminator, turns it on.
            if profile.is_production() {
                log::warn!(
                    "NRF_SBI_OAUTH2_TRUST_FORWARDED_CLIENT_CERT is ignored under the production \
                     SBI profile: declare the TLS terminator in nrf.sbi.oauth2 instead"
                );
            } else {
                self.trust_forwarded_client_cert = true;
            }
        }
        if forced_on("NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED") {
            self.require_client_auth = false;
        }
    }
}

/// Process-wide resolved policy, set once at startup. Handlers read it via
/// [`nrf_policy`]; before initialisation (e.g. in unit tests) the safe
/// [`NrfPolicy::default`] applies.
static NRF_POLICY: OnceLock<NrfPolicy> = OnceLock::new();

fn nrf_policy() -> &'static NrfPolicy {
    NRF_POLICY.get_or_init(NrfPolicy::default)
}

/// Per-process ES256 (ECDSA P-256) signing key, generated once at startup.
/// Asymmetric so consumers can verify tokens with the public key (published via
/// JWKS in a later stage) without sharing a secret.
static NRF_SIGNING_KEY: OnceLock<p256::ecdsa::SigningKey> = OnceLock::new();

/// Key id advertised in the JWT header and (later) the JWKS document.
const NRF_KID: &str = "nrf-es256";

/// The NRF's own SBI URI, set once at startup from CLI args.
static NRF_SELF_URI: OnceLock<String> = OnceLock::new();

/// The NRF's own NF Instance ID (UUID). Used as the OAuth2 `iss` claim per
/// TS 29.510 §6.3.5.2.4 (issuer = NF Instance ID of the NRF).
///
/// Issue #187: resolved through the shared
/// [`nextgcore_sbi::nf_instance_id`] resolver, so `--nf-instance-id` (seeded
/// into it at startup), `NEXTGCORE_NF_INSTANCE_ID` and
/// `NEXTGCORE_NRF_INSTANCE_ID` all pin it by the same rules every other NF
/// follows. The NRF needs a pinnable ID for the same reason its consumers do:
/// with `oauth2.require: true` it requests tokens from ITSELF for its outbound
/// status notifications, and it is not exempt from its own client-authentication
/// policy — so its own public key has to be in its own trust store, keyed by
/// this value.
fn nrf_instance_id() -> &'static str {
    nextgcore_sbi::nf_instance_id::nf_instance_id(NfType::Nrf)
}

fn nrf_self_uri() -> &'static str {
    NRF_SELF_URI
        .get()
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:7777")
}

/// Build the NRF's own NFProfile, so it appears in its own registry as the
/// consumer it actually is (issue #187, criterion 5).
///
/// TS 29.510 §6.1.6.2.2 mandates only `nfInstanceId`, `nfType` and `nfStatus`
/// (`MANDATORY_PROFILE_ATTRS`); the endpoints are included because
/// `authorize_access_token` and the discovery filters read them, and a profile
/// that omitted them would be a differently-shaped entry from every other NF's.
fn nrf_self_profile() -> serde_json::Value {
    nrf_self_profile_for(nrf_self_uri())
}

/// [`nrf_self_profile`] for the NRF reached at `uri` (#1324: testable by host type).
fn nrf_self_profile_for(uri: &str) -> serde_json::Value {
    let (scheme, host_port) = match uri.split_once("://") {
        Some((s, rest)) => (s, rest),
        None => ("http", uri),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(7777)),
        None => (host_port, 7777),
    };
    let services: Vec<serde_json::Value> = ["nnrf-nfm", "nnrf-disc", "nnrf-oauth2"]
        .iter()
        .map(|name| {
            serde_json::json!({
                "serviceInstanceId": name,
                "serviceName": name,
                "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.0.0" }],
                "scheme": scheme,
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{ "ipv4Address": host, "port": port, "transport": "TCP" }],
            })
        })
        .collect();
    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nrf_instance_id(),
            "nfType": NfType::Nrf.to_str(),
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [host],
            // #1644 review B1: the NRF's own APIs, so the token endpoint can grant
            // the `nnrf-nfm` / `nnrf-disc` scope that the nrfd-06 gate requires
            // (TS 29.510 §5.2.2.2.3 b: an NRF profile lists nnrf-disc, nnrf-nfm and
            // optionally nnrf-oauth2).
            "nfServices": services,
        }),
        host,
    )
}

/// Register the NRF in its own registry (issue #187, criterion 5).
///
/// The token endpoint refuses a requester `nf_manager()` does not know, and the
/// NRF requests tokens from itself for its outbound NF status notifications. So
/// without this its own notifications are refused `invalid_client` the moment
/// client authentication is on — an NRF locked out of itself.
///
/// Idempotent: `NfInstanceManager::register` inserts by instance ID, and the ID
/// is stable across restarts once pinned, so a restart overwrites its own entry
/// rather than accumulating one per start.
/// Whether the NRF puts itself in its own registry at startup (#187, #1644 review
/// m4): when it requests tokens from itself (`require_oauth2`), and when its own
/// nnrf-nfm / nnrf-disc are gated (`require_server`), because a token for them is
/// minted only when a registered NRF offers the service.
fn registers_itself(require_oauth2: bool, require_server: bool) -> bool {
    require_oauth2 || require_server
}

/// The one lock for tests that add or remove the NRF's own entry in the
/// process-global registry (#1644 review M1), declared beside the function that
/// writes it: a test deregistering the entry raced one that needs it.
///
/// It also covers the dev PKI's NRF row (`docker/rust/certs/nf-identities.txt`,
/// `...0000000000f0`), the NRF's own entry in the shipped stack: the #1617
/// listener test registers it as the NRF's self client, and the dev-PKI test
/// needs it absent (#1733: the two overlapped and saw each other's entry).
#[cfg(test)]
fn self_entry_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// #1617 step f: when nothing needs the NRF's own entry (`registers_itself` is
/// false) but the state file restored one from a run that did, remove it.
/// The entry never gets a no-heartbeat timer (#1644 review M2), so it would
/// otherwise stay REGISTERED and discoverable for the life of the state file,
/// naming an NRF profile this process does not maintain. Returns whether an
/// entry was removed.
///
/// #1821: the removal is a deregistration like any other, so the subscribers
/// whose conditions match the entry are told NF_DEREGISTERED (TS 29.510
/// §5.2.2.6.1), as `handle_nf_deregister` and the no-heartbeat expiry tell
/// theirs. Before, the entry vanished silently and a subscriber kept it cached.
/// The subscriptions restored from the same state file are already in the
/// registry when `main` calls this.
fn drop_restored_self_entry() -> bool {
    let Some(profile) = nf_manager().get(nrf_instance_id()) else {
        return false;
    };
    match nf_manager().deregister(nrf_instance_id()) {
        Ok(_) => {
            log::info!(
                "nrfd-187: removed the NRF's own entry {} restored from the state file; \
                 this configuration does not register the NRF in its own registry",
                nrf_instance_id()
            );
            let server_uri = nrf_self_uri().to_string();
            tokio::spawn(async move {
                if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                    NotificationEventType::NfDeregistered,
                    &profile,
                    &server_uri,
                )
                .await
                {
                    log::error!(
                        "Failed to send NF_DEREGISTERED for the NRF's dropped own entry: {e}"
                    );
                }
            });
            true
        }
        Err(e) => {
            log::warn!("nrfd-187: could not remove the restored NRF entry: {e}");
            false
        }
    }
}

fn register_self_with_own_registry() {
    // #1644 review M2: whatever armed one before (a restored registry), the NRF's
    // own entry has no no-heartbeat timer.
    disarm_heartbeat_timer(nrf_instance_id());
    let doc = nrf_self_profile();
    match NfProfile::from_json(&doc) {
        Ok(profile) => match nf_manager().register(profile) {
            Ok(()) => log::info!(
                "nrfd-187: the NRF registered ITSELF as {} so its own access-token requests \
                 are from a known client (TS 29.510 §6.3.5.2.2)",
                nrf_instance_id()
            ),
            Err(e) => log::error!(
                "nrfd-187: the NRF could not register itself ({e}); its own outbound \
                 notifications will be refused invalid_client while require_client_auth is on"
            ),
        },
        // Unreachable unless `nrf_self_profile` regresses; logged rather than
        // panicking, because a live NRF failing to notify is better than one
        // that will not start.
        Err(missing) => log::error!(
            "nrfd-187: the NRF's own NFProfile is missing mandatory attributes {missing:?}"
        ),
    }
}

/// Where the ES256 signing key is persisted, when the operator configured a path
/// (issue #64 gap 4). Set once at startup from `--signing-key-file`.
static NRF_SIGNING_KEY_FILE: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Access-token lifetime in seconds (`expires_in`), from `--token-expires-in`.
static NRF_TOKEN_EXPIRES_IN: OnceLock<u64> = OnceLock::new();

/// Default access-token lifetime, matching the value that used to be hardcoded.
const DEFAULT_TOKEN_EXPIRES_IN_SECS: u64 = 3600;

/// The configured access-token lifetime (issue #64 gap 4).
fn nrf_token_expires_in() -> u64 {
    *NRF_TOKEN_EXPIRES_IN
        .get()
        .unwrap_or(&DEFAULT_TOKEN_EXPIRES_IN_SECS)
}

/// Generate a fresh ES256 signing key.
fn generate_signing_key() -> p256::ecdsa::SigningKey {
    nextgcore_sbi::oauth::generate_es256_key()
}

/// Load the signing key from `path`, or generate one and persist it there.
///
/// Issue #64 gap 4: the key used to be generated per process under a FIXED `kid`
/// (`nrf-es256`). So every restart, and every additional HA NRF instance, published
/// a DIFFERENT public key under the SAME `kid` — a producer that had cached the
/// JWKS then rejected still-valid tokens, which surfaces as sporadic 401s during
/// rollout and failover with no obvious cause. TS 33.501 §13.4.1 assumes a stable
/// NRF signing key.
///
/// Format is the raw 32-byte scalar, hex-encoded. Deliberately not PKCS#8/PEM: that
/// needs a p256 feature this build does not enable, and the normal operator flow is
/// to let the NRF generate the file on first start and then mount it (as a
/// Kubernetes Secret or equivalent) so replicas and restarts share it — no
/// externally-generated key needs to be parsed.
///
/// A malformed or wrong-length file is an ERROR, never a silent regeneration:
/// quietly minting a new key would reproduce exactly the defect this fixes.
///
/// The load/persist/permissions mechanics live in
/// [`nextgcore_sbi::oauth::load_or_create_es256_key`] because every NF's CCA
/// signing key needs the identical contract (issue #64 gaps 1+2). Keeping two
/// copies of a security-relevant load-or-create is how one of them drifts; this
/// wrapper adds only the NRF-specific consequence to the error text.
fn load_or_create_signing_key(path: &std::path::Path) -> anyhow::Result<p256::ecdsa::SigningKey> {
    let existed = path.exists();
    let key = nextgcore_sbi::oauth::load_or_create_es256_key(path).map_err(|e| {
        anyhow::anyhow!(
            "{e}. This is the --signing-key-file: a new key under the same kid \
             '{NRF_KID}' would invalidate every outstanding access token, so it is not \
             regenerated automatically."
        )
    })?;
    if existed {
        log::info!("loaded the ES256 signing key from {}", path.display());
    } else {
        log::info!(
            "generated a new ES256 signing key and persisted it to {} (mount this so \
             restarts and HA replicas share it)",
            path.display()
        );
    }
    Ok(key)
}

fn nrf_signing_key() -> &'static p256::ecdsa::SigningKey {
    NRF_SIGNING_KEY.get_or_init(|| {
        // A configured path was already loaded (and validated) at startup; this
        // fallback is the no-path case, which keeps the pre-#64 per-process
        // behaviour for local runs.
        match NRF_SIGNING_KEY_FILE.get() {
            Some(path) => load_or_create_signing_key(path)
                .unwrap_or_else(|e| panic!("signing key unavailable: {e:#}")),
            None => {
                log::warn!(
                    "no --signing-key-file configured: generating an EPHEMERAL ES256 key. \
                     Every restart and every additional NRF replica will publish a \
                     different key under kid '{NRF_KID}', so previously issued tokens \
                     will be rejected (issue #64)."
                );
                generate_signing_key()
            }
        }
    })
}

/// NextGCore NRF - Network Repository Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nrfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Repository Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nrf.yaml")]
    config: String,

    /// Log file path
    #[arg(short = 'l', long)]
    log_file: Option<String>,

    /// Log level (trace, debug, info, warn, error). Without it, the config
    /// file's `logger.level`, else `info`; `RUST_LOG` overrides (#691).
    #[arg(short = 'e', long)]
    log_level: Option<String>,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// Kill a running instance (NOT SUPPORTED: exits with an error;
    /// stop the NF through its supervisor)
    #[arg(short = 'k', long)]
    kill: bool,

    /// SBI server address. Without it, `nrf.sbi.server[0].address` from the
    /// config file, else 127.0.0.1 (#1308, #1311).
    #[arg(long)]
    sbi_addr: Option<String>,

    /// SBI server port. Without it, `nrf.sbi.server[0].port`, else 7777.
    #[arg(long)]
    sbi_port: Option<u16>,

    /// File holding the ES256 access-token signing key (issue #64 gap 4).
    ///
    /// Generated on first start if absent, then reused. Mount the same file into
    /// every NRF replica: without it each process signs with a different key under
    /// the same `kid`, so restarts and scale-out invalidate outstanding tokens.
    #[arg(long)]
    signing_key_file: Option<String>,

    /// Access-token lifetime in seconds (`expires_in`).
    #[arg(long, default_value_t = DEFAULT_TOKEN_EXPIRES_IN_SECS)]
    token_expires_in: u64,

    /// Serve the SBI listener over TLS. Without it, NEXTGCORE_NRF_SERVER_TLS,
    /// else `nrf.sbi.server[0].tls.enabled`. With TLS the listener requests a
    /// client certificate and verifies a presented one (#1617).
    #[arg(long)]
    tls: bool,

    /// TLS certificate path (else NEXTGCORE_NRF_SERVER_TLS_CERT, else
    /// `nrf.sbi.server[0].tls.cert`, else /etc/nextgcore/tls/server.crt).
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path (else NEXTGCORE_NRF_SERVER_TLS_KEY, else
    /// `nrf.sbi.server[0].tls.key`, else /etc/nextgcore/tls/server.key).
    #[arg(long)]
    tls_key: Option<String>,

    /// REQUIRE a client certificate (default: requested, optional). Needs TLS.
    #[arg(long)]
    mtls: bool,

    /// CA a client certificate must chain to (else NEXTGCORE_NRF_SERVER_TLS_CA,
    /// else `nrf.sbi.server[0].tls.ca`, else /etc/nextgcore/tls/ca.crt).
    #[arg(long)]
    tls_ca_cert: Option<String>,

    /// Maximum number of UEs
    #[arg(long, default_value = "1024")]
    max_ue: usize,

    /// NF Instance ID of this NRF (UUID, used as OAuth2 token issuer).
    /// Auto-generated when not given.
    #[arg(long)]
    nf_instance_id: Option<String>,

    /// Path to the JSON snapshot file for registered NFProfiles and
    /// subscriptions. When unset (the default) the registry is purely
    /// in-memory and is lost on restart. Also settable via
    /// NEXTGCORE_NRF_STATE_FILE.
    #[arg(long)]
    state_file: Option<String>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Active NfInstanceNoHeartbeat timer id per NF instance.
///
/// get_expired_events() fires every timer left in the manager, so a heartbeat
/// refresh must DELETE the superseded expiry timer — merely starting a new one
/// leaves the old timer armed and the NF gets suspended on schedule regardless
/// of heartbeats.
static HEARTBEAT_TIMERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// nrfd-03: negotiate the `heartBeatTimer` the NRF will enforce (TS 29.510
/// Table 6.1.6.2.2-1). The NRF reuses the consumer's proposal when it falls
/// within the accepted `[min,max]` bounds; otherwise (absent or out of range)
/// it overrides with the preconfigured default. Pure for unit testing.
fn negotiate_heartbeat(proposed: Option<u32>, default: u32, min: u32, max: u32) -> u32 {
    match proposed {
        Some(v) if v >= min && v <= max => v,
        _ => default,
    }
}

/// Arm (or re-arm) the no-heartbeat expiry timer for an NF instance,
/// cancelling any previously armed timer for the same instance.
///
/// Never for the NRF's own entry (#1644 review M2): the NRF does not heartbeat
/// itself, so a timer on it (from `rearm_restored_timers` after a restart with
/// persistence, or a PUT naming it) would suspend and then deregister it, after
/// which its token endpoint grants no nnrf-* scope and the nrfd-06 gate refuses
/// everyone.
fn arm_heartbeat_timer(nf_instance_id: &str, expiry: Duration) {
    if nf_instance_id.eq_ignore_ascii_case(nrf_instance_id()) {
        disarm_heartbeat_timer(nf_instance_id);
        return;
    }
    let timer_mgr = timer_manager();
    let new_id = timer_mgr.start_timer(
        nextgcore_nrfd::NrfTimerId::NfInstanceNoHeartbeat,
        expiry,
        nf_instance_id.to_string(),
    );
    if let Ok(mut timers) = HEARTBEAT_TIMERS.lock() {
        let old = match new_id {
            Some(id) => timers.insert(nf_instance_id.to_string(), id),
            None => timers.remove(nf_instance_id),
        };
        if let Some(old_id) = old {
            timer_mgr.delete_timer(old_id);
        }
    }
}

/// Cancel the no-heartbeat expiry timer for an NF instance (deregistration).
fn disarm_heartbeat_timer(nf_instance_id: &str) {
    if let Ok(mut timers) = HEARTBEAT_TIMERS.lock() {
        if let Some(old_id) = timers.remove(nf_instance_id) {
            timer_manager().delete_timer(old_id);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // #1311: the config file's SBI listen address, unless the command line names one.
    // Read and parsed once (#1313 review); a file that is there but cannot be read
    // or parsed fails startup rather than falling back to loopback.
    let config_yaml = load_config(&args.config)?;
    let listen = resolve_sbi_listen(
        args.sbi_addr.as_deref(),
        args.sbi_port,
        config_yaml.as_ref(),
    );

    // Initialize logging
    init_logging(&args)?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore NRF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize NRF context
    nrf_context_init(args.max_ue);
    log::info!("NRF context initialized (max_ue={})", args.max_ue);

    // Initialise the NF registry, optionally restoring persisted profiles and
    // subscriptions. Path precedence: --state-file, then NEXTGCORE_NRF_STATE_FILE.
    // With neither set the registry stays purely in-memory (previous behaviour).
    let nrf_state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_NRF_STATE_FILE").ok())
        .filter(|s| !s.is_empty());
    match &nrf_state_file {
        Some(path) => {
            nextgcore_nrfd::init_nf_manager(Some(std::path::PathBuf::from(path)));
            log::info!("NRF registry persistence enabled: {path}");
            // Restoring the registry without re-arming its timers leaves every
            // restored NF unsupervised and every restored subscription immortal:
            // the no-heartbeat timer is armed only inside register/update and the
            // validity timer only inside subscription create, so nothing ever
            // expires a record that came off disk (TS 29.510 Section 6.1.3).
            rearm_restored_timers();
        }
        None => {
            nextgcore_nrfd::init_nf_manager(None);
            log::info!("NRF registry persistence disabled (in-memory only)");
        }
    }

    // Issue #64 gap 4: resolve the signing key BEFORE the server can serve a token
    // request, so a bad key file fails startup rather than surfacing as a runtime
    // panic on the first token.
    if let Some(ref path) = args.signing_key_file {
        NRF_SIGNING_KEY_FILE
            .set(std::path::PathBuf::from(path))
            .ok();
        let key = load_or_create_signing_key(std::path::Path::new(path))?;
        NRF_SIGNING_KEY.set(key).ok();
    }
    NRF_TOKEN_EXPIRES_IN.set(args.token_expires_in).ok();
    log::info!(
        "access-token lifetime: {}s (kid {NRF_KID})",
        nrf_token_expires_in()
    );

    // #1617 step b: TLS on the one SBI listener, from the command line, the
    // environment or nrf.sbi.server[0].tls. Resolved and checked before anything
    // listens, so a bad setting or a missing file fails startup by name.
    let server_tls = resolve_server_tls(
        &TlsFlags {
            tls: args.tls,
            cert: args.tls_cert.clone(),
            key: args.tls_key.clone(),
            mtls: args.mtls,
            ca: args.tls_ca_cert.clone(),
        },
        |var| std::env::var(var).ok(),
        config_yaml
            .as_ref()
            .and_then(|y| y.nrf.as_ref())
            .and_then(|n| n.sbi.as_ref())
            .and_then(|s| s.server.as_ref())
            .and_then(|v| v.first())
            .and_then(|s| s.tls.as_ref()),
    )?;
    // #1795: under the production SBI profile the NRF never serves cleartext.
    check_listener_profile(
        nextgcore_sbi::security::SbiProfile::resolve(),
        server_tls.as_ref(),
    )?;
    if let Some(tls) = &server_tls {
        tls.check_files()?;
    } else {
        // #1617 step f: no caller of a cleartext listener can present a
        // certificate, so this NRF serves discovery and tokens but refuses every
        // NF-management request. Said once at startup, not per refusal.
        log::warn!(
            "the NRF serves cleartext h2c: no NF can present a client certificate, so every \
             NFRegister / NFUpdate / NFDeregister is refused 400 INVALID_CLIENT (#1617). \
             Enable TLS (nrf.sbi.server[0].tls.enabled, {NRF_SERVER_TLS_ENV}=true or --tls) \
             with the NFs' certificates (docker/rust/certs/generate-dev-certs.sh)."
        );
    }

    // Store the NRF's own SBI URI so notification handlers can use it
    let scheme = if server_tls.is_some() {
        "https"
    } else {
        "http"
    };
    let self_uri = format!(
        "{}://{}",
        scheme,
        nextgcore_sbi::uri_encode::uri_authority(&listen.advertise, listen.port)
    );
    NRF_SELF_URI.set(self_uri).ok();

    // The NRF's NF Instance ID is the OAuth2 token issuer (TS 29.510
    // §6.3.5.2.4). Issue #187: `--nf-instance-id` seeds the shared resolver, so
    // it keeps its meaning and keeps beating both environment sources, and every
    // read in this process observes the one value.
    if let Some(ref id) = args.nf_instance_id {
        if !nextgcore_sbi::nf_instance_id::seed(id) {
            // Seeding after something already resolved the ID would silently
            // leave the NRF issuing tokens under an ID the operator did not ask
            // for, so say so rather than discarding the flag quietly.
            log::warn!(
                "--nf-instance-id {id} was IGNORED: this NF's instance ID had already been \
                 resolved to {}. The flag must be applied before anything reads the ID.",
                nrf_instance_id()
            );
        }
    }
    log::info!("NRF NF Instance ID: {}", nrf_instance_id());

    // Initialize NRF state machine
    let mut nrf_sm = NrfSmContext::new();
    nrf_sm.init();
    log::info!("NRF state machine initialized");

    // Parse configuration (if file exists) and pick up the SBI OAuth2 knob
    // (nrf.sbi.oauth2.require) plus the heartbeat / discovery / server-auth
    // policy (nrfd-03/-05/-06/-10). With no file (the matched-sim default) the
    // conservative `NrfPolicy::default` applies and nothing changes.
    let mut require_oauth2 = false;
    let mut policy = NrfPolicy::default();
    if let Some(yaml) = config_yaml.as_ref() {
        require_oauth2 = yaml
            .nrf
            .as_ref()
            .and_then(|n| n.sbi.as_ref())
            .and_then(|s| s.oauth2.as_ref())
            .and_then(|o| o.require)
            .unwrap_or(false);
        policy = NrfPolicy::from_yaml(yaml);
    }
    // I2: apply the env-var runtime overrides (default-safe: forces ON only) so
    // the manual host-gate flip is A/B-testable in docker without a code edit.
    policy.apply_env_overrides();
    if policy.require_oauth2_server {
        log::warn!(
            "nrfd-06: server-side OAuth2 enforcement ENABLED on nnrf-nfm/nnrf-disc \
             (token + jwks endpoints stay exempt)"
        );
    }
    let self_registers = registers_itself(require_oauth2, policy.require_oauth2_server);
    if policy.require_client_auth {
        log::info!(
            "nrfd-05: token-endpoint client authentication required (signature-verified CCA \
             or mTLS identity); {} trusted CCA key(s) configured",
            policy.cca_trusted_keys.len()
        );
    } else {
        // Issue #64 gap 1: this is the documented escape hatch, and it must not
        // be quiet. With it set, the endpoint mints a valid access token for any
        // nfInstanceId that happens to be registered.
        log::warn!(
            "nrfd-05: token-endpoint client authentication is DISABLED \
             (nrf.sbi.oauth2.require_client_auth=false or \
             NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED). Any caller that knows a registered \
             nfInstanceId can obtain an access token for it. Do not run this in production."
        );
    }
    if policy.require_client_cert_binding {
        log::info!(
            "nrfd-I2: token-endpoint mTLS client-certificate binding REQUIRED \
             (certificate URI SAN must match nfInstanceId)"
        );
    }
    if policy.trust_forwarded_client_cert {
        // Issue #64 gap 2: trusting this header is safe only behind a terminator
        // that overwrites it. Say so where an operator will see it.
        log::warn!(
            "nrfd-I2: the {XFCC_HEADER} header is TRUSTED as proof of mTLS identity. Every \
             path to this NRF must pass through a TLS terminator that sets this header and \
             strips any client-supplied copy -- otherwise any client can assert any \
             identity by setting it."
        );
    }
    if !policy.cca_verify_signature {
        log::warn!(
            "nrfd-I1: CCA ES256 signature verification is DISABLED. A CCA is then just \
             attacker-chosen claims, so it proves nothing about the requester's identity."
        );
    }
    match &policy.nf_set_allowlist {
        None => log::warn!(
            "nrfd-1719: nrf.nf_set_allowlist is not configured, so a registrant's nfSetIdList \
             is accepted as sent. Any NF that can register can claim membership of any NF Set, \
             and a consumer that admits a peer by set membership (smfd's sm-policy-notify, \
             #1717) can be misled. List each NF Set and who may claim it."
        ),
        Some(allow) => log::info!(
            "nrfd-1719: {} NF Set allowlist entr(y/ies) configured; NFRegister and NFUpdate \
             refuse any other set",
            allow.len()
        ),
    }
    // #1719 (R19): a profile restored from the state file was never checked
    // against this allowlist, and a heartbeating NF never re-registers, so the
    // claim is enforced here, before the policy is published.
    enforce_nf_set_allowlist_at_restore(&policy, nf_manager().list());
    // #1809 / #1917, and #1926 (DECISION 2026-11-19): subscriptions are bound to
    // a verified identity, and NF management to the NF type the caller's
    // certificate names, wherever the NRF can verify callers: under the
    // production profile, or whenever its listener verifies client certificates.
    let verification = verification_required(
        nextgcore_sbi::security::SbiProfile::resolve(),
        server_tls.as_ref(),
    );
    // #1952: a declared TLS terminator (trust_forwarded_client_cert) also lets
    // the NRF verify a subscriber: the forwarded certificate identity counts. So
    // a dev NRF behind one, which sees plaintext, still binds subscriptions.
    // (#1979 made the NF-type rule follow it too, below.)
    // #1990: believing XFCC is checked before the policy is published.
    check_forwarded_trust(
        nextgcore_sbi::security::SbiProfile::resolve(),
        &policy,
        server_tls.as_ref(),
    )?;
    policy.require_subscriber_identity = verification || policy.trust_forwarded_client_cert;
    // #1979: with XFCC `Cert=` parsed, a declared terminator's forwarded
    // registrants carry NF types too, so the rule follows it as well. A
    // terminator that forwards no `Cert=` proves no type, and its registrants
    // are refused: configure it to forward the certificate.
    policy.require_registrant_nf_types = verification || policy.trust_forwarded_client_cert;
    if !policy.require_registrant_nf_types {
        // #1979: both rules follow a declared terminator, so here neither is on.
        log::warn!(
            "nrfd-1926: dev SBI profile, no TLS client-certificate verification and no \
             declared TLS terminator: a registrant may register as any NF type, and \
             NFStatusSubscribe needs no verified identity"
        );
    } else if !verification {
        log::info!(
            "nrfd-1979: a TLS terminator is declared (trust_forwarded_client_cert): \
             forwarded registrants are bound to the NF types of the certificate it forwards \
             in XFCC Cert=; one that forwards no Cert= is refused"
        );
    }
    if policy.require_subscriber_identity {
        let manager = nf_manager();
        let unbound = manager
            .subscription_ids()
            .iter()
            .filter(|id| {
                manager
                    .find_subscription(id)
                    .is_some_and(|s| s.owner.is_none())
            })
            .count();
        if unbound > 0 {
            log::warn!(
                "{unbound} restored subscription(s) carry no verified owner (written before \
                 #1809): they keep their notifications until their validity lapses (at most \
                 24 h after this restart), but no caller can update or remove them; their \
                 consumers re-subscribe on the 404 that follows expiry"
            );
        }
    }
    NRF_POLICY.set(policy).ok();

    // Client side (T1.1): when SBI OAuth2 is enabled, the NRF acquires and
    // attaches NRF-issued tokens on its own outbound calls (status notify to
    // consumers). The NRF is the Authorization Server, so it points the token
    // client at itself (self_uri).
    //
    // Server side: NOT applied here. Enabling require_oauth2 on the NRF's SBI
    // server would gate the NRF's own /nnrf-oauth2/v1/access-token + /jwks
    // endpoints (L1's middleware has no per-path exemption), deadlocking token
    // issuance for the whole core. See SbiOauth2Yaml docs.
    if require_oauth2 {
        // Issue #187, criterion 5: the NRF is NOT exempt from its own
        // client-authentication policy. Two things its own token request needs,
        // both of which it previously lacked:
        //
        //  1. A CCA signing key, plus its public half in its OWN trust store —
        //     provisioned exactly like every consumer's, through the shared
        //     resolver, so the NRF's public JWK lands in the same directory the
        //     NRF then loads. Nothing special-cases the NRF.
        //  2. A registration. `handle_access_token_request_with_policy` rejects
        //     a requester that `nf_manager()` does not know (RFC 6749 §5.2
        //     invalid_client), and the NRF never registered itself — so with
        //     client authentication ON its own outbound notifications could not
        //     get a token even with a valid CCA.
        if let Err(e) =
            nextgcore_sbi::oauth::init_cca_client_credentials(nrf_instance_id()).map(|configured| {
                if configured {
                    log::info!(
                        "nrfd-187: the NRF's own CCA signing key is configured; it authenticates \
                         to its own token endpoint like any other consumer"
                    );
                }
            })
        {
            // A malformed key file needs a human; an absent one is generated.
            log::error!(
                "nrfd-187: the NRF's own CCA signing key is unusable: {e}. Its outbound \
                 notifications will be refused invalid_client by its own token endpoint while \
                 require_client_auth is on."
            );
        }
        register_self_with_own_registry();

        // #1617 step b: under TLS the NRF's token client dials its own listener
        // with the NRF client TLS (#1690). Fill what the NEXTGCORE_NRF_TLS_*
        // settings leave unset from the listener's own CA, name and certificate,
        // so the self URI's address need not be a name the certificate carries.
        if let Some(tls) = &server_tls {
            let own = tls.self_client_tls(|var| std::env::var(var).ok(), nrf_instance_id());
            log::info!(
                "NRF self client TLS: CA={} client certificate={} server name={}",
                own.ca_cert,
                own.client_cert.as_deref().unwrap_or("NONE"),
                own.server_name.as_deref().unwrap_or("(the self URI host)"),
            );
            nextgcore_sbi::nrf_tls::set_nrf_client_tls_override(Some(own));
        }

        let oauth2 = Arc::new(OAuth2Client::new(
            nrf_self_uri().to_string(),
            nrf_instance_id().to_string(),
            NfType::Nrf,
        ));
        nextgcore_nrfd::sbi_path::set_oauth2_client(oauth2);
        log::info!(
            "SBI OAuth2 enabled: NRF will attach Bearer tokens on outbound \
             calls (issuer/self: {})",
            nrf_self_uri()
        );
    } else if self_registers {
        // #1644 review B1: a token for nnrf-nfm / nnrf-disc is minted only when a
        // registered NRF offers the service, so the NRF must be in its own registry
        // whenever the gate requires one.
        register_self_with_own_registry();
    } else {
        drop_restored_self_entry();
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: listen.host.clone(),
        port: listen.port,
        tls_enabled: server_tls.is_some(),
        tls_cert: server_tls.as_ref().map(|t| t.cert.clone()),
        tls_key: server_tls.as_ref().map(|t| t.key.clone()),
    };

    // Open legacy SBI server (for context initialization)
    let _server = nrf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr =
        nextgcore_core::sockaddr::parse_listen_addr(&listen.host, listen.port)
            .context("Invalid SBI address")?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    nextgcore_core::sockaddr::warn_if_loopback_listener(
        "SBI",
        &sbi_addr,
        "--sbi-addr or nrf.sbi.server",
    );
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);

    // #1617 step b: one listener; with TLS it requests a client certificate and
    // verifies a presented one (required only with --mtls / client_auth: required).
    if let Some(tls) = &server_tls {
        sbi_server_config = tls.apply(sbi_server_config);
        log::info!(
            "TLS enabled: cert={}, key={}, client CA={}, client certificate {}",
            tls.cert,
            tls.key,
            tls.ca,
            match tls.client_auth {
                ClientAuth::Optional => "requested (optional; a presented one must verify)",
                ClientAuth::Required => "REQUIRED",
            }
        );
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(nrf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if server_tls.is_some() {
        "HTTPS"
    } else {
        "HTTP"
    };
    log::info!("SBI HTTP/2 {scheme} server listening on {sbi_addr}");

    // #1334: the Prometheus endpoint, on NEXTGCORE_METRICS_BIND (loopback by default,
    // #837) and NRF_METRICS_PORT (9090). Non-fatal: an NRF that cannot expose
    // metrics still serves the core.
    let _metrics = nextgcore_metrics::nf::serve_nf_metrics(
        "NRF",
        "NRF_METRICS_PORT",
        Arc::new(nextgcore_nrfd::metrics::render_prometheus),
    )
    .await;
    log::info!("NextGCore NRF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nrf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    nrf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    nrf_sm.fini();
    log::info!("NRF state machine finalized");

    // Cleanup context
    nrf_context_final();
    log::info!("NRF context finalized");

    log::info!("NextGCore NRF stopped");
    Ok(())
}

/// nrfd-06: which producer paths require a valid OAuth2 Bearer token when
/// server-side enforcement is on. The NRF is itself the Authorization Server,
/// so its `/nnrf-oauth2/*` token + `/jwks` endpoints (and health `/`) MUST stay
/// reachable without a token — only the `nnrf-nfm` and `nnrf-disc` producer
/// services are gated (TS 33.501 §13.4.1 / §13.3.1).
fn oauth2_protected_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    p == "nnrf-nfm" || p == "nnrf-disc" || p.starts_with("nnrf-nfm/") || p.starts_with("nnrf-disc/")
}

/// nrfd-06: returns `Some(401)` when the request must be rejected for lacking a
/// valid NRF-issued Bearer token, or `None` when it may proceed. Pure over its
/// inputs (no globals) so the policy is unit-testable without flipping process
/// state. `require == false` (the default) always returns `None`, preserving
/// the matched-sim path; exempt paths (token/jwks/health) always return `None`.
fn enforce_oauth2_on_request(
    path: &str,
    auth_header: Option<&str>,
    require: bool,
    jwks: &serde_json::Value,
) -> Option<SbiResponse> {
    oauth2_gate(path, auth_header, require, jwks)
        .err()
        .map(|r| *r)
}

/// [`enforce_oauth2_on_request`], keeping what it verified (#1611): `Ok(Some(sub))`
/// is the `sub` of an NRF-issued token whose signature verified (the consumer's
/// NF Instance ID, TS 29.510 §6.3.5.2.4 `AccessTokenClaims`); `Ok(None)` means no
/// token was required here.
///
/// #1634: a verified signature is not enough. The token must also be FOR this
/// API on this NRF (TS 33.501 §13.4.1.1, TS 29.500 §6.7.3):
/// - `scope` must contain the invoked service name (`nnrf-nfm` / `nnrf-disc`):
///   TS 29.500 §6.7.3 makes the service-name scope part of every access scope,
///   and TS 29.510 Table 6.1.8-1 defines `nnrf-nfm` for the Nnrf_NFManagement API.
///   Otherwise 403, `WWW-Authenticate: Bearer error="insufficient_scope"`.
/// - `aud` must name this NRF: its NF type `NRF` or its NF Instance ID (TS 29.510
///   §6.3.5.2.4). A token minted for another producer is a claims mismatch: 403
///   `ACCESS_TOKEN_CLAIM_MISMATCH`, `error="invalid_token"`.
///
/// Before, a token issued for any service of any producer (say an
/// nsmf-pdusession token a peer obtained legitimately) was accepted here, and,
/// since #1611, its `sub` then stood for the caller's identity.
fn oauth2_gate(
    path: &str,
    auth_header: Option<&str>,
    require: bool,
    jwks: &serde_json::Value,
) -> Result<Option<String>, Box<SbiResponse>> {
    if !require || !oauth2_protected_path(path) {
        return Ok(None);
    }
    let service = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    let realm = format!("{}/{service}/v1", nrf_self_uri());
    let challenge = |error: Option<&str>, scope: Option<&str>| {
        let mut c = format!("Bearer realm=\"{realm}\"");
        if let Some(e) = error {
            c.push_str(&format!(", error=\"{e}\""));
        }
        if let Some(s) = scope {
            c.push_str(&format!(", scope=\"{s}\""));
        }
        c
    };
    let refuse = |status: u16, title: &str, detail: String, cause: Option<&str>, www: String| {
        Box::new(send_error(status, title, &detail, cause).with_header("WWW-Authenticate", www))
    };
    // TS 29.500 §6.7.3: a claims mismatch MAY carry ACCESS_TOKEN_CLAIM_MISMATCH with
    // `invalidParams` naming the claim (#1644 review m1).
    let claim_mismatch = |claim: &str, detail: String| {
        let body = serde_json::json!({
            "title": "Forbidden",
            "status": 403,
            "detail": detail,
            "cause": "ACCESS_TOKEN_CLAIM_MISMATCH",
            "invalidParams": [{ "param": claim }],
        });
        Box::new(
            SbiResponse::with_status(403)
                .with_body(body.to_string(), "application/problem+json")
                .with_header("WWW-Authenticate", challenge(Some("invalid_token"), None)),
        )
    };
    let claims = match nextgcore_sbi::oauth::authorize_bearer(auth_header, jwks) {
        Ok(claims) => claims,
        Err(e) => {
            // TS 29.500 §6.7.3: no `error` when the request carried no token; and
            // RFC 6750 §3.1: a request with another authentication scheme carries
            // no Bearer token either (#1644 review m2).
            let presented = auth_header.is_some_and(|h| {
                h.trim()
                    .get(..7)
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer "))
            });
            return Err(refuse(
                401,
                "Unauthorized",
                format!("OAuth2 access token required: {e}"),
                Some("UNAUTHORIZED"),
                challenge(presented.then_some("invalid_token"), None),
            ));
        }
    };
    // The issuer must be this NRF (TS 29.510 §6.3.5.2.4 `iss`: the NRF's NF Instance
    // ID). The signature already ties the token to this NRF's key; this keeps the
    // gate right if the JWKS ever holds another NRF's key.
    if !claims.iss.eq_ignore_ascii_case(nrf_instance_id()) {
        return Err(claim_mismatch(
            "iss",
            format!(
                "the access token was not issued by this NRF ({:?})",
                claims.iss
            ),
        ));
    }
    let for_this_nrf = |aud: &str| aud == "NRF" || aud.eq_ignore_ascii_case(nrf_instance_id());
    let aud_ok = match &claims.aud {
        serde_json::Value::String(a) => for_this_nrf(a),
        serde_json::Value::Array(items) => {
            items.iter().filter_map(|v| v.as_str()).any(for_this_nrf)
        }
        _ => false,
    };
    if !aud_ok {
        return Err(claim_mismatch(
            "aud",
            format!("the access token's audience {} is not this NRF", claims.aud),
        ));
    }
    if nextgcore_sbi::oauth::check_token_scope(&claims.scope, service).is_err() {
        return Err(refuse(
            403,
            "Forbidden",
            format!("the access token's scope does not include {service}"),
            // RFC 6750 `insufficient_scope` is in the challenge; TS 29.500 defines no
            // ProblemDetails cause for it (#1644 review m1).
            None,
            challenge(Some("insufficient_scope"), Some(service)),
        ));
    }
    Ok(Some(claims.sub))
}

/// SBI request handler for NRF
/// #1617 step f: the plaintext test listeners of NF-management lifecycles stand
/// in for a TLS terminator that verified the caller's certificate for the
/// nfInstanceID the request names. Those tests exercise registration, heartbeat
/// and deregistration, not caller identity; the refusal of an unverified caller
/// is tested over real TLS (`server_tls_tests_1617`, `dev_pki_tests_1617`) and
/// at the handlers (`unverified_registrant_tests_1617`). Test-only: nothing in
/// the daemon can attach an identity a handshake did not verify.
///
/// #1917: that certificate also names the NF type the request registers as (a
/// PUT's `nfType`) or manages (the stored profile's), as a production NF
/// certificate does (RFC 9310 NFTypes); one naming none is refused under the
/// production profile, and that refusal is tested in
/// `registrant_nf_type_tests_1917`.
#[cfg(test)]
async fn nrf_handler_as_path_certificate(mut request: SbiRequest) -> SbiResponse {
    if request.peer_cert_nf_instance_id.is_none() {
        request.peer_cert_nf_instance_id = request
            .header
            .uri
            .strip_prefix("/nnrf-nfm/v1/nf-instances/")
            .and_then(|rest| rest.split(['/', '?']).next())
            .filter(|id| !id.is_empty())
            .map(str::to_string);
        if let Some(id) = request.peer_cert_nf_instance_id.clone() {
            if request.peer_cert_nf_types.is_empty() {
                request.peer_cert_nf_types = test_certificate_nf_type(&request, &id)
                    .into_iter()
                    .collect();
            }
        }
    }
    nrf_sbi_request_handler(request).await
}

/// #1917, tests only: the NF type a stand-in certificate for `id` names, from a
/// PUT body's `nfType`, else from the stored profile.
#[cfg(test)]
fn test_certificate_nf_type(request: &SbiRequest, id: &str) -> Option<String> {
    request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
        .and_then(|v| v.get("nfType").and_then(|t| t.as_str()).map(str::to_string))
        .or_else(|| {
            nf_manager()
                .get(&nextgcore_nrfd::nnrf_handler::canonical_nf_instance_id(id))
                .map(|p| p.nf_type.clone())
        })
}

async fn nrf_sbi_request_handler(mut request: SbiRequest) -> SbiResponse {
    // nrfd-06: per-path server-side OAuth2 enforcement (default OFF). The token
    // and jwks endpoints stay exempt so the core can always obtain a token.
    // #1611: the subject of a token verified here is an identity THIS process
    // attested, so it is recorded for the NF-instance binding below.
    {
        let uri = &request.header.uri;
        let path = uri.split('?').next().unwrap_or(uri);
        match oauth2_gate(
            path,
            request.http.get_header("authorization").map(String::as_str),
            nrf_policy().require_oauth2_server,
            &nrf_jwks_json(),
        ) {
            Err(rejection) => return *rejection,
            Ok(Some(sub)) => request.oauth2_subject = Some(sub),
            Ok(None) => {}
        }
    }

    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!(
        "NRF SBI request: {method} {uri}",
        uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
    );

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Nnrf_Bootstrapping (TS 29.510 §5.5) is served at `{apiRoot}/bootstrapping`
    // with NO service/version prefix, so it must be matched before the
    // three-segment guard below — which is exactly why it used to 404.
    if parts.first() == Some(&"bootstrapping") && parts.len() == 1 {
        return match method {
            "GET" => handle_bootstrapping(&request),
            _ => send_method_not_allowed(method, uri),
        };
    }

    // Route based on service and resource
    // Expected paths:
    // - /nnrf-nfm/v1/nf-instances/{nfInstanceId}
    // - /nnrf-nfm/v1/subscriptions/{subscriptionId}
    // - /nnrf-disc/v1/nf-instances

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    // #1334: the NRF's outcome counters, by what the request was.
    use nextgcore_nrfd::metrics::{observe, NrfOperation};
    let operation = match (service, resource, method) {
        ("nnrf-nfm", "nf-instances", "PUT") if parts.len() >= 4 => Some(NrfOperation::Register),
        ("nnrf-nfm", "nf-instances", "PATCH") if parts.len() >= 4 => Some(NrfOperation::Update),
        ("nnrf-nfm", "nf-instances", "DELETE") if parts.len() >= 4 => {
            Some(NrfOperation::Deregister)
        }
        ("nnrf-nfm", "subscriptions", "POST") => Some(NrfOperation::Subscribe),
        ("nnrf-oauth2", "access-token", "POST") => Some(NrfOperation::AccessToken),
        _ => None,
    };
    let discovery = (service, resource, method) == ("nnrf-disc", "nf-instances", "GET");

    let response = match (service, resource, method) {
        // NF Management Service (nnrf-nfm)
        ("nnrf-nfm", "nf-instances", "PUT") if parts.len() >= 4 => {
            // NF Register/Update: PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_register(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "GET") if parts.len() >= 4 => {
            // NF Profile Retrieval: GET /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_profile_retrieval(nf_instance_id).await
        }
        ("nnrf-nfm", "nf-instances", "DELETE") if parts.len() >= 4 => {
            // NF Deregister: DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_deregister(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "PATCH") if parts.len() >= 4 => {
            // NF Update: PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_update(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "GET") => {
            // NF List Retrieval: GET /nnrf-nfm/v1/nf-instances
            handle_nf_list_retrieval(&request).await
        }

        // Subscriptions
        ("nnrf-nfm", "subscriptions", "POST") => {
            // Subscribe: POST /nnrf-nfm/v1/subscriptions
            handle_subscription_create(&request).await
        }
        ("nnrf-nfm", "subscriptions", "DELETE") if parts.len() >= 4 => {
            // Unsubscribe: DELETE /nnrf-nfm/v1/subscriptions/{subscriptionId}
            let subscription_id = parts[3];
            handle_subscription_delete(subscription_id, &request).await
        }
        ("nnrf-nfm", "subscriptions", "PATCH") if parts.len() >= 4 => {
            // Update subscription: PATCH /nnrf-nfm/v1/subscriptions/{subscriptionId}
            let subscription_id = parts[3];
            handle_subscription_update(subscription_id, &request).await
        }

        // NF Discovery Service (nnrf-disc)
        ("nnrf-disc", "nf-instances", "GET") => {
            // NF Discovery: GET /nnrf-disc/v1/nf-instances?target-nf-type=...&requester-nf-type=...
            handle_nf_discover(&request).await
        }

        // OAuth2 Access Token Service (nnrf-oauth2)
        ("nnrf-oauth2", "access-token", "POST") => {
            // Access Token Request: POST /nnrf-oauth2/v1/access-token
            handle_access_token_request(&request).await
        }
        // JWKS: GET /nnrf-oauth2/v1/jwks — publishes the ES256 public key so
        // consumers can verify access tokens (no shared secret needed).
        ("nnrf-oauth2", "jwks", "GET") => handle_jwks(),

        _ => {
            log::warn!(
                "Unknown NRF request: {method} {uri}",
                uri = nextgcore_sbi::log_redact::redact_callback_tokens(uri)
            );
            send_method_not_allowed(method, uri)
        }
    };
    if let Some(op) = operation {
        observe(op, response.status);
    }
    // A 200 SearchResult was counted by the handler with its match count.
    if discovery && response.status != 200 {
        nextgcore_nrfd::metrics::observe_discovery(None);
    }
    response
}

/// The `NotificationEventType` a `PUT /nf-instances/{id}` must be notified as.
///
/// TS 29.510 §5.2.2.3.1A / §5.2.2.3.2: a first registration is `NF_REGISTERED`;
/// a complete replacement of a profile that already exists is
/// `NF_PROFILE_CHANGED`.
fn registration_notification_event(is_new: bool) -> NotificationEventType {
    if is_new {
        NotificationEventType::NfRegistered
    } else {
        NotificationEventType::NfProfileChanged
    }
}

/// Handle NF Register request
/// R32 on #1957: 400 with `invalidParams` for a profile whose range patterns
/// are over this NRF's caps (TS 29.500 §5.2.7.2), before anything is stored.
fn refuse_range_patterns(profile: &serde_json::Value) -> Option<SbiResponse> {
    let (param, reason) = nextgcore_nrfd::nnrf_handler::range_pattern_violation(profile)?;
    let body = serde_json::json!({
        "title": "Bad Request",
        "status": 400,
        "detail": reason,
        "cause": "INVALID_MSG_FORMAT",
        "invalidParams": [{ "param": param, "reason": reason }],
    });
    Some(SbiResponse::with_status(400).with_body(body.to_string(), "application/problem+json"))
}

async fn handle_nf_register(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    // #1633: the registry key (TS 29.510 §5.2.2.2.2: upper-case UUIDs are handled as
    // lower-case).
    let nf_instance_id = nextgcore_nrfd::nnrf_handler::canonical_nf_instance_id(nf_instance_id);
    let nf_instance_id = nf_instance_id.as_str();
    log::info!("NF Register: {nf_instance_id}");

    // #1611: a verified caller registers only its own NF instance.
    let registrant = RegistrantIdentity::of(request, nrf_policy());
    if let Some(refused) = registrant.require_certificate(
        "NFRegister",
        nf_instance_id,
        nrf_policy().require_registrant_identity,
    ) {
        return refused;
    }
    if let Some(refused) = registrant.bind_instance("NFRegister", nf_instance_id) {
        return refused;
    }

    // Parse the NF profile from request body
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // Parse as NfProfile
    let profile: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    if let Some(refused) = refuse_range_patterns(&profile) {
        return refused;
    }
    // Mandatory attribute validation (TS 29.510 Table 6.1.6.2.2-1:
    // nfInstanceId, nfType, nfStatus) -> 400 ProblemDetails.
    let nf_profile = match NfProfile::from_json(&profile) {
        Ok(p) => p,
        Err(missing) => {
            return send_bad_request(
                &format!(
                    "Missing mandatory NFProfile attribute(s): {}",
                    missing.join(", ")
                ),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    // The nfInstanceId in the body must match the resource URI (TS 29.510
    // §5.2.2.2.1: the NF registers under its own NF Instance ID).
    if nf_profile.nf_instance_id != nf_instance_id {
        return send_bad_request(
            &format!(
                "Body nfInstanceId {:?} does not match resource URI {:?}",
                nf_profile.nf_instance_id, nf_instance_id
            ),
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    // #1611: and only as an NF type its verified certificate names.
    if let Some(refused) = registrant.bind_nf_type(
        "NFRegister",
        nf_instance_id,
        &nf_profile.nf_type,
        registrant_nf_types_required(nrf_policy()),
    ) {
        return refused;
    }
    // #1719: and claims only the NF Sets the operator provisioned it for.
    if let Some(refused) = refuse_unallowed_nf_sets(
        "NFRegister",
        nf_instance_id,
        &nf_profile.nf_type,
        nf_set_ids_of(&profile),
    ) {
        return refused;
    }
    // #2035: and lists no GUAMI an AMF of another AMF Set lists.
    if let Some(refused) = refuse_guami_of_another_set(
        "NFRegister",
        nf_instance_id,
        &nf_profile.nf_type,
        &profile,
        &nextgcore_nrfd::sbi_path::guami_list_of(&profile),
    ) {
        return refused;
    }

    // nrfd-03: negotiate the heartBeatTimer the NRF will enforce and stamp it
    // onto the stored AND returned profile (TS 29.510 Table 6.1.6.2.2-1: the
    // response carries the value the NRF will use, not the bare proposal).
    let policy = nrf_policy();
    let hb = negotiate_heartbeat(
        nf_profile.heartbeat_timer,
        policy.hb_default,
        policy.hb_min,
        policy.hb_max,
    );
    let mut nf_profile = nf_profile;
    nf_profile.set_heartbeat_timer(hb);

    let nf_type = nf_profile.nf_type.clone();
    let manager = nf_manager();
    // 201 Created on first registration, 200 OK on profile replacement
    // (TS 29.510 PUT response codes).
    let is_new = manager.get(nf_instance_id).is_none();

    match manager.register(nf_profile.clone()) {
        Ok(_) => {
            log::info!("NF {nf_instance_id} ({nf_type}) registered successfully");

            // Arm the no-heartbeat supervision timer from the negotiated value:
            // 2x the interval as tolerance before declaring a missed heartbeat.
            let expiry_secs = (hb as u64) * 2;
            arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
            log::info!(
                "Heartbeat timer started for NF {nf_instance_id} ({expiry_secs} seconds, 2x {hb}s interval)"
            );

            // Send NF status notifications to all matching subscribers.
            //
            // TS 29.510 §5.2.2.3.1A: a PUT that COMPLETELY REPLACES an existing
            // profile is a change, not an appearance, and must be notified as
            // NF_PROFILE_CHANGED. Emitting NF_REGISTERED for a replacement tells
            // every subscriber a producer just appeared that has in fact been
            // registered all along — which is what a consumer's
            // "new NF available" handling keys on.
            let event = registration_notification_event(is_new);
            let notify_profile = nf_profile.clone();
            let server_uri = nrf_self_uri().to_string();
            tokio::spawn(async move {
                if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                    event,
                    &notify_profile,
                    &server_uri,
                )
                .await
                {
                    log::error!("Failed to send {} notifications: {e}", event.as_str());
                }
            });

            // 201 Created (Location header mandatory) or 200 OK, both with the
            // full stored NF profile.
            let status = if is_new { 201 } else { 200 };
            let response = SbiResponse::with_status(status);
            let response = if is_new {
                response.with_header(
                    "Location",
                    format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}"),
                )
            } else {
                response
            };
            response
                .with_json_body(&nf_profile.to_json())
                .unwrap_or_else(|_| SbiResponse::with_status(status))
        }
        Err(e) => {
            log::error!("Failed to register NF {nf_instance_id}: {e}");
            send_error(500, "Internal Server Error", &e, Some("SYSTEM_FAILURE"))
        }
    }
}

/// Handle NF Profile Retrieval request
async fn handle_nf_profile_retrieval(nf_instance_id: &str) -> SbiResponse {
    // #1633: the registry key (TS 29.510 §5.2.2.2.2: upper-case UUIDs are handled as
    // lower-case).
    let nf_instance_id = nextgcore_nrfd::nnrf_handler::canonical_nf_instance_id(nf_instance_id);
    let nf_instance_id = nf_instance_id.as_str();
    log::debug!("NF Profile Retrieval: {nf_instance_id}");

    let manager = nf_manager();

    match manager.get(nf_instance_id) {
        // Return the complete stored NFProfile (TS 29.510 GetNFInstance:
        // 200 OK with NFProfile) — full register -> GET fidelity.
        Some(profile) => SbiResponse::with_status(200)
            .with_json_body(&profile.to_json())
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("NF instance {nf_instance_id} not found"),
            Some("NF_NOT_FOUND"),
        ),
    }
}

/// Handle NF Deregister request
async fn handle_nf_deregister(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    // #1633: the registry key (TS 29.510 §5.2.2.2.2: upper-case UUIDs are handled as
    // lower-case).
    let nf_instance_id = nextgcore_nrfd::nnrf_handler::canonical_nf_instance_id(nf_instance_id);
    let nf_instance_id = nf_instance_id.as_str();
    log::info!("NF Deregister: {nf_instance_id}");

    // #1611: a verified caller deregisters only its own NF instance, and (for a
    // certificate that names NF types) only one of a type it names.
    let registrant = RegistrantIdentity::of(request, nrf_policy());
    if let Some(refused) = registrant.require_certificate(
        "NFDeregister",
        nf_instance_id,
        nrf_policy().require_registrant_identity,
    ) {
        return refused;
    }
    if let Some(refused) = registrant.bind_instance("NFDeregister", nf_instance_id) {
        return refused;
    }

    let manager = nf_manager();

    // Fetch the profile before deregistering so we can notify subscribers
    let profile_for_notify = manager.get(nf_instance_id);
    if let Some(refused) = profile_for_notify.as_ref().and_then(|p| {
        registrant.bind_nf_type(
            "NFDeregister",
            nf_instance_id,
            &p.nf_type,
            registrant_nf_types_required(nrf_policy()),
        )
    }) {
        return refused;
    }

    match manager.deregister(nf_instance_id) {
        Ok(_) => {
            log::info!("NF {nf_instance_id} deregistered successfully");
            disarm_heartbeat_timer(nf_instance_id);

            // Send NF_DEREGISTERED notifications to matching subscribers
            if let Some(profile) = profile_for_notify {
                let server_uri = nrf_self_uri().to_string();
                tokio::spawn(async move {
                    if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                        NotificationEventType::NfDeregistered,
                        &profile,
                        &server_uri,
                    )
                    .await
                    {
                        log::error!("Failed to send NF_DEREGISTERED notifications: {e}");
                    }
                });
            }

            SbiResponse::with_status(204) // No Content
        }
        Err(e) => {
            log::error!("Failed to deregister NF {nf_instance_id}: {e}");
            send_not_found(&e, Some("NF_NOT_FOUND"))
        }
    }
}

/// Derive an RFC 6902-style `ChangeItem` list from a PATCH operation.
///
/// For JSON Patch (`is_json_patch = true`) the applied ops are translated
/// directly (skipping `test` ops which are guards, not changes).  For merge
/// patches the pre- and post-documents are diffed at the top level: each
/// key whose value changed becomes a `replace`, each new key becomes an
/// `add`, and each null-valued key (RFC 7396 delete) becomes a `remove`.
///
/// `pre` must be the stored profile document before the patch; `post` is the
/// document after a successful application.
pub fn compute_profile_changes(
    pre: &serde_json::Value,
    post: &serde_json::Value,
    patch: &serde_json::Value,
    is_json_patch: bool,
) -> Vec<ChangeItem> {
    if is_json_patch {
        let Some(items) = patch.as_array() else {
            return vec![];
        };
        items
            .iter()
            .filter_map(|item| {
                let op = item.get("op")?.as_str()?;
                if op == "test" {
                    return None; // guard op — not a profile change
                }
                let path = item.get("path")?.as_str()?.to_string();
                let value = item.get("value").cloned();
                // For replace/remove, capture the original value from pre-patch doc.
                let orig_value = if op == "replace" || op == "remove" {
                    pre.pointer(&path).cloned()
                } else {
                    None
                };
                Some(ChangeItem {
                    op: op.to_string(),
                    path,
                    value,
                    orig_value,
                })
            })
            .collect()
    } else {
        // Merge patch: diff pre vs post at the top level.
        let Some(patch_obj) = patch.as_object() else {
            return vec![];
        };
        patch_obj
            .iter()
            .map(|(key, patch_val)| {
                let path = format!("/{key}");
                if patch_val.is_null() {
                    // RFC 7396 null = remove
                    ChangeItem {
                        op: "remove".to_string(),
                        path,
                        value: None,
                        orig_value: pre.get(key).cloned(),
                    }
                } else if pre.get(key).is_some() {
                    ChangeItem {
                        op: "replace".to_string(),
                        path,
                        value: post.get(key).cloned(),
                        orig_value: pre.get(key).cloned(),
                    }
                } else {
                    ChangeItem {
                        op: "add".to_string(),
                        path,
                        value: post.get(key).cloned(),
                        orig_value: None,
                    }
                }
            })
            .collect()
    }
}

/// Handle NF Update request (PATCH)
///
/// TS 29.510 §5.2.2.3 mandates `application/json-patch+json` (RFC 6902
/// PatchItem array) for NFUpdate. `application/merge-patch+json` (RFC 7396)
/// is additionally accepted for lenient peers; bodies without a recognized
/// content type are dispatched on shape (array => JSON Patch, object =>
/// merge patch). Success returns 200 OK with the full updated NFProfile
/// (TS 29.510 also allows 204; we return the profile for visibility).
/// A failed RFC 6902 `test` op maps to 409 Conflict (RFC 5789 §2.2);
/// malformed/inapplicable patches map to 400 ProblemDetails.
/// Issue #22 NES: does this NFUpdate body explicitly set
/// `nfStatus=SUSPENDED`? Such a PATCH is a self-suspension (energy saving)
/// the NRF must honor rather than treat as a liveness signal that
/// reactivates the profile. Covers both RFC 6902 arrays and merge-patch
/// objects (the same shapes `handle_nf_update` dispatches on).
fn patch_requests_self_suspension(patch: &serde_json::Value, is_json_patch: bool) -> bool {
    if is_json_patch {
        patch.as_array().is_some_and(|ops| {
            ops.iter().any(|op| {
                op.get("path").and_then(|p| p.as_str()) == Some("/nfStatus")
                    && op.get("value").and_then(|v| v.as_str()) == Some("SUSPENDED")
            })
        })
    } else {
        patch.get("nfStatus").and_then(|v| v.as_str()) == Some("SUSPENDED")
    }
}

async fn handle_nf_update(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    // #1633: the registry key (TS 29.510 §5.2.2.2.2: upper-case UUIDs are handled as
    // lower-case).
    let nf_instance_id = nextgcore_nrfd::nnrf_handler::canonical_nf_instance_id(nf_instance_id);
    let nf_instance_id = nf_instance_id.as_str();
    log::info!("NF Update: {nf_instance_id}");

    // #1611: a verified caller updates only its own NF instance, checked before
    // the lookup so another NF's existence is not disclosed.
    let registrant = RegistrantIdentity::of(request, nrf_policy());
    if let Some(refused) = registrant.require_certificate(
        "NFUpdate",
        nf_instance_id,
        nrf_policy().require_registrant_identity,
    ) {
        return refused;
    }
    if let Some(refused) = registrant.bind_instance("NFUpdate", nf_instance_id) {
        return refused;
    }

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let manager = nf_manager();

    // Copy the stored profile out; no lock is held during patch application.
    let profile = match manager.get(nf_instance_id) {
        Some(p) => p,
        None => {
            return send_not_found(
                &format!("NF instance {nf_instance_id} not found"),
                Some("NF_NOT_FOUND"),
            )
        }
    };

    // Snapshot the pre-patch JSON — needed for diff / ChangeItem extraction
    // and to detect whether anything actually changed (nrfd-02).
    let pre_patch_doc = profile.to_json();

    // Apply the patch to a copy of the full stored document.
    let mut doc = pre_patch_doc.clone();
    let content_type = request
        .http
        .get_header("content-type")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_json_patch = content_type.contains("json-patch+json") || patch.is_array();
    let patch_result = if content_type.contains("json-patch+json") {
        apply_json_patch(&mut doc, &patch)
    } else if content_type.contains("merge-patch+json") {
        json_merge_patch(&mut doc, &patch);
        Ok(())
    } else if patch.is_array() {
        apply_json_patch(&mut doc, &patch)
    } else {
        json_merge_patch(&mut doc, &patch);
        Ok(())
    };

    match patch_result {
        Ok(()) => {}
        Err(PatchError::TestFailed(msg)) => {
            return send_error(409, "Conflict", &msg, Some("PATCH_TEST_FAILED"))
        }
        Err(PatchError::Malformed(msg)) => {
            return send_bad_request(&msg, Some("INVALID_MSG_FORMAT"))
        }
    }

    // A patch that adds or changes range patterns is held to the caps. One that
    // leaves them as they were (a heartbeat of a profile restored from before
    // the caps) is not refused for them; discovery excludes that profile.
    if nextgcore_nrfd::nnrf_handler::range_pattern_violation(&doc)
        != nextgcore_nrfd::nnrf_handler::range_pattern_violation(&pre_patch_doc)
    {
        if let Some(refused) = refuse_range_patterns(&doc) {
            return refused;
        }
    }
    // The patched document must still be a valid NFProfile with the same
    // identity (nfInstanceId is read-only for the resource).
    let mut updated = match NfProfile::from_json(&doc) {
        Ok(p) => p,
        Err(missing) => {
            return send_bad_request(
                &format!(
                    "Patch removes mandatory NFProfile attribute(s): {}",
                    missing.join(", ")
                ),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    if updated.nf_instance_id != nf_instance_id {
        return send_bad_request(
            "Patch must not change nfInstanceId",
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    // #1611: the patched profile's nfType must still be one the verified
    // certificate names (a patch must not re-type the instance either).
    if let Some(refused) = registrant.bind_nf_type(
        "NFUpdate",
        nf_instance_id,
        &updated.nf_type,
        registrant_nf_types_required(nrf_policy()),
    ) {
        return refused;
    }
    // #1719: a patch may not add an NF Set the registrant is not provisioned for.
    // Only the sets it ADDS are checked, so a heartbeat of a profile restored
    // from before the allowlist is not refused (startup names that profile). A
    // patch that changes nfType re-checks every set, as the entitlement may be
    // per type.
    let retyped = !profile.nf_type.eq_ignore_ascii_case(&updated.nf_type);
    let held = if retyped {
        Vec::new()
    } else {
        nf_set_ids_of(&pre_patch_doc)
    };
    let added: Vec<&str> = nf_set_ids_of(&doc)
        .into_iter()
        .filter(|set| {
            !held
                .iter()
                .any(|h| nextgcore_nrfd::nnrf_handler::same_nf_set_id(h, set))
        })
        .collect();
    if let Some(refused) =
        refuse_unallowed_nf_sets("NFUpdate", nf_instance_id, &updated.nf_type, added)
    {
        return refused;
    }
    // #2035: nor add a GUAMI an AMF of another AMF Set lists. As for the sets,
    // only the GUAMIs it adds (all of them when the patch re-types it, or
    // changes its AMF Set), so a heartbeat of a profile restored from before
    // the check is not refused.
    let reset = retyped
        || pre_patch_doc.pointer("/amfInfo/amfSetId") != doc.pointer("/amfInfo/amfSetId")
        || pre_patch_doc.pointer("/amfInfo/amfRegionId") != doc.pointer("/amfInfo/amfRegionId");
    let held_guamis = if reset {
        Vec::new()
    } else {
        nextgcore_nrfd::sbi_path::guami_list_of(&pre_patch_doc)
    };
    let added_guamis: Vec<&serde_json::Value> = nextgcore_nrfd::sbi_path::guami_list_of(&doc)
        .into_iter()
        .filter(|g| !held_guamis.contains(g))
        .collect();
    if let Some(refused) = refuse_guami_of_another_set(
        "NFUpdate",
        nf_instance_id,
        &updated.nf_type,
        &doc,
        &added_guamis,
    ) {
        return refused;
    }

    // nrfd-03: re-negotiate and stamp the heartBeatTimer the NRF will enforce
    // onto the stored/returned profile (PATCH also carries an update of it).
    let policy = nrf_policy();
    let hb = negotiate_heartbeat(
        updated.heartbeat_timer,
        policy.hb_default,
        policy.hb_min,
        policy.hb_max,
    );
    updated.set_heartbeat_timer(hb);

    if let Err(e) = manager.register(updated.clone()) {
        log::error!("Failed to store patched NF profile {nf_instance_id}: {e}");
        return send_error(500, "Internal Server Error", &e, Some("SYSTEM_FAILURE"));
    }

    // Refresh the no-heartbeat supervision timer on any PATCH (serves as a
    // heartbeat, TS 29.510 §5.2.2.3.2) from the negotiated heartBeatTimer.
    let expiry_secs = (hb as u64) * 2;
    arm_heartbeat_timer(nf_instance_id, Duration::from_secs(expiry_secs));
    log::debug!("Heartbeat timer refreshed for NF {nf_instance_id} ({expiry_secs}s)");

    // nrfd-02: Emit NF_PROFILE_CHANGED to matching subscribers when the
    // profile document changed materially (TS 29.510 §5.2.2.3 / §5.2.2.6).
    let profile_changed = pre_patch_doc != doc;
    if profile_changed {
        let profile_changes = compute_profile_changes(&pre_patch_doc, &doc, &patch, is_json_patch);
        let notify_profile = updated.clone();
        let server_uri = nrf_self_uri().to_string();
        tokio::spawn(async move {
            if let Err(e) = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
                &notify_profile,
                &server_uri,
                profile_changes,
            )
            .await
            {
                log::error!("Failed to send NF_PROFILE_CHANGED notifications: {e}");
            }
        });
    }

    // A heartbeat on a SUSPENDED NF restores it to REGISTERED (TS 29.510).
    // The status transition is always a material change — notify regardless
    // of whether other fields changed (nrfd-02 reactivate path).
    //
    // Issue #22 NES exception: a PATCH whose body itself sets nfStatus to
    // SUSPENDED is an explicit self-suspension (energy saving), not a
    // liveness signal — honor it instead of reactivating. The liveness
    // timer was still re-armed above, so a sleeping-but-heartbeating NF is
    // not auto-deregistered.
    let self_suspension = patch_requests_self_suspension(&patch, is_json_patch);
    if self_suspension {
        log::info!("NF {nf_instance_id} self-suspended (NES); skipping heartbeat reactivation");
    } else if manager.reactivate(nf_instance_id) {
        log::info!("NF {nf_instance_id} heartbeat received while SUSPENDED, back to REGISTERED");
        // Build the status-change ChangeItem from the reactivation.
        let reactivate_changes = vec![ChangeItem {
            op: "replace".to_string(),
            path: "/nfStatus".to_string(),
            value: Some(serde_json::json!("REGISTERED")),
            orig_value: Some(serde_json::json!("SUSPENDED")),
        }];
        // Re-fetch the now-REGISTERED profile so the body is accurate.
        let reactivated_profile = manager
            .get(nf_instance_id)
            .unwrap_or_else(|| updated.clone());
        let server_uri2 = nrf_self_uri().to_string();
        tokio::spawn(async move {
            if let Err(e) = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
                &reactivated_profile,
                &server_uri2,
                reactivate_changes,
            )
            .await
            {
                log::error!("Failed to send NF_PROFILE_CHANGED (reactivate) notifications: {e}");
            }
        });
    }

    // Re-read so the response reflects the live nfStatus after reactivation.
    let response_doc = manager
        .get(nf_instance_id)
        .map(|p| p.to_json())
        .unwrap_or_else(|| updated.to_json());

    SbiResponse::with_status(200)
        .with_json_body(&response_doc)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// The `3gppHal+json` media type the NF-instance collection is served as
/// (TS 29.510 §6.1.3.2.3.1).
const HAL_JSON_CONTENT_TYPE: &str = "application/3gppHal+json";

/// Handle NF List Retrieval request
///
/// TS 29.510 §6.1.3.2.3.1: `GET /nf-instances` returns a `UriList` in
/// `application/3gppHal+json`, whose `_links` members are `LinksValueSchema`
/// values — i.e. `{ "href": ... }` objects, or arrays of them — and it applies
/// the `nf-type`, `limit` and `page` query parameters.
///
/// Three things were wrong and all three were invisible to a lenient client:
/// the media type was plain `application/json`; `_links` carried bare strings
/// under a mis-spelled `items` member (the schema names it `item`); and the
/// query parameters were ignored outright — the request was bound as `_request`
/// — so a consumer paging through a large registry silently received the whole
/// list on every page.
async fn handle_nf_list_retrieval(request: &SbiRequest) -> SbiResponse {
    log::debug!("NF List Retrieval");

    let params = query_params(&request.header.uri);
    let param = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    // `nf-type` filters the collection; an unparseable `limit`/`page` is a 400
    // rather than a silently-ignored parameter, since ignoring it returns a page
    // the consumer did not ask for and cannot detect.
    let nf_type_filter = param("nf-type");
    let limit = match param("limit") {
        Some(text) => match text.parse::<usize>() {
            Ok(n) if n > 0 => Some(n),
            _ => {
                return send_bad_request(
                    &format!("limit {text:?} must be a positive integer"),
                    Some("MANDATORY_IE_INCORRECT"),
                )
            }
        },
        None => None,
    };
    let page = match param("page") {
        Some(text) => match text.parse::<usize>() {
            Ok(n) if n > 0 => Some(n),
            _ => {
                return send_bad_request(
                    &format!("page {text:?} must be a positive integer (pages are 1-based)"),
                    Some("MANDATORY_IE_INCORRECT"),
                )
            }
        },
        None => None,
    };
    if page.is_some() && limit.is_none() {
        return send_bad_request(
            "page requires limit: a page number is meaningless without a page size",
            Some("MANDATORY_IE_INCORRECT"),
        );
    }

    let manager = nf_manager();

    // Ordered by instance id so paging is stable: without a total order, two
    // requests for page 2 can return different, overlapping sets from the same
    // registry because the underlying map iterates arbitrarily.
    let mut matched: Vec<String> = manager
        .list()
        .iter()
        .filter(|p| nf_type_filter.is_none_or(|want| p.nf_type == want))
        .map(|p| p.nf_instance_id.clone())
        .collect();
    matched.sort_unstable();

    // `totalItemCount` counts everything the filter matched, not the page, so a
    // consumer can tell how many pages remain.
    let total_item_count = matched.len();

    let page_items: Vec<String> = match (limit, page) {
        (Some(limit), Some(page)) => matched
            .into_iter()
            .skip((page - 1) * limit)
            .take(limit)
            .collect(),
        (Some(limit), None) => matched.into_iter().take(limit).collect(),
        _ => matched,
    };

    let self_href = match (limit, page) {
        (Some(limit), Some(page)) => {
            format!("/nnrf-nfm/v1/nf-instances?limit={limit}&page={page}")
        }
        (Some(limit), None) => format!("/nnrf-nfm/v1/nf-instances?limit={limit}"),
        _ => "/nnrf-nfm/v1/nf-instances".to_string(),
    };

    let body = serde_json::json!({
        "_links": {
            "self": { "href": self_href },
            "item": page_items
                .iter()
                .map(|id| serde_json::json!({
                    "href": format!("/nnrf-nfm/v1/nf-instances/{id}")
                }))
                .collect::<Vec<_>>(),
        },
        "totalItemCount": total_item_count,
    });

    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
        .with_header("Content-Type", HAL_JSON_CONTENT_TYPE)
}

/// How long a `BootstrappingInfo` response may be cached, in seconds.
///
/// The document only changes when the NRF's own service surface or OAuth2
/// posture changes, so a short cache is safe and keeps a fleet of consumers from
/// re-fetching it on every start; the `ETag` lets a consumer revalidate cheaply.
const BOOTSTRAPPING_MAX_AGE_SECS: u32 = 60;

/// Handle `GET /bootstrapping` (TS 29.510 §5.5, `Nnrf_Bootstrapping`).
///
/// This service is how a consumer that knows only the NRF's authority learns
/// where the NRF's services live and whether they need OAuth2 — before it holds
/// a token. It was unrouted: the path has a single segment, so it never even
/// reached the service match and fell out at the `parts.len() < 3` guard as a
/// 404, leaving a consumer with no conformant way to discover the endpoints.
///
/// The service is optional per §5.5. It is nonetheless served unconditionally
/// rather than behind a build feature or an off-by-default switch: it is
/// read-only, it publishes only what an unauthenticated peer must be able to
/// read for bootstrapping to mean anything, and a gate that defaults closed
/// would leave the gap open for every deployment that did not know to flip it.
/// `/bootstrapping` is outside `oauth2_protected_path`, so server-side OAuth2
/// enforcement does not gate it even when enabled — which is required, since a
/// consumer reads this document precisely to find the token endpoint.
fn handle_bootstrapping(request: &SbiRequest) -> SbiResponse {
    log::debug!("Bootstrapping Info Request");

    let api_root = nrf_self_uri();
    let policy = nrf_policy();

    // Relation names are the registered types of TS 29.510 Table 6.4.6.3.3.1-1;
    // hrefs are absolute, as that clause requires.
    let body = serde_json::json!({
        "status": "OPERATIVE",
        "_links": {
            "self": { "href": format!("{api_root}/bootstrapping") },
            "manage": { "href": format!("{api_root}/nnrf-nfm/v1/nf-instances") },
            "subscribe": { "href": format!("{api_root}/nnrf-nfm/v1/subscriptions") },
            "discover": { "href": format!("{api_root}/nnrf-disc/v1/nf-instances") },
            "authorize": { "href": format!("{api_root}/nnrf-oauth2/v1/access-token") },
            "retrieve-key": { "href": format!("{api_root}/nnrf-oauth2/v1/jwks") },
        },
        // Keyed by NRF service name per §6.1.6.3.11. Reports the posture this
        // NRF actually enforces (`require_oauth2_server`), so the answer cannot
        // drift from behaviour the way a hardcoded value would.
        "oauth2Required": {
            "nnrf-nfm": policy.require_oauth2_server,
            "nnrf-disc": policy.require_oauth2_server,
        },
        "nrfInstanceId": nrf_instance_id(),
    });

    let etag = format!("\"{:016x}\"", fnv1a64(&body.to_string()));

    // RFC 9110 §13.1.2: a matching If-None-Match is answered 304 with no body.
    // The Bootstrapping yaml lists If-None-Match as a parameter but does not
    // enumerate a 304 response; the parameter has no other purpose, so the
    // conditional is honoured rather than accepted and ignored.
    if let Some(inm) = request.http.get_header("if-none-match") {
        if if_none_match_matches(inm, &etag) {
            return SbiResponse::with_status(304)
                .with_header("ETag", &etag)
                .with_header(
                    "Cache-Control",
                    format!("max-age={BOOTSTRAPPING_MAX_AGE_SECS}"),
                );
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
        .with_header("Content-Type", HAL_JSON_CONTENT_TYPE)
        .with_header("ETag", &etag)
        .with_header(
            "Cache-Control",
            format!("max-age={BOOTSTRAPPING_MAX_AGE_SECS}"),
        )
}

/// Does an `If-None-Match` header field match `etag`?
///
/// Handles the `*` form and a comma-separated list, and compares weak and strong
/// forms of the same tag as equal (RFC 9110 §13.1.2 uses the weak comparison
/// function for `If-None-Match`).
fn if_none_match_matches(header: &str, etag: &str) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").to_string();
    let want = strip(etag);
    header
        .split(',')
        .any(|candidate| candidate.trim() == "*" || strip(candidate) == want)
}

/// FNV-1a (64-bit) over a string, for deriving a strong `ETag` from a response
/// body without adding a hashing dependency.
///
/// Deliberately not `DefaultHasher`: that is documented as unstable across Rust
/// releases, which would silently invalidate every cached bootstrapping document
/// on a toolchain bump.
fn fnv1a64(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Split a request URI's query string into decoded `(key, value)` pairs.
///
/// Percent-decoding is applied to both halves so an encoded `nf-type` still
/// compares equal; `+` is left alone because these are path-style query values,
/// not form encoding.
fn query_params(uri: &str) -> Vec<(String, String)> {
    let Some(query) = uri.split_once('?').map(|(_, q)| q) else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        // #65: the shared QUERY decoder, where `+` is a literal plus. nrfd's
        // deleted local copy mapped `+` to a space here, which is the form-body
        // rule -- so a query value carrying a base64 token or an RFC 3339 offset
        // (`+02:00`) was silently corrupted.
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (
                nextgcore_sbi::uri_encode::decode_query_value(k),
                nextgcore_sbi::uri_encode::decode_query_value(v),
            ),
            None => (
                nextgcore_sbi::uri_encode::decode_query_value(pair),
                String::new(),
            ),
        })
        .collect()
}

/// Handle Subscription Create request
async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    handle_subscription_create_under(request, nextgcore_sbi::security::SbiProfile::resolve()).await
}

/// [`handle_subscription_create`] under an explicit SBI profile, so a test can
/// drive the production path without the process-global override (#1869).
async fn handle_subscription_create_under(
    request: &SbiRequest,
    profile: nextgcore_sbi::security::SbiProfile,
) -> SbiResponse {
    log::info!("Subscription Create");

    // #1809: the verified identity this subscription is bound to, checked
    // before the body is read or anything is stored.
    let owner = match RegistrantIdentity::of(request, nrf_policy())
        .subscription_owner(subscriber_identity_required())
    {
        Ok(owner) => owner,
        Err(refused) => return *refused,
    };

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let subscription: serde_json::Value = match serde_json::from_str(body) {
        Ok(s) => s,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Extract notification URI (required field)
    let notification_uri = match subscription
        .get("nfStatusNotificationUri")
        .and_then(|v| v.as_str())
    {
        Some(uri) => uri.to_string(),
        None => {
            return send_bad_request(
                "Missing nfStatusNotificationUri",
                Some("MISSING_NOTIFY_URI"),
            )
        }
    };
    // #1869: under production the notification is sent over TLS with a token, so
    // a cleartext callback is refused here, before anything is stored (TS 29.500
    // §5.2.7.2: 400 with `invalidParams` naming the attribute).
    if let Err(reason) =
        nextgcore_nrfd::sbi_path::check_notification_uri(&notification_uri, profile)
    {
        let body = serde_json::json!({
            "title": "Bad Request",
            "status": 400,
            "detail": reason,
            "cause": "MANDATORY_IE_INCORRECT",
            "invalidParams": [{ "param": "/nfStatusNotificationUri", "reason": reason }],
        });
        return SbiResponse::with_status(400)
            .with_body(body.to_string(), "application/problem+json");
    }

    // Generate subscription ID
    let subscription_id = uuid::Uuid::new_v4().to_string();

    // Parse the subscription condition (TS 29.510 §5.2.2.5.2 `SubscrCond`, a
    // `oneOf` over 17 condition schemas).
    //
    // An unrecognised condition is a 400, NOT an unconditional subscription.
    // This is the crux of the fix: the previous parse read three fields out of
    // whatever object arrived, so a conformant `NfSetCond` or `AmfCond` produced
    // a condition with no criteria at all — and a criteria-less condition
    // matched every NF in the registry, flooding the subscriber with
    // notifications it never asked for.
    let subscr_cond = match subscription.get("subscrCond") {
        Some(cond) => match nextgcore_nrfd::nnrf_handler::SubscrCond::from_json(cond) {
            Some(parsed) => {
                // A recognised variant whose criteria this NRF cannot evaluate
                // is refused too. Accepting it would leave only bad options:
                // notify for every NF, or for none — both silent, and both worse
                // than a refusal the consumer can act on.
                if let Some(unsupported) = parsed.unsupported_criterion() {
                    return send_bad_request(
                        &format!(
                            "subscrCond criterion {:?} is not supported: {}",
                            unsupported.criterion, unsupported.reason
                        ),
                        Some("SUBSCR_COND_NOT_SUPPORTED"),
                    );
                }
                Some(parsed)
            }
            None => {
                return send_bad_request(
                    &format!(
                        "subscrCond {cond} matches no TS 29.510 SubscrCond variant; \
                         omit subscrCond to subscribe to every NF"
                    ),
                    Some("MANDATORY_IE_INCORRECT"),
                )
            }
        },
        None => None,
    };

    // `reqNotifEvents` (TS 29.510 §5.2.2.5.2): the event types the subscriber
    // wants. Previously dropped on parse, so a subscriber asking only for
    // NF_DEREGISTERED still received every registration and profile change.
    let req_notif_events = match subscription.get("reqNotifEvents") {
        Some(v) => {
            let Some(arr) = v.as_array() else {
                return send_bad_request(
                    "reqNotifEvents must be an array of NotificationEventType",
                    Some("MANDATORY_IE_INCORRECT"),
                );
            };
            if arr.is_empty() {
                return send_bad_request(
                    "reqNotifEvents must carry at least one NotificationEventType (minItems: 1)",
                    Some("MANDATORY_IE_INCORRECT"),
                );
            }
            let events: Vec<String> = arr
                .iter()
                .filter_map(|e| e.as_str())
                .map(String::from)
                .collect();
            if events.len() != arr.len() {
                return send_bad_request(
                    "reqNotifEvents must contain only strings",
                    Some("MANDATORY_IE_INCORRECT"),
                );
            }
            Some(events)
        }
        None => None,
    };

    // `notifCondition` (TS 29.510 §5.2.2.5.2). The schema's `not` clause makes
    // monitoredAttributes and unmonitoredAttributes mutually exclusive, so a
    // body carrying both is refused rather than silently resolved one way.
    let notif_condition = match subscription.get("notifCondition") {
        Some(v) => match nextgcore_nrfd::nnrf_handler::NotifCondition::from_json(v) {
            Some(c) => Some(c),
            None => {
                return send_bad_request(
                    "notifCondition must carry exactly one of monitoredAttributes or \
                     unmonitoredAttributes, each with at least one entry",
                    Some("MANDATORY_IE_INCORRECT"),
                )
            }
        },
        None => None,
    };

    // Parse the proposed validity. `validityTime` is a DateTime string (TS 29.571
    // `DateTime`), not an integer duration — reading it with `as_u64` meant every
    // conformant proposal silently fell through to the default. The consumer MAY
    // propose; the NRF negotiates the validity it will enforce and returns it as
    // an absolute timestamp (below). Default = preconfigured 24h.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let validity_duration = match subscription.get("validityTime") {
        None | Some(serde_json::Value::Null) => NRF_SUBSCRIPTION_DEFAULT_VALIDITY,
        Some(v) => {
            let Some(text) = v.as_str() else {
                return send_bad_request(
                    "validityTime is a DateTime string (TS 29.571), not a number",
                    Some("MANDATORY_IE_INCORRECT"),
                );
            };
            let Some(absolute) = rfc3339_to_epoch(text) else {
                return send_bad_request(
                    &format!("validityTime {text:?} is not an RFC 3339 date-time"),
                    Some("MANDATORY_IE_INCORRECT"),
                );
            };
            if absolute <= now {
                return send_bad_request(
                    &format!("validityTime {text:?} is in the past"),
                    Some("MANDATORY_IE_INCORRECT"),
                );
            }
            // The proposal is honoured only up to the NRF's own maximum, so a
            // consumer cannot pin a subscription open indefinitely.
            (absolute - now).min(NRF_SUBSCRIPTION_DEFAULT_VALIDITY)
        }
    };

    // Build subscription data
    let subscription_data = nextgcore_nrfd::SubscriptionData {
        id: subscription_id.clone(),
        req_nf_type: subscription
            .get("reqNfType")
            .and_then(|v| v.as_str())
            .map(String::from),
        req_nf_instance_id: subscription
            .get("reqNfInstanceId")
            .and_then(|v| v.as_str())
            .map(String::from),
        notification_uri,
        subscr_cond,
        validity_duration,
        req_notif_events,
        notif_condition,
        // #1809: bound to who created it, so only that consumer can manage it.
        owner,
    };

    // nrfd-08: the NRF-assigned validityTime is an absolute RFC 3339 timestamp
    // (now + the armed validity duration) so the body matches the armed timer,
    // not the consumer's (possibly absent) proposal.
    let validity_time = epoch_to_rfc3339(now + validity_duration);

    // nrfd-08: return the full stored SubscriptionData (all fields), built
    // before the value is moved into the manager.
    let response_body = subscription_response_json(&subscription_data, &validity_time);

    // Store the subscription in the manager
    let manager = nf_manager();
    manager.add_subscription(subscription_data);

    // Start a subscription validity timer
    let timer_mgr = timer_manager();
    timer_mgr.start_timer(
        nextgcore_nrfd::NrfTimerId::SubscriptionValidity,
        Duration::from_secs(validity_duration),
        subscription_id.clone(),
    );

    log::info!("Created subscription: {subscription_id} (validity={validity_duration}s)");

    // Return 201 Created
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nnrf-nfm/v1/subscriptions/{subscription_id}"),
        )
        .with_json_body(&response_body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// nrfd-08: serialize a stored `SubscriptionData` to the SubscriptionData 201
/// response body (TS 29.510 §5.2.2.5 / Table 6.1.6.2.x), including the
/// NRF-assigned absolute `validityTime`.
fn subscription_response_json(
    sub: &nextgcore_nrfd::SubscriptionData,
    validity_time: &str,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "subscriptionId": sub.id,
        "nfStatusNotificationUri": sub.notification_uri,
        "validityTime": validity_time,
    });
    let map = obj.as_object_mut().expect("object");
    if let Some(ref t) = sub.req_nf_type {
        map.insert("reqNfType".to_string(), t.clone().into());
    }
    if let Some(ref id) = sub.req_nf_instance_id {
        map.insert("reqNfInstanceId".to_string(), id.clone().into());
    }
    // Echoed exactly as received. Rebuilding it from parsed fields is what used
    // to drop every member the old three-field model did not know about, so a
    // consumer reading back its own subscription saw a condition narrower than
    // the one it sent.
    if let Some(ref cond) = sub.subscr_cond {
        map.insert("subscrCond".to_string(), cond.raw.clone());
    }
    if let Some(ref events) = sub.req_notif_events {
        map.insert("reqNotifEvents".to_string(), events.clone().into());
    }
    if let Some(ref cond) = sub.notif_condition {
        map.insert("notifCondition".to_string(), cond.to_json());
    }
    obj
}

/// Re-arm supervision timers for records restored from the state file.
///
/// Restored NFs get a no-heartbeat timer so a stale registration is eventually
/// suspended and deregistered; restored subscriptions get a validity timer so an
/// expired subscription is cleaned up. Without this, a restart converts every
/// persisted record into one that never expires.
///
/// A restored NF is given a FULL supervision interval rather than the remainder
/// of its original one: how long it has already been silent is not persisted, and
/// granting a fresh interval risks keeping a dead NF one interval too long, while
/// guessing short would deregister a healthy NF that simply restarted alongside
/// the NRF. Erring toward keeping it is the recoverable direction — the next
/// missed heartbeat still suspends it.
fn rearm_restored_timers() {
    let manager = nf_manager();
    let timer_mgr = timer_manager();

    let mut nf_count = 0usize;
    for profile in manager.list() {
        let hb = profile.heartbeat_timer.unwrap_or(10) as u64;
        arm_heartbeat_timer(&profile.nf_instance_id, Duration::from_secs(hb * 2));
        nf_count += 1;
    }

    let mut sub_count = 0usize;
    for id in manager.subscription_ids() {
        if let Some(sub) = manager.find_subscription(&id) {
            let validity = restored_validity(&sub);
            if validity != sub.validity_duration {
                // Stored too, so what the NRF holds matches what it enforces.
                manager.set_subscription_validity(&id, validity);
            }
            timer_mgr.start_timer(
                nextgcore_nrfd::NrfTimerId::SubscriptionValidity,
                Duration::from_secs(validity),
                id.clone(),
            );
            sub_count += 1;
        }
    }

    if nf_count > 0 || sub_count > 0 {
        log::info!(
            "Re-armed timers for {nf_count} restored NF instance(s) and \
             {sub_count} restored subscription(s)"
        );
    }
}

// #235-adjacent (the RFC 3339 migration): nrfd's private `epoch_to_rfc3339` and
// `rfc3339_to_epoch` used to live here. They are now
// `nextgcore_sbi::datetime::{epoch_to_rfc3339, rfc3339_to_epoch}`, imported at the
// top of this file. The shared module was DERIVED from these two, so the migration
// is behaviour-preserving: both bodies were character-for-character the same
// algorithm, differing only in whether the civil-days intermediates were typed
// `i64` or `u64` -- and since `secs: u64` makes every intermediate non-negative,
// the two are semantically identical. Wire timestamps belong in one place: a
// leap-year or offset fix applied here would otherwise stay unapplied in the other
// five copies.

/// #1809 (R26 on #1831): the validity a restored subscription is re-armed
/// with. An ownerless one (written before #1809) is frozen under production,
/// so it must not outlive the NRF's own maximum: it is capped at
/// [`NRF_SUBSCRIPTION_DEFAULT_VALIDITY`] (24 h), after which its consumer
/// re-subscribes, bound. Before that cap a PATCH could set any validity, so a
/// frozen subscription could otherwise have lasted indefinitely. An owned
/// subscription keeps what was stored: its owner can still extend or cancel it.
fn restored_validity(sub: &nextgcore_nrfd::SubscriptionData) -> u64 {
    if sub.owner.is_none() {
        sub.validity_duration.min(NRF_SUBSCRIPTION_DEFAULT_VALIDITY)
    } else {
        sub.validity_duration
    }
}

/// Handle Subscription Delete request
async fn handle_subscription_delete(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Subscription Delete: {subscription_id}");

    let manager = nf_manager();
    // #1809: only the consumer that created the subscription may cancel it,
    // checked before anything is removed.
    if let Some(sub) = manager.find_subscription(subscription_id) {
        if let Some(refused) = RegistrantIdentity::of(request, nrf_policy()).bind_subscription(
            "NFStatusUnsubscribe",
            &sub,
            subscriber_identity_required(),
        ) {
            return refused;
        }
    }
    if manager.remove_subscription(subscription_id) {
        log::info!("Subscription {subscription_id} removed");
        SbiResponse::with_status(204) // No Content
    } else {
        send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Handle Subscription Update request
async fn handle_subscription_update(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Subscription Update: {subscription_id}");

    let manager = nf_manager();
    // An unknown id must be 404, not a bodyless 200 that tells the consumer its
    // extension succeeded (TS 29.510 Section 5.2.2.5.6).
    let Some(existing) = manager.find_subscription(subscription_id) else {
        return send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };
    // #1809: only the consumer that created the subscription may extend it,
    // checked before the body is read or anything is stored.
    if let Some(refused) = RegistrantIdentity::of(request, nrf_policy()).bind_subscription(
        "NFStatusSubscribe update",
        &existing,
        subscriber_identity_required(),
    ) {
        return refused;
    }

    let body = request.http.content.as_deref().unwrap_or("");
    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(
                &format!("Malformed subscription patch: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // TS 29.510 Section 5.2.2.5.6: the patch may carry validityTime, and it is
    // the ONLY replaceable attribute of a subscription. Accept both the JSON
    // Patch array form and a merge-patch object, since the resource accepts
    // application/json-patch+json.
    let proposed = extract_patch_validity_time(&patch);

    let Some(validity_time) = proposed else {
        // Nothing we can act on. Report it rather than returning a 200 that
        // implies the (absent) change was applied.
        return send_bad_request(
            "Subscription patch carries no replaceable attribute (expected validityTime)",
            Some("MANDATORY_IE_MISSING"),
        );
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // validityTime is a DateTime string per the spec, not a duration. Convert to
    // a duration from now; a time already in the past is a client error rather
    // than an instant expiry we silently apply.
    let Some(absolute) = rfc3339_to_epoch(&validity_time) else {
        return send_bad_request(
            &format!("validityTime {validity_time:?} is not an RFC 3339 date-time"),
            Some("INVALID_MSG_FORMAT"),
        );
    };
    if absolute <= now {
        return send_bad_request(
            &format!("validityTime {validity_time:?} is in the past"),
            Some("INVALID_MSG_FORMAT"),
        );
    }
    // R26 on #1831: the same maximum as Subscribe, so a PATCH cannot pin a
    // subscription open past what the NRF would grant a new one.
    let validity_duration = (absolute - now).min(NRF_SUBSCRIPTION_DEFAULT_VALIDITY);
    // The validity the NRF grants, which the response returns (TS 29.510
    // §5.2.2.5.6), not the proposal it narrowed.
    let validity_time = epoch_to_rfc3339(now + validity_duration);

    if !manager.set_subscription_validity(subscription_id, validity_duration) {
        return send_error(
            500,
            "Internal Server Error",
            "Failed to store the updated subscription validity",
            Some("SYSTEM_FAILURE"),
        );
    }

    // Re-arm the validity timer, which is the whole point of the PATCH: without
    // this the subscription still expires at the ORIGINAL time and the
    // consumer's extension is silently ineffective.
    let timer_mgr = timer_manager();
    timer_mgr.start_timer(
        nextgcore_nrfd::NrfTimerId::SubscriptionValidity,
        Duration::from_secs(validity_duration),
        subscription_id.to_string(),
    );
    log::info!(
        "Subscription {subscription_id} validity extended to {validity_time} \
         ({validity_duration}s); timer re-armed"
    );

    let mut updated = existing;
    updated.validity_duration = validity_duration;
    SbiResponse::with_status(200)
        .with_json_body(&subscription_response_json(&updated, &validity_time))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Pull `validityTime` out of either patch form the resource accepts: a JSON
/// Patch array of operations, or a merge-patch object.
fn extract_patch_validity_time(patch: &serde_json::Value) -> Option<String> {
    if let Some(ops) = patch.as_array() {
        // JSON Patch: the last replace/add wins, matching how a sequence of
        // operations applies.
        return ops
            .iter()
            .rfind(|op| {
                matches!(
                    op.get("op").and_then(|v| v.as_str()),
                    Some("replace") | Some("add")
                ) && op.get("path").and_then(|v| v.as_str()) == Some("/validityTime")
            })
            .and_then(|op| op.get("value"))
            .and_then(|v| v.as_str())
            .map(String::from);
    }
    patch
        .get("validityTime")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Handle NF Discovery request (TS 29.510 §6.2.3.2.3.1 SearchNFInstances)
///
/// Implements the query parameter matrix: target-nf-type + requester-nf-type
/// (both mandatory per the OpenAPI, missing => 400 MANDATORY_QUERY_PARAM_MISSING),
/// service-names (comma-separated), snssais / target-plmn-list (JSON in query),
/// dnn, target-nf-instance-id, target-nf-fqdn, limit.
///
/// No match => 200 OK with an empty SearchResult (`nfInstances: []`): the
/// SearchResult schema (TS 29.510 Table 6.2.6.2.2) requires the array but
/// permits it to be empty, and the reference NRF (Open5GS) answers 200 OK
/// with an empty list. 404 is NOT mandated for "target NF type unregistered".
async fn handle_nf_discover(request: &SbiRequest) -> SbiResponse {
    // #65: `http.params` arrives already percent-decoded from the shared SBI
    // server, so this must NOT decode again -- a second pass turns a legitimately
    // escaped `%2520` into a space that the consumer never sent.
    let param = |name: &str| {
        request
            .http
            .params
            .get(name)
            .cloned()
            .filter(|s| !s.is_empty())
    };

    let target_nf_type = param("target-nf-type").unwrap_or_default();
    let requester_nf_type = param("requester-nf-type").unwrap_or_default();

    log::info!("NF Discovery: target={target_nf_type}, requester={requester_nf_type}");

    // Both target-nf-type and requester-nf-type are `required: true`
    // (TS 29.510 SearchNFInstances).
    if target_nf_type.is_empty() {
        return send_bad_request(
            "Missing target-nf-type parameter",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }
    if requester_nf_type.is_empty() {
        return send_bad_request(
            "Missing requester-nf-type parameter",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }

    // JSON-valued query parameters (content: application/json in the spec).
    let json_array_param = |name: &str| -> Result<Vec<serde_json::Value>, String> {
        match param(name) {
            None => Ok(vec![]),
            Some(raw) => serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .ok_or_else(|| format!("{name} must be a JSON array")),
        }
    };
    let snssais = match json_array_param("snssais") {
        Ok(v) => v,
        Err(e) => return send_bad_request(&e, Some("INVALID_QUERY_PARAM")),
    };
    let target_plmn_list = match json_array_param("target-plmn-list") {
        Ok(v) => v,
        Err(e) => return send_bad_request(&e, Some("INVALID_QUERY_PARAM")),
    };
    // #1570: an array of MlAnalyticsInfo objects, minItems 1.
    let ml_analytics_info_list = match json_array_param("ml-analytics-info-list") {
        Ok(v) if v.iter().all(|i| i.is_object()) => v,
        Ok(_) => {
            return send_bad_request(
                "ml-analytics-info-list must be a JSON array of MlAnalyticsInfo objects",
                Some("INVALID_QUERY_PARAM"),
            )
        }
        Err(e) => return send_bad_request(&e, Some("INVALID_QUERY_PARAM")),
    };

    // nrfd-10: clamp the requested page size to the NRF default/maximum, and
    // page over the full match set in the handler (so discover_profiles still
    // returns everything matching). The generous defaults never truncate the
    // matched simulator's tiny registry.
    let policy = nrf_policy();
    let page_size = param("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(policy.disc_default_page_size)
        .clamp(1, policy.disc_max_page_size);
    let page = param("page")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|p| *p >= 1)
        .unwrap_or(1);

    let query = DiscoveryQuery {
        target_nf_type,
        requester_nf_type,
        // style: form, explode: false => comma-separated list.
        service_names: param("service-names")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default(),
        snssais,
        dnn: param("dnn"),
        target_plmn_list,
        target_nf_instance_id: param("target-nf-instance-id"),
        target_nf_fqdn: param("target-nf-fqdn"),
        target_nf_set_id: param("target-nf-set-id"),
        // Page in the handler; ask discover_profiles for the full match set.
        limit: None,
        // Identity selection for UDM/UDR/AUSF (TS 29.510 §5.3.2.2.2): route the
        // request to the instance whose supiRanges/gpsiRanges/routingIndicators/
        // groupId actually cover this subscriber, rather than to any registered
        // producer of the target type.
        supi: param("supi"),
        gpsi: param("gpsi"),
        routing_indicator: param("routing-indicator"),
        // style: form, explode: false => comma-separated, as service-names.
        group_id_list: param("group-id-list")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        ml_analytics_info_list,
    };

    let all_matches = discover_profiles(&query);
    let total = all_matches.len();
    nextgcore_nrfd::metrics::observe_discovery(Some(total));
    let (nf_instances, has_more) = paginate_results(all_matches, page, page_size);
    log::info!(
        "Found {} matching NF instances for type {} (page {page}, size {page_size}, returning {})",
        total,
        query.target_nf_type,
        nf_instances.len()
    );

    let mut result = serde_json::json!({
        "validityPeriod": policy.disc_validity_period,
        "nfInstances": nf_instances,
    });
    // nrfd-10: when results are truncated, surface a continuation link to the
    // next page (TS 29.510 Table 6.2.6.2.2 SearchResult `nfInstanceListUri`).
    if has_more {
        let next = page + 1;
        let uri = format!(
            "{}/nnrf-disc/v1/nf-instances?target-nf-type={}&requester-nf-type={}&limit={}&page={}",
            nrf_self_uri(),
            query.target_nf_type,
            query.requester_nf_type,
            page_size,
            next
        );
        if let Some(obj) = result.as_object_mut() {
            obj.insert("nfInstanceListUri".to_string(), serde_json::json!(uri));
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&result)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// nrfd-10: slice `items` to a 1-indexed `page` of `page_size`, returning the
/// page and whether more results exist beyond it. `page_size` is assumed ≥ 1.
fn paginate_results(
    items: Vec<serde_json::Value>,
    page: usize,
    page_size: usize,
) -> (Vec<serde_json::Value>, bool) {
    let len = items.len();
    let start = page.saturating_sub(1).saturating_mul(page_size);
    let end = start.saturating_add(page_size);
    let has_more = len > end;
    if start >= len {
        return (vec![], false);
    }
    (items[start..end.min(len)].to_vec(), has_more)
}

/// Handle OAuth2 Access Token Request
///
/// Implements the NRF's role as Authorization Server per 3GPP TS 29.510.
/// Accepts client_credentials grant and issues Bearer tokens.
/// Builds the JWK Set (RFC 7517) advertising the NRF's ES256 public key.
fn nrf_jwks_json() -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let point = nrf_signing_key().verifying_key().to_encoded_point(false);
    let x = point.x().expect("P-256 public key has an x coordinate");
    let y = point.y().expect("P-256 public key has a y coordinate");
    serde_json::json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": NRF_KID,
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        }]
    })
}

/// Handles `GET /nnrf-oauth2/v1/jwks`.
fn handle_jwks() -> SbiResponse {
    SbiResponse::with_status(200).with_body(nrf_jwks_json().to_string(), "application/json")
}

/// Builds an RFC 6749 §5.2 / TS 29.510 AccessTokenErr error response.
///
/// TS 29.510 (TS29510_Nnrf_AccessToken.yaml) maps token request failures to
/// 400 Bad Request with an AccessTokenErr body (`{"error": "..."}`) as
/// `application/json`, with mandatory `Cache-Control: no-store` and
/// `Pragma: no-cache` headers.
/// The NFType values TS 29.510 defines (TS29510_Nnrf_NFManagement.yaml `NFType`,
/// 29510-k00), in the yaml's order (#1753). The schema's second `anyOf`
/// alternative, a free string, is only "for forward compatibility with future
/// extensions" (TS 29.501 §5.3.12), so it is not in this list.
const TS29510_NF_TYPES: &[&str] = &[
    "NRF",
    "UDM",
    "AMF",
    "SMF",
    "AUSF",
    "NEF",
    "PCF",
    "SMSF",
    "NSSF",
    "UDR",
    "LMF",
    "GMLC",
    "5G_EIR",
    "SEPP",
    "UPF",
    "N3IWF",
    "AF",
    "UDSF",
    "BSF",
    "CHF",
    "NWDAF",
    "PCSCF",
    "CBCF",
    "HSS",
    "UCMF",
    "SOR_AF",
    "SPAF",
    "MME",
    "SCSAS",
    "SCEF",
    "SCP",
    "NSSAAF",
    "ICSCF",
    "SCSCF",
    "DRA",
    "IMS_AS",
    "AANF",
    "5G_DDNMF",
    "NSACF",
    "MFAF",
    "EASDF",
    "DCCF",
    "MB_SMF",
    "TSCTSF",
    "ADRF",
    "GBA_BSF",
    "CEF",
    "MB_UPF",
    "NSWOF",
    "PKMF",
    "MNPF",
    "SMS_GMSC",
    "SMS_IWMSC",
    "MBSF",
    "MBSTF",
    "PANF",
    "IP_SM_GW",
    "SMS_ROUTER",
    "DCSF",
    "MRF",
    "MRFP",
    "MF",
    "SLPKMF",
    "RH",
    "EIF",
    "AIOTF",
    "ADM",
    "SENF",
];

/// Whether `nf_type` is one of [`TS29510_NF_TYPES`] (case-insensitive, as nrfd
/// compares NF types everywhere else).
fn is_ts29510_nf_type(nf_type: &str) -> bool {
    TS29510_NF_TYPES
        .iter()
        .any(|t| t.eq_ignore_ascii_case(nf_type.trim()))
}

fn token_error(error: &str, description: &str) -> SbiResponse {
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    SbiResponse::with_status(400)
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
        .with_body(body.to_string(), "application/json")
}

/// Two S-NSSAIs match when sst is equal and sd is equal (an absent sd only
/// matches an absent sd, per TS 29.571 Snssai).
fn snssai_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("sst").and_then(|v| v.as_u64()) == b.get("sst").and_then(|v| v.as_u64())
        && a.get("sd").and_then(|v| v.as_str()) == b.get("sd").and_then(|v| v.as_str())
}

/// Two PLMN-Ids match when mcc and mnc are both equal.
fn plmn_eq(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("mcc").and_then(|v| v.as_str()) == b.get("mcc").and_then(|v| v.as_str())
        && a.get("mnc").and_then(|v| v.as_str()) == b.get("mnc").and_then(|v| v.as_str())
}

/// nrfd-04: does this producer satisfy the requester's PLMN and S-NSSAI
/// restrictions (TS 29.510 Table 6.3.5.2.2-1 `requesterPlmnList` /
/// `requesterSnssaiList`)? When the requester gives a list and the producer
/// advertises that attribute, at least one must match; a producer that
/// advertises none of an attribute "serves any" and stays eligible (mirrors
/// the discovery filter semantics).
fn producer_eligible(
    producer: &NfProfile,
    requester_plmns: &[serde_json::Value],
    requester_snssais: &[serde_json::Value],
) -> bool {
    if !requester_plmns.is_empty() {
        let pp = producer.plmns();
        if !pp.is_empty()
            && !pp
                .iter()
                .any(|x| requester_plmns.iter().any(|q| plmn_eq(x, q)))
        {
            return false;
        }
    }
    if !requester_snssais.is_empty() {
        let ps = producer.snssais();
        if !ps.is_empty()
            && !ps
                .iter()
                .any(|x| requester_snssais.iter().any(|q| snssai_eq(x, q)))
        {
            return false;
        }
    }
    true
}

/// OAuth2 access-token authorization decision (TS 33.501 §13.4.1.1.2 step 2;
/// TS 29.510 §5.4.2.2.2). The NRF acts as the authorization server and must:
///   1. verify the asserted consumer `nfType` matches the registered consumer
///      profile (an identity/parameter mismatch is `invalid_request`); and
///   2. verify each requested service-name scope is offered by — and permitted
///      to the consumer by — at least one registered producer of the target NF
///      type (`allowedNfTypes` profile- and service-level filters, TS 29.510
///      §6.1.6.2; an empty/absent list is "no restriction"); and
///   3. (#1811) grant a resource/operation-level scope
///      (`<service>:<resource>:<op>`) only when that producer's NFService lists
///      it for the consumer in `allowedOperationsPerNfType` /
///      `allowedOperationsPerNfInstance` (TS 29.510 Table 6.1.6.2.3-1 NOTE 11;
///      TS 33.501 §13.4.1.1 "additional scope"). An ungranted scope is left out
///      of the token, as RFC 6749 §3.3 lets the server do.
///
/// Returns the granted scope subset, or an RFC 6749 §5.2 error
/// `(code, description)` carried in the 400 `AccessTokenErr`.
///
/// Fail closed (issue #1391): when the NRF holds NO profile of the target NF
/// type, nothing positively authorizes the scope, so the answer is
/// `invalid_scope` and no token. TS 33.501 §13.4.1.1.2 step 2 has the NRF check
/// "whether the NF Service Consumer is authorized to access the requested
/// service(s)" and says that if it is not, "the NRF shall not issue an access
/// token" (33501-k20 l.14594-14602). NOTE 1 (l.14619-14622) only says what a
/// token WITHOUT NSSAI/NSI claims may be used for; it does not license granting
/// a scope that no registered producer offers. The old conservative grant let a
/// token minted while the producer was down outlive a restrictive
/// `allowedNfTypes` the producer registered with afterwards.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn authorize_access_token(
    consumer: &NfProfile,
    req_nf_type: &str,
    target_nf_type: &str,
    requested_scopes: &[String],
    producers: &[NfProfile],
    requester_plmns: &[serde_json::Value],
    requester_snssais: &[serde_json::Value],
) -> Result<Vec<String>, (&'static str, String)> {
    authorize_access_token_for(
        consumer,
        req_nf_type,
        target_nf_type,
        requested_scopes,
        producers,
        producers,
        requester_plmns,
        requester_snssais,
    )
}

/// #1828 (R26 on #1922): the producers that will ACCEPT the token being
/// minted, which a resource scope must be allowed by. A type-targeted token's
/// audience is the NF type (TS 29.510 §6.3.5.2.4), and every producer of that
/// type accepts it (TS 33.501 §13.4.1.2), whatever its status, PLMN or slice.
/// So the set is every registered producer of the type: SUSPENDED included
/// (it can resume and accept the token while it is still valid), and never
/// narrowed by the requester's own `requesterPlmnList` / `requesterSnssaiList`,
/// which the requester chooses. An instance-targeted token's audience is that
/// instance alone.
fn token_acceptors(
    registered: &[NfProfile],
    target_nf_type: &str,
    target_instance: Option<&NfProfile>,
) -> Vec<NfProfile> {
    match target_instance {
        Some(p) => vec![p.clone()],
        None => registered
            .iter()
            .filter(|p| p.nf_type.eq_ignore_ascii_case(target_nf_type))
            .cloned()
            .collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn authorize_access_token_for(
    consumer: &NfProfile,
    req_nf_type: &str,
    target_nf_type: &str,
    requested_scopes: &[String],
    producers: &[NfProfile],
    acceptors: &[NfProfile],
    requester_plmns: &[serde_json::Value],
    requester_snssais: &[serde_json::Value],
) -> Result<Vec<String>, (&'static str, String)> {
    // (1) The asserted nfType must match the registered consumer profile.
    if !req_nf_type.eq_ignore_ascii_case(&consumer.nf_type) {
        return Err((
            "invalid_request",
            format!(
                "nfType {req_nf_type:?} does not match the registered profile of consumer {} (nfType {:?})",
                consumer.nf_instance_id, consumer.nf_type
            ),
        ));
    }

    // (2) No registered producer of the target type at all: nothing authorizes
    //     the scope, so fail closed (issue #1391, TS 33.501 §13.4.1.1.2 step 2).
    //     The consumer retries once the producer has registered; tokens are never
    //     cached on failure (nextgcore-sbi OAuth2Client::get_token_on_behalf_of).
    if producers.is_empty() {
        return Err((
            "invalid_scope",
            format!(
                "no operative {target_nf_type} producer is registered with this NRF, so no producer \
                 authorizes the requested service(s) {requested_scopes:?}"
            ),
        ));
    }

    // (nrfd-04) Restrict to producers serving the requester's PLMN/slice set.
    let eligible: Vec<&NfProfile> = producers
        .iter()
        .filter(|p| producer_eligible(p, requester_plmns, requester_snssais))
        .collect();

    // (3) Per requested service-name: must be offered by AND permitted to the
    //     consumer by at least one ELIGIBLE producer of the target type.
    let mut granted = Vec::new();
    let mut any_offered = false;
    for service in requested_scopes {
        // #1811: a resource/operation-level scope is granted only to the
        // consumers the producer's allowedOperationsPerNf* name.
        let decisions: Vec<(bool, bool)> = eligible
            .iter()
            .map(|p| p.authorizes_scope(&consumer.nf_type, &consumer.nf_instance_id, service))
            .collect();
        let offered = decisions.iter().any(|(o, _)| *o);
        let permitted = if service.contains(':') {
            // #1828: TS 29.510 Table 6.1.6.2.3-1 NOTE 11 is per producer, and a
            // token whose audience is the target TYPE is accepted by every
            // producer of it. A resource scope is therefore granted only when
            // an eligible producer allows it AND every ACCEPTOR of the token
            // offering the service allows it too ([`token_acceptors`]: every
            // registered producer of the type, whatever its status, and not
            // the requester-filtered eligible set). One UDR registered with a
            // wider map must not put the K-read scope into a token all UDRs
            // accept. An instance-targeted token has one acceptor.
            decisions.iter().any(|(_, perm)| *perm)
                && acceptors
                    .iter()
                    .map(|p| {
                        p.authorizes_scope(&consumer.nf_type, &consumer.nf_instance_id, service)
                    })
                    .filter(|(o, _)| *o)
                    .all(|(_, perm)| perm)
        } else {
            decisions.iter().any(|(_, perm)| *perm)
        };
        any_offered |= offered;
        if permitted {
            granted.push(service.clone());
        }
    }

    if !granted.is_empty() {
        return Ok(granted);
    }

    // Nothing authorized: distinguish "an eligible producer offers the service
    // but the consumer type is barred" (unauthorized_client) from "no eligible
    // producer offers the requested service at all" — which also covers a
    // requester PLMN/S-NSSAI that no producer serves (invalid_scope).
    if any_offered {
        Err((
            "unauthorized_client",
            format!(
                "consumer nfType {:?} is not in allowedNfTypes of any {target_nf_type} producer \
                 offering the requested service(s)",
                consumer.nf_type
            ),
        ))
    } else {
        Err((
            "invalid_scope",
            format!(
                "no registered {target_nf_type} producer serving the requester's PLMN/slice offers \
                 the requested service(s) {requested_scopes:?}"
            ),
        ))
    }
}

/// nrfd-05 / CCA hardening: client-credentials-assertion (CCA) binding check
/// (TS 29.510 §6.7.5, TS 33.501 §13.3.8.3). Decodes the CCA JWT payload and
/// verifies its subject/issuer are the body `nfInstanceId`, that it has not
/// expired, that the `iat` timestamp is present and not in the future, and that
/// the `aud` claim matches the NRF's own NF type ("NRF").
///
/// This function performs the claim-binding plus the iat/aud validation mandated
/// of the NRF by §13.3.8.3. The CCA's ES256 JWS SIGNATURE is verified by the
/// companion [`verify_cca_signature`] (I1), against a key resolved by
/// [`resolve_cca_verifying_key`] — which is where §13.3.8.3's FOURTH and final
/// bullet now lives (issue #393):
///
/// > It verifies that the NF instance ID of the NFc in the CCA matches the NF
/// > instance ID in the public key certificate used for signing the CCA.
///
/// When the CCA carries an `x5c` chain (TS 33.501 §13.3.8.2) the NRF validates it
/// to a configured CA, requires the leaf's URI SubjectAltName to equal `sub`, and
/// verifies the signature against the key that certificate certifies — so the
/// certificate is authoritative and `cca_trusted_keys` is not consulted. With no
/// `x5c` the trust store remains the binding, which is a documented deviation kept
/// for deployments with no PKI (issue #187). `x5u` is refused by name; the
/// reasoning is in [`nextgcore_sbi::cca_x5c`].
fn verify_cca_binding(
    cca_jwt: &str,
    expected_nf_instance_id: &str,
    now: u64,
) -> Result<(), (&'static str, String)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = cca_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err((
            "invalid_client",
            "Client Credentials Assertion is not a well-formed JWT".to_string(),
        ));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .ok_or_else(|| {
            (
                "invalid_client",
                "Client Credentials Assertion payload is not valid base64url JSON".to_string(),
            )
        })?;

    // `sub` (and, per TS 29.510 §6.7.5, the assertion is self-issued so `iss`
    // equals `sub`) must be the NF Instance ID asserted in the token request.
    let sub = payload.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if !same_nf_instance_id(sub, expected_nf_instance_id) {
        return Err((
            "invalid_client",
            format!(
                "CCA subject {sub:?} does not match request nfInstanceId {expected_nf_instance_id:?}"
            ),
        ));
    }
    if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
        if !same_nf_instance_id(iss, expected_nf_instance_id) {
            return Err((
                "invalid_client",
                format!("CCA issuer {iss:?} does not match request nfInstanceId"),
            ));
        }
    }
    // Reject an expired assertion when it carries an `exp` (TS 29.510 §6.7.5).
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        if exp <= now {
            return Err((
                "invalid_client",
                "Client Credentials Assertion has expired".to_string(),
            ));
        }
    }
    // TS 33.501 §13.3.8.3: the NRF validates the timestamp (iat). The CCA carries
    // it (§13.3.8.2); require its presence and reject a future-dated assertion,
    // allowing a small clock skew.
    const CCA_CLOCK_SKEW_SECS: u64 = 60;
    match payload.get("iat").and_then(|v| v.as_u64()) {
        Some(iat) if iat > now.saturating_add(CCA_CLOCK_SKEW_SECS) => {
            return Err((
                "invalid_client",
                "Client Credentials Assertion iat is in the future".to_string(),
            ));
        }
        Some(_) => {}
        None => {
            return Err((
                "invalid_client",
                "Client Credentials Assertion is missing the mandatory iat claim".to_string(),
            ));
        }
    }
    // TS 33.501 §13.3.8.3: the receiving NRF checks that the audience claim
    // matches its own NF type ("NRF"). `aud` is a JSON string or array of strings.
    let aud_matches_nrf = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == "NRF",
        Some(serde_json::Value::Array(a)) => a.iter().any(|v| v.as_str() == Some("NRF")),
        _ => false,
    };
    if !aud_matches_nrf {
        return Err((
            "invalid_client",
            "Client Credentials Assertion audience does not match the NRF's NF type".to_string(),
        ));
    }
    Ok(())
}

/// I1 (TS 33.501 §13.3.8.3): cryptographically verify a CCA's ES256 JWS
/// signature against the requesting NF's trusted public `key`.
///
/// The JWS signing input is the ASCII `base64url(header) "." base64url(payload)`
/// (RFC 7515 §5.2); the JOSE header `alg` MUST be `ES256` — `none` and every
/// other algorithm are rejected so a forged unsigned/downgraded assertion cannot
/// pass (the classic JWS algorithm-substitution hole). ES256 signatures are the
/// fixed 64-byte `r||s` form (RFC 7518 §3.4). Returns `invalid_client` on any
/// failure so the caller emits a fail-closed AccessTokenErr.
fn verify_cca_signature(
    cca_jwt: &str,
    key: &p256::ecdsa::VerifyingKey,
) -> Result<(), (&'static str, String)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;

    let parts: Vec<&str> = cca_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err((
            "invalid_client",
            "Client Credentials Assertion is not a well-formed JWT".to_string(),
        ));
    }
    // JOSE header: the algorithm MUST be ES256 (TS 33.501 §13.3.8.2).
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .ok_or((
            "invalid_client",
            "Client Credentials Assertion header is not valid base64url JSON".to_string(),
        ))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err((
            "invalid_client",
            "Client Credentials Assertion alg is not ES256".to_string(),
        ));
    }
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        (
            "invalid_client",
            "Client Credentials Assertion signature is not valid base64url".to_string(),
        )
    })?;
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| {
        (
            "invalid_client",
            "Client Credentials Assertion has a malformed ES256 signature".to_string(),
        )
    })?;
    // Verify over the exact base64url header.payload as received (do NOT
    // re-encode the decoded parts — canonicalisation would change the bytes).
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            (
                "invalid_client",
                "Client Credentials Assertion signature verification failed".to_string(),
            )
        })?;
    Ok(())
}

/// Issue #393 (TS 33.501 §13.3.8.3, last bullet): resolve the public key the
/// CCA's JWS signature must be verified against, and — when the assertion carries
/// an `x5c` chain — BIND that certificate to the asserted NF Instance ID.
///
/// This is the function that decides which of the two mechanisms is authoritative,
/// so the precedence is exhaustive and has no fallback edge:
///
/// | CCA header | `cca_trust_anchors` | outcome |
/// |---|---|---|
/// | `x5c` | configured | chain validated, leaf URI SAN == `sub` enforced, key taken FROM THE LEAF. The trust store is not consulted, even on failure. |
/// | `x5c` | empty | `invalid_client`. Not a downgrade: see below. |
/// | `x5u` | either | `invalid_client`, naming `x5u` as unsupported. |
/// | neither | either | the `cca_trusted_keys` store, then `cca_trusted_keys_dir` — unchanged from issue #187. |
///
/// **Why an `x5c`-bearing CCA is refused rather than downgraded when no anchors are
/// configured.** The alternative — try the certificate, fall back to the trust
/// store — hands the requester the choice of which check it faces, because the
/// requester decides whether to attach `x5c`. A malformed or untrusted chain would
/// become a way to reach the weaker path. So the presence of `x5c` COMMITS the
/// request to the certificate path, and failure there is final.
///
/// The key comes from the validated leaf, not from the store, and that is the whole
/// point: a chain that is validated but not used to verify the signature would
/// constrain nothing about who actually signed the assertion.
fn resolve_cca_verifying_key(
    policy: &NrfPolicy,
    cca_jwt: &str,
    nf_instance_id: &str,
    now: u64,
) -> Result<p256::ecdsa::VerifyingKey, (&'static str, String)> {
    use nextgcore_sbi::cca_x5c::{cert_reference_from_jose_header, CcaCertReference};

    let header = decode_cca_jose_header(cca_jwt)?;
    let reference = cert_reference_from_jose_header(&header).map_err(|e| {
        (
            "invalid_client",
            format!("Client Credentials Assertion certificate reference is unusable: {e}"),
        )
    })?;

    match reference {
        CcaCertReference::Chain(chain) => {
            if policy.cca_trust_anchors.is_empty() {
                return Err((
                    "invalid_client",
                    "Client Credentials Assertion carries an x5c certificate chain but this NRF \
                     has no cca_trust_anchors configured, so the certificate binding required by \
                     TS 33.501 §13.3.8.3 cannot be evaluated. The request is refused rather than \
                     verified against the cca_trusted_keys store, because falling back would let \
                     a requester choose the weaker check."
                        .to_string(),
                ));
            }
            let verified =
                nextgcore_sbi::cca_x5c::verify_x5c_binding(&chain, &policy.cca_trust_anchors, now)
                    .map_err(|e| ("invalid_client", format!("CCA x5c chain rejected: {e}")))?;

            // §13.3.8.3's final bullet, the reason this issue exists. Both ids are
            // named: a mismatch is an operator-visible misissuance or an attempted
            // impersonation, and "they differ" without saying how is undiagnosable.
            if !same_nf_instance_id(&verified.nf_instance_id, nf_instance_id) {
                return Err((
                    "invalid_client",
                    format!(
                        "CCA x5c certificate binds NF Instance ID {:?}, but the assertion claims \
                         {nf_instance_id:?}; TS 33.501 §13.3.8.3 requires them to match",
                        verified.nf_instance_id
                    ),
                ));
            }

            verified.es256_verifying_key().map_err(|e| {
                (
                    "invalid_client",
                    format!("CCA x5c leaf certificate does not certify a usable ES256 key: {e}"),
                )
            })
        }
        CcaCertReference::Url(url) => Err((
            "invalid_client",
            format!(
                "Client Credentials Assertion references its signing certificate by x5u ({url}); \
                 this NRF implements only the x5c arm of TS 33.501 §13.3.8.2, because fetching a \
                 requester-supplied URL during unauthenticated token issuance is an SSRF and \
                 availability hazard. Present the certificate chain inline as x5c."
            ),
        )),
        CcaCertReference::Absent => {
            // No certificate reference: the pre-#393 trust-store path (issue #187).
            // Fail-closed, unchanged — an issuer with no trusted key is refused.
            match policy
                .cca_trusted_keys
                .get(&canonical_nf_instance_id(nf_instance_id))
            {
                Some(k) => Ok(*k),
                // The file as the request spells the ID, then in the registry's
                // spelling (#1633).
                None => match lazy_trusted_key(policy, nf_instance_id) {
                    Some(k) => Ok(k),
                    None => Err((
                        "invalid_client",
                        format!(
                            "no trusted ES256 key configured to verify the CCA signature of \
                             nfInstanceId {nf_instance_id:?}"
                        ),
                    )),
                },
            }
        }
    }
}

/// A key published in `cca_trusted_keys_dir` after start for `nf_instance_id`
/// (issue #187): the NRF is the first NF up, and each NF publishes its own public
/// JWK as it starts, so an NF that registers after the NRF cannot have been in
/// the startup read. Deliberately not cached, so a rotated key is picked up.
/// `None`, and so a refusal, when no directory is configured or no usable key
/// is there.
///
/// #1633: every file whose ID names the same NF, in any case of its UUID, is
/// read, and under the load-time rule two different keys mean none is trusted.
/// So is an NF whose entries conflicted at load: the request's case, or a file
/// published later, cannot bring a key back for it.
fn lazy_trusted_key(policy: &NrfPolicy, nf_instance_id: &str) -> Option<p256::ecdsa::VerifyingKey> {
    let dir = policy.cca_trusted_keys_dir.as_ref()?;
    // Kept from the single-file lookup: an ID that could not be a file name is
    // not looked up at all.
    if nf_instance_id.is_empty()
        || nf_instance_id.contains('/')
        || nf_instance_id.contains('\\')
        || nf_instance_id.contains("..")
    {
        return None;
    }
    let canonical = canonical_nf_instance_id(nf_instance_id);
    if policy.cca_conflicted.contains(&canonical) {
        return None;
    }
    // A conflict among the files leaves the NF out of `keys` (TrustedKeySet).
    let found = TrustedKeySet::read_dir(dir, Some(&canonical)).ok()?;
    let key = found.keys.get(&canonical).copied()?;
    log::info!(
        "nrfd-187: picked up the CCA trusted key for nfInstanceId {canonical} from {} \
         (published after this NRF started)",
        dir.display()
    );
    Some(key)
}

/// NF IDs whose CCA key conflict has been reported (#1633); one lock, beside its
/// global.
static CCA_KEY_CONFLICTS_REPORTED: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::OnceLock::new();

/// Report, once per NF for the NRF's life, that `source` holds different CCA
/// keys for the NF `id` under differently cased IDs (#1633): an ERROR an
/// operator sees once, not a WARN per request, and the
/// `nrf_cca_trusted_key_conflicts_total` counter. Returns whether this call
/// reported it.
fn report_cca_key_conflict(source: &str, id: &str, spelled: &str) -> bool {
    let fresh = CCA_KEY_CONFLICTS_REPORTED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.to_string());
    if fresh {
        log::error!(
            "nrfd-1633: {source} holds different CCA keys for NF {id} under differently cased \
             IDs (one of them {spelled:?}); trusting none, so that NF's CCA is refused until \
             the stale entry is removed and the NRF restarted"
        );
        nextgcore_nrfd::metrics::observe_cca_key_conflict();
    }
    fresh
}

/// Decode a CCA's JWS protected header to JSON.
///
/// Split out because both [`verify_cca_signature`] (which checks `alg`) and
/// [`resolve_cca_verifying_key`] (which reads `x5c`/`x5u`) need it, and a second
/// hand-rolled decode of the same attacker-supplied bytes is how the two drift
/// apart.
fn decode_cca_jose_header(cca_jwt: &str) -> Result<serde_json::Value, (&'static str, String)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let first = cca_jwt.split('.').next().unwrap_or("");
    URL_SAFE_NO_PAD
        .decode(first)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .ok_or((
            "invalid_client",
            "Client Credentials Assertion header is not valid base64url JSON".to_string(),
        ))
}

/// The HTTP header a trusted TLS-terminating SBI ingress / SCP uses to convey
/// the verified client certificate to the upstream NF (Envoy `x-forwarded-
/// client-cert`, the de-facto SBA service-mesh standard; same trust model as
/// RFC 9440 `Client-Cert`). It MUST be set only by the trusted terminator and
/// stripped from any client-supplied copy at the trust boundary.
const XFCC_HEADER: &str = "x-forwarded-client-cert";

/// #1990: the one XFCC entry a declared terminator forwarded, as its `Key=Value`
/// elements (keys lower-cased), parsed per Envoy's grammar: entries are
/// separated by unquoted `,`, elements by unquoted `;`, and a value may be
/// double-quoted with `\"` and `\\` escapes inside. `None` for anything
/// ambiguous, which is refused rather than guessed at:
/// - more than one entry (under Envoy `APPEND_FORWARD` the leading entries are
///   whatever the client sent; only a lone entry is the terminator's own);
/// - an unterminated quote, a quote inside an unquoted value, or trailing text
///   after a closing quote;
/// - an element without `=`, or a key that appears twice.
///
/// Before, quotes were toggled with no escape handling, so a client certificate
/// whose Subject DN held `\"` could close the quote early and smuggle a second
/// `URI=` into the entry.
fn parse_xfcc_single_entry(header: &str) -> Option<std::collections::HashMap<String, String>> {
    let mut entries: Vec<Vec<(String, String)>> = vec![Vec::new()];
    let mut key = String::new();
    let mut value = String::new();
    let mut in_key = true;
    let mut chars = header.chars().peekable();
    // Where the current value stands: not started, inside quotes, closed.
    #[derive(PartialEq)]
    enum Q {
        Bare,
        Open,
        Closed,
    }
    let mut q = Q::Bare;
    let push = |entry: &mut Vec<(String, String)>,
                key: &mut String,
                value: &mut String,
                in_key: &mut bool|
     -> Option<()> {
        if *in_key {
            // An element with no `=`: only an empty trailing element is allowed.
            if !key.trim().is_empty() {
                return None;
            }
        } else {
            let k = key.trim().to_ascii_lowercase();
            if k.is_empty() || entry.iter().any(|(e, _)| *e == k) {
                return None;
            }
            entry.push((k, std::mem::take(value)));
        }
        key.clear();
        *in_key = true;
        Some(())
    };
    while let Some(c) = chars.next() {
        if !in_key && q == Q::Open {
            match c {
                '\\' => value.push(chars.next()?),
                '"' => q = Q::Closed,
                _ => value.push(c),
            }
            continue;
        }
        match c {
            ',' | ';' => {
                let entry = entries.last_mut().expect("one entry");
                push(entry, &mut key, &mut value, &mut in_key)?;
                q = Q::Bare;
                if c == ',' {
                    entries.push(Vec::new());
                }
            }
            '=' if in_key => in_key = false,
            '"' if !in_key && q == Q::Bare && value.trim().is_empty() => {
                value.clear();
                q = Q::Open;
            }
            '"' => return None,
            _ if in_key => key.push(c),
            _ if q == Q::Closed => {
                if !c.is_whitespace() {
                    return None;
                }
            }
            _ => value.push(c),
        }
    }
    if q == Q::Open {
        return None;
    }
    let entry = entries.last_mut().expect("one entry");
    push(entry, &mut key, &mut value, &mut in_key)?;
    let entries: Vec<_> = entries.into_iter().filter(|e| !e.is_empty()).collect();
    match entries.as_slice() {
        [only] => Some(only.iter().cloned().collect()),
        _ => None,
    }
}

/// #1990 (R30): whether this connection's OWN verified client certificate is a
/// configured XFCC terminator's: the flag is on, a verified certificate was
/// presented, and one of its URI SANs is in `trusted_xfcc_terminators`. Only
/// then is the XFCC header believed. An unauthenticated connection (client auth
/// is optional by default, so anyone can send the header) and any other mTLS
/// peer are not terminators.
///
/// #2000: ANY URI SAN of the certificate counts, not only the one chosen as its
/// NF Instance ID (`urn:uuid:` first), so a terminator allowlisted by its SPIFFE
/// ID is recognised even when its certificate also carries a `urn:uuid:` SAN.
///
/// #2012: an entry and a SAN compare case-insensitively only when BOTH are a
/// UUID ([`as_uuid`]: RFC 4122 text, with or without `urn:uuid:`), as UUIDs
/// compare (RFC 4122 §3). Anything else compares exactly, as written: a SAN
/// that merely starts with `urn:uuid:` no longer matches a non-UUID entry
/// whatever its case.
fn from_trusted_terminator(request: &SbiRequest, policy: &NrfPolicy) -> bool {
    if !policy.trust_forwarded_client_cert || !request.peer_cert_present {
        return false;
    }
    // The certificate's URI SANs, and the NF Instance ID chosen from them (the
    // only one a request built without a handshake carries).
    let sans: Vec<&str> = request
        .peer_cert_uri_sans
        .iter()
        .map(String::as_str)
        .chain(request.peer_cert_nf_instance_id.as_deref())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    policy.trusted_xfcc_terminators.iter().any(|t| {
        let t = t.trim();
        !t.is_empty()
            && sans.iter().any(|s| match (as_uuid(t), as_uuid(s)) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => *s == t,
            })
    })
}

/// #2012: the UUID `v` names, when it is one: RFC 4122 text (8-4-4-4-12 hex
/// digits), bare or after a case-insensitive `urn:uuid:` (RFC 4122 §3).
fn as_uuid(v: &str) -> Option<&str> {
    let v = v.trim();
    let id = match v.get(..9) {
        Some(p) if p.eq_ignore_ascii_case("urn:uuid:") => &v[9..],
        _ => v,
    };
    let b = id.as_bytes();
    (b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        }))
    .then_some(id)
}

/// Whether the connection's verified certificate identifies the caller
/// itself: present, and not a configured terminator's (whose certificate
/// names the terminator, not the NF it forwards for).
fn direct_certificate(request: &SbiRequest, policy: &NrfPolicy) -> bool {
    request
        .peer_cert_nf_instance_id
        .as_deref()
        .map(str::trim)
        .is_some_and(|id| !id.is_empty())
        && !from_trusted_terminator(request, policy)
}

/// #1990: under the production profile, believing XFCC needs both the
/// terminator allowlist and required client authentication on the listener;
/// anything less is refused at startup. Under dev an empty allowlist only
/// means no header is ever believed, and that is logged.
fn check_forwarded_trust(
    profile: nextgcore_sbi::security::SbiProfile,
    policy: &NrfPolicy,
    server_tls: Option<&NrfServerTls>,
) -> anyhow::Result<()> {
    if !policy.trust_forwarded_client_cert {
        return Ok(());
    }
    let required = server_tls.is_some_and(|t| t.client_auth == ClientAuth::Required);
    if profile.is_production() {
        if policy.trusted_xfcc_terminators.is_empty() {
            anyhow::bail!(
                "trust_forwarded_client_cert needs nrf.sbi.oauth2.trusted_xfcc_terminators under \
                 the production SBI profile: the URI SAN(s) of the terminator's own client \
                 certificate"
            );
        }
        if !required {
            anyhow::bail!(
                "trust_forwarded_client_cert needs client_auth: required on the NRF listener \
                 under the production SBI profile, so the terminator is recognised by its \
                 certificate"
            );
        }
    } else if policy.trusted_xfcc_terminators.is_empty() {
        log::warn!(
            "trust_forwarded_client_cert is on but nrf.sbi.oauth2.trusted_xfcc_terminators is \
             empty: no x-forwarded-client-cert header will be believed"
        );
    }
    Ok(())
}

/// #1990: what a declared TLS terminator vouches for, read from the
/// certificate it forwarded in XFCC `Cert=` and from nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardedClientCert {
    /// The NF Instance ID of the certificate's `urn:uuid:` URI SAN.
    nf_instance_id: String,
    /// Its RFC 9310 NFTypes (empty when it carries none).
    nf_types: Vec<String>,
}

/// #1979/#1990: the client certificate a declared TLS terminator forwarded,
/// or `None` when it is not to be believed.
///
/// - Only with `trust_forwarded_client_cert`, and only on a connection whose
///   own verified client certificate is a configured terminator's
///   ([`from_trusted_terminator`]): any other client, authenticated or not, is
///   the peer itself, and its header is its own words.
/// - Only a lone XFCC entry, parsed strictly ([`parse_xfcc_single_entry`]).
/// - The identity AND the NF types come from the `Cert=` PEM alone, so they
///   belong to one certificate. `URI=` is ignored: pairing a victim's `URI=`
///   with any public AMF certificate used to yield (victim, [AMF]).
/// - When `Hash=` is present it must be the SHA-256 of that certificate's DER,
///   as Envoy computes it.
///
/// Chain verification is the terminator's job: it verified the client before
/// forwarding (documented in nrf.md). A certificate with no `urn:uuid:` URI
/// SAN names no NF instance and is not believed.
fn forwarded_client_cert(request: &SbiRequest, policy: &NrfPolicy) -> Option<ForwardedClientCert> {
    use base64::Engine;
    use sha2::Digest;
    if !from_trusted_terminator(request, policy) {
        return None;
    }
    let header = request.http.get_header(XFCC_HEADER)?;
    let entry = parse_xfcc_single_entry(header)?;
    let pem = nextgcore_sbi::uri_encode::decode_query_value(entry.get("cert")?);
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .ok()
        .filter(|d| !d.is_empty())?;
    if let Some(hash) = entry.get("hash") {
        let digest: String = sha2::Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !hash.trim().eq_ignore_ascii_case(&digest) {
            log::debug!("{XFCC_HEADER}: Hash= does not match the forwarded Cert=; not believed");
            return None;
        }
    }
    let nf_instance_id = nextgcore_sbi::peer_cert::nf_instance_id_from_der(&der)?;
    Some(ForwardedClientCert {
        nf_instance_id,
        nf_types: nextgcore_sbi::peer_cert::nf_types_from_der(&der),
    })
}

/// I2 (TS 33.501 §13.3.1/§13.4.1, TS 33.310, TS 29.510 §6.1.6.2): extract the
/// transport-authenticated client NF Instance ID from the request. A 3GPP NF
/// certificate carries the NF Instance ID as a URI SubjectAltName (commonly the
/// URN `urn:uuid:<nfInstanceId>`); a trusted TLS-terminating SBI ingress/SCP
/// conveys that verified SAN to the NRF in the XFCC header. Returns the bare NF
/// Instance ID, or None when no transport identity is present.
///
/// NOTE: this consumes an identity a TRUSTED terminator already verified at the
/// TLS layer; it does not itself validate the certificate chain. When the NRF
/// terminates TLS directly (no SCP), surfacing the rustls-verified peer
/// certificate's SAN into this header (or onto `SbiRequest`) is an additive
/// `nextgcore-sbi` server-glue extension outside this component's boundary.
///
/// Issue #64 gap 2: the header is read ONLY when the operator has declared that
/// a trusted terminator exists (`policy.trust_forwarded_client_cert`). It is an
/// ordinary request header, so without that declaration any client that can
/// reach the NRF could mint an identity by setting it — and the mTLS binding
/// built on top of it would confirm the forgery rather than catch it.
fn extract_transport_client_nf_instance_id(
    request: &SbiRequest,
    policy: &NrfPolicy,
) -> Option<String> {
    // Issue #186: a certificate THIS process verified outranks a header, and needs
    // no trust declaration -- rustls validated the chain during the handshake, so
    // there is no terminator to trust. This is the direct-mTLS path that used to
    // yield nothing, which is why require_client_cert_binding could only reject.
    // #1990 (R30): a configured terminator's connection carries the caller's
    // identity in its XFCC header, never in its own certificate.
    if from_trusted_terminator(request, policy) {
        return forwarded_client_cert(request, policy).map(|c| c.nf_instance_id);
    }
    if let Some(id) = request.peer_cert_nf_instance_id.as_deref() {
        let id = id.trim();
        if !id.is_empty() {
            return Some(id.to_string());
        }
    }
    // #1990 (R30): any other connection's header is the client's own words.
    if request.http.get_header(XFCC_HEADER).is_some() {
        log::debug!(
            "ignoring a {XFCC_HEADER} header: the connection is not a configured TLS \
             terminator's (nrf.sbi.oauth2.trust_forwarded_client_cert / trusted_xfcc_terminators)"
        );
    }
    None
}

/// #1611: who an Nnrf_NFManagement NF-instance request (NFRegister, NFUpdate,
/// NFDeregister) provably comes from, and the check that binds the request to it.
///
/// TS 33.501 §5.9.2.2 NOTE: "While registering and updating NF profile, the NRF
/// verifies that the values of parameters that are present both in the NF
/// profile and in the public key certificate of the NF instance match."
/// TS 33.310 §6.1.3c.3: the certificate carries the NF Instance ID as a
/// `urn:uuid:` URI-ID and the NF type in the RFC 9310 NFTypes extension. Before
/// this, any caller could register any nfInstanceId as any nfType, and every
/// consumer that trusts an NRF-cached NF type trusted a self-assertion.
///
/// Only identities that cannot be forged count: the URI SAN of a client
/// certificate this process verified, a forwarded certificate identity when the
/// operator declared a trusted terminator, and the `sub` of an NRF-issued token
/// whose signature this process verified. NF management additionally needs a
/// CERTIFICATE identity ([`Self::require_certificate`]): with none (a plaintext
/// connection, a TLS client without a certificate, a certificate without a URI
/// SAN) NFRegister / NFUpdate / NFDeregister are refused `400 INVALID_CLIENT`.
/// TS 33.501 §13.3.1.1 would let NF-NRF authentication be implicit (NDS/IP,
/// physical security); the operator decision on #1617 does not rely on that.
#[derive(Debug, Default, PartialEq, Eq)]
struct RegistrantIdentity {
    /// Each verified NF Instance ID of the caller, with where it came from.
    instance_ids: Vec<(&'static str, String)>,
    /// The NF types the caller's verified certificate names. Empty means the
    /// certificate asserts none (or there is no certificate), never "any".
    nf_types: Vec<String>,
    /// #1917: the certificate identity came only through a forwarded header, so
    /// no NF type of the caller is known (see [`Self::bind_nf_type`]).
    forwarded: bool,
}

impl RegistrantIdentity {
    fn of(request: &SbiRequest, policy: &NrfPolicy) -> Self {
        let direct = direct_certificate(request, policy);
        let mut instance_ids = Vec::new();
        if let Some(id) = extract_transport_client_nf_instance_id(request, policy) {
            let source = if direct {
                "client certificate"
            } else {
                "forwarded client certificate"
            };
            instance_ids.push((source, id));
        }
        if let Some(sub) = request
            .oauth2_subject
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            instance_ids.push(("access token subject", sub.to_string()));
        }
        // A forwarded identity came through a terminator: the certificate of the
        // connection is the terminator's, and its NF types describe it, not the
        // registrant.
        // #1979: the registrant's own NF types are those of the certificate the
        // trusted terminator forwarded in XFCC `Cert=`, if it forwarded one.
        let forwarded = !direct && instance_ids.iter().any(|(s, _)| s.starts_with("forwarded"));
        // #2000: on a terminator's connection the certificate is ALWAYS the
        // terminator's, so with no (believed) XFCC entry the caller has no
        // certificate NF type at all: (None, []), never (None, [the terminator's]).
        let nf_types = if from_trusted_terminator(request, policy) {
            forwarded_client_cert(request, policy)
                .map(|c| c.nf_types)
                .unwrap_or_default()
        } else {
            request.peer_cert_nf_types.clone()
        };
        Self {
            instance_ids,
            nf_types,
            forwarded,
        }
    }

    /// The verified certificate identity of the caller: the URN of a client
    /// certificate this process verified, or of one a declared trusted
    /// terminator forwarded. An access-token subject is not one: the operator
    /// decision on #1617 makes NF management need a certificate identity
    /// (TS 33.310 §6.1.3c.3, TS 33.501 §13.1.0). Since #1667 a first NFRegister
    /// can carry a token, but that token was itself granted on a proven identity,
    /// so the certificate stays the identity NF management is bound to.
    fn certificate_identity(&self) -> Option<&str> {
        self.instance_ids
            .iter()
            .find(|(source, _)| source.ends_with("client certificate"))
            .map(|(_, id)| id.as_str())
    }

    /// #1617: the enforcement point every NF-management operation passes first,
    /// before anything is read or stored. A caller with no verified certificate
    /// identity is counted and refused `400 INVALID_CLIENT` (TS 29.510
    /// Table 6.1.7.3-1); `enforce` is the policy, which is always on outside
    /// tests of the counter. `Some` is the refusal to send.
    fn require_certificate(
        &self,
        operation: &str,
        nf_instance_id: &str,
        enforce: bool,
    ) -> Option<SbiResponse> {
        if self.certificate_identity().is_some() {
            return None;
        }
        nextgcore_nrfd::metrics::observe_unverified_nf_management();
        log::debug!(
            "{operation} for NF instance {nf_instance_id}: the caller has no verified \
             certificate identity{}",
            if enforce { "; refused" } else { "" }
        );
        enforce.then(|| {
            invalid_client(&format!(
                "{operation}: the requester has no verified client certificate identity \
                 (urn:uuid URI SAN, TS 33.310 §6.1.3c.3)"
            ))
        })
    }

    /// The `{nfInstanceID}` the request targets must be every verified identity
    /// of the caller, compared as the registry keys them: a UUID
    /// case-insensitively (TS 29.510 §5.2.2.2.2), any other ID exactly, so a
    /// certificate for `nf-a` cannot manage a distinct `NF-A` entry (#1633).
    /// `Some` is the refusal to send.
    fn bind_instance(&self, operation: &str, nf_instance_id: &str) -> Option<SbiResponse> {
        let (source, id) = self
            .instance_ids
            .iter()
            .find(|(_, id)| !same_nf_instance_id(id, nf_instance_id.trim()))?;
        // debug, not warn: a peer can send these at will (#1620 review m7); the
        // refusal is counted by the NRF's per-operation outcome metrics.
        log::debug!(
            "{operation} for NF instance {nf_instance_id} refused: the caller's {source} \
             identifies NF instance {id}"
        );
        Some(invalid_client(&format!(
            "{operation}: nfInstanceId {nf_instance_id:?} does not match the requester's \
             {source} ({id:?})"
        )))
    }

    /// The profile's `nfType` must be one the verified certificate names (TS
    /// 33.310 §6.1.3c.3, RFC 9310; TS 33.501 §5.9.2.2 NOTE). When it names none,
    /// or the identity was forwarded, the type cannot be verified: `required`
    /// ([`registrant_nf_types_required`], the production profile, #1917) refuses
    /// it, otherwise it is accepted as asserted. `Some` is the refusal to send.
    fn bind_nf_type(
        &self,
        operation: &str,
        nf_instance_id: &str,
        nf_type: &str,
        required: bool,
    ) -> Option<SbiResponse> {
        if self.nf_types.is_empty() {
            if !required {
                return None;
            }
            nextgcore_nrfd::metrics::observe_unverified_nf_management();
            let why = if self.forwarded {
                "the client certificate a TLS terminator forwarded for it (XFCC Cert=) names \
                 no NF type (RFC 9310 NFTypes)"
            } else {
                "its client certificate names no NF type (RFC 9310 NFTypes)"
            };
            log::debug!("{operation} for NF instance {nf_instance_id} as {nf_type} refused: {why}");
            return Some(invalid_client(&format!(
                "{operation}: nfType {nf_type:?} cannot be verified: {why} (TS 33.310 §6.1.3c.3)"
            )));
        }
        if self
            .nf_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(nf_type))
        {
            return None;
        }
        log::debug!(
            "{operation} for NF instance {nf_instance_id} refused: nfType {nf_type} is not in \
             the caller's certificate NFTypes {:?}",
            self.nf_types
        );
        Some(invalid_client(&format!(
            "{operation}: nfType {nf_type:?} is not among the NF types of the requester's \
             client certificate ({:?})",
            self.nf_types
        )))
    }
}

/// #1917: [`NrfPolicy::require_registrant_nf_types`], which tests of the dev
/// behaviour turn off for their own task only.
fn registrant_nf_types_required(policy: &NrfPolicy) -> bool {
    #[cfg(test)]
    if let Ok(required) = registrant_nf_type_tests_1917::REQUIRED.try_with(|r| *r) {
        return required;
    }
    // #1979: the policy the caller decides under, not the process-global one.
    policy.require_registrant_nf_types
}

/// #1809: [`NrfPolicy::require_subscriber_identity`], which tests of the dev
/// behaviour turn off for their own task only.
fn subscriber_identity_required() -> bool {
    #[cfg(test)]
    if let Ok(required) = subscription_owner_tests_1809::REQUIRED.try_with(|r| *r) {
        return required;
    }
    nrf_policy().require_subscriber_identity
}

impl RegistrantIdentity {
    /// #1809: the identity a new subscription is bound to. One rule for create
    /// and manage: every verified identity of the caller (certificate, trusted
    /// forwarded certificate, token `sub`) must name the same NF instance, so
    /// the creator can always manage what it created. Callers whose identities
    /// disagree are refused `400 INVALID_CLIENT` (TS 29.510 Table 6.1.7.3-1), as
    /// `bind_instance` refuses them for NF management. A caller with no verified
    /// identity is refused the same way when `required` (the production
    /// profile, as #1617 refuses cert-less NF management), else `Ok(None)`.
    fn subscription_owner(&self, required: bool) -> Result<Option<String>, Box<SbiResponse>> {
        let Some((_, first)) = self.instance_ids.first() else {
            if required {
                nextgcore_nrfd::metrics::observe_unverified_nf_management();
                return Err(Box::new(invalid_client(
                    "NFStatusSubscribe: the requester has no verified identity (client \
                     certificate or NRF-issued access token), so the subscription could not be \
                     bound to it",
                )));
            }
            return Ok(None);
        };
        if let Some((source, other)) = self
            .instance_ids
            .iter()
            .find(|(_, id)| !same_nf_instance_id(id, first))
        {
            log::debug!(
                "NFStatusSubscribe refused: the caller's identities disagree ({first} vs \
                 {source} {other})"
            );
            return Err(Box::new(invalid_client(&format!(
                "NFStatusSubscribe: the requester's {source} ({other:?}) does not match its \
                 other verified identity ({first:?})"
            ))));
        }
        Ok(Some(first.clone()))
    }

    /// #1809: a subscription is updated (TS 29.510 §5.2.2.5.6) or removed
    /// (§5.2.2.6) only by the consumer that created it. When it was bound to an
    /// identity, the caller must prove one and every identity it proves must be
    /// that one (TS 33.501 §13.1: the NRF authorizes on the authenticated
    /// identity, not on a claim). `403`, because the request is well formed and
    /// the caller is simply not allowed to act on someone else's resource.
    /// `Some` is the refusal to send; nothing has been read or changed yet.
    ///
    /// An ownerless subscription binds nothing under `dev`. When `required`
    /// (production) it is refused instead: it can only be one restored from a
    /// state file written before #1809, and nobody can prove they created it.
    fn bind_subscription(
        &self,
        operation: &str,
        sub: &nextgcore_nrfd::SubscriptionData,
        required: bool,
    ) -> Option<SbiResponse> {
        let Some(owner) = sub.owner.as_deref() else {
            return required.then(|| {
                send_error(
                    403,
                    "Forbidden",
                    &format!(
                        "{operation}: subscription {} has no verified owner (it predates \
                         #1809), so no requester can be shown to have created it",
                        sub.id
                    ),
                    None,
                )
            });
        };
        let foreign = if self.instance_ids.is_empty() {
            Some("no verified identity".to_string())
        } else {
            self.instance_ids
                .iter()
                .find(|(_, id)| !same_nf_instance_id(id, owner))
                .map(|(source, id)| format!("{source} {id:?}"))
        }?;
        // debug, not warn: a peer can send these at will (#1620 review m7).
        log::debug!(
            "{operation} of subscription {} refused: the caller has {foreign}, the \
             subscription belongs to NF instance {owner}",
            sub.id
        );
        Some(send_error(
            403,
            "Forbidden",
            &format!(
                "{operation}: subscription {} was not created by the requester ({foreign})",
                sub.id
            ),
            None,
        ))
    }
}

/// TS 29.510 Table 6.1.7.3-1 `INVALID_CLIENT` (400): "some or all attributes of
/// the NF Service Consumer presented in the request message do not match the
/// requester information in, e.g. its public key certificate".
fn invalid_client(detail: &str) -> SbiResponse {
    send_bad_request(detail, Some("INVALID_CLIENT"))
}

/// I2: verify the transport-authenticated (mTLS) client NF Instance ID is bound
/// to the token request's `nfInstanceId`. A mismatch is `invalid_client`
/// (TS 33.501 §13.4.1: the authenticated consumer identity must equal the NF
/// Instance ID asserted in the request). Combined with [`verify_cca_binding`]
/// (which binds `cca.sub == nfInstanceId`), this transitively binds the mTLS
/// certificate identity to the CCA — closing the "no mTLS/CCA binding" gap.
fn verify_transport_binding(
    cert_nf_instance_id: &str,
    expected_nf_instance_id: &str,
) -> Result<(), (&'static str, String)> {
    if !same_nf_instance_id(cert_nf_instance_id, expected_nf_instance_id) {
        return Err((
            "invalid_client",
            format!(
                "mTLS client-certificate NF Instance ID {cert_nf_instance_id:?} does not match \
                 request nfInstanceId {expected_nf_instance_id:?}"
            ),
        ));
    }
    Ok(())
}

/// The result of authenticating a token requester (issue #64 gaps 1+2).
///
/// `identity` is `Some` only when UNFORGEABLE evidence proved the requester is
/// that NF Instance ID: a certificate identity from a trusted TLS terminator, or
/// a CCA whose ES256 signature verified against a key the NRF trusts for that
/// issuer. A CCA that was merely claim-checked does NOT count — its claims are
/// chosen by whoever sent it.
#[derive(Debug, Default, PartialEq, Eq)]
struct ClientAuthentication {
    /// The proven NF Instance ID, if any.
    identity: Option<String>,
    /// Whether the proof came from a transport (mTLS) certificate identity.
    via_transport: bool,
}

impl ClientAuthentication {
    fn is_authenticated(&self) -> bool {
        self.identity.is_some()
    }
}

/// Authenticate the requester of an access token (TS 33.501 §13.3.1, §13.3.8.3,
/// §13.4.1.1) and return the identity that was actually PROVEN.
///
/// Order matters, and every failure is fail-closed:
///
/// 1. A certificate identity is taken only from a trusted terminator (see
///    [`extract_transport_client_nf_instance_id`]) and, when present, MUST bind
///    to the request `nfInstanceId` — a mismatch is rejected regardless of the
///    policy flags, since a forged binding is never acceptable.
/// 2. A present CCA is always claim-checked ([`verify_cca_binding`]). Its
///    signature is then verified against the key [`resolve_cca_verifying_key`]
///    resolves — the key certified by its `x5c` chain when it carries one
///    (issue #393, with the §13.3.8.3 certificate binding enforced), else the
///    trusted key for that issuer. With no usable key the request is rejected
///    rather than downgraded.
/// 3. The CCA contributes an identity ONLY if its signature verified. If
///    `cca_verify_signature` is off, the assertion is still claim-checked (so a
///    contradictory one is refused) but it authenticates nothing — which is the
///    honest reading of "we did not check it".
fn authenticate_token_client(
    policy: &NrfPolicy,
    request: &SbiRequest,
    nf_instance_id: &str,
    cca: &str,
    now: u64,
) -> Result<ClientAuthentication, (&'static str, String)> {
    let mut auth = ClientAuthentication::default();

    if let Some(cert_id) = extract_transport_client_nf_instance_id(request, policy) {
        verify_transport_binding(&cert_id, nf_instance_id)?;
        // The registry's spelling (#1633): the token subject is then the same
        // whatever case the certificate and the request used.
        auth.identity = Some(canonical_nf_instance_id(&cert_id));
        auth.via_transport = true;
    }

    if !cca.is_empty() {
        verify_cca_binding(cca, nf_instance_id, now)?;
        if policy.cca_verify_signature {
            // Issue #393: resolve the verifying key, which is also where the
            // certificate-to-instance-ID binding of TS 33.501 §13.3.8.3's final
            // bullet is enforced when the CCA carries `x5c`. Fail-closed at every
            // branch — see `resolve_cca_verifying_key` for the full precedence,
            // including why an `x5c`-bearing CCA is never downgraded to the trust
            // store.
            let key = resolve_cca_verifying_key(policy, cca, nf_instance_id, now)?;
            verify_cca_signature(cca, &key)?;
            // Signature verified: the assertion now proves the identity. When a
            // certificate identity was also present both bind to the same
            // nfInstanceId, so this does not overwrite it with anything different.
            auth.identity
                .get_or_insert_with(|| canonical_nf_instance_id(nf_instance_id));
        }
    }

    Ok(auth)
}

/// I2: decide whether the token request satisfies the configured client-
/// authentication policy, given the outcome of [`authenticate_token_client`].
///
/// - `require_client_auth` (nrfd-05 + I2, DEFAULT ON): an identity must have
///   been proven — by a signature-verified CCA or a certificate identity from a
///   trusted terminator. A request that proved neither is rejected.
/// - `require_client_cert_binding` (I2, default off): the proof must
///   specifically be a transport (mTLS) certificate identity.
fn enforce_client_authentication(
    policy: &NrfPolicy,
    has_cca: bool,
    has_transport_identity: bool,
) -> Result<(), (&'static str, String)> {
    if policy.require_client_cert_binding && !has_transport_identity {
        return Err((
            "invalid_client",
            "mTLS client-certificate authentication required \
             (nrf.sbi.oauth2.require_client_cert_binding)"
                .to_string(),
        ));
    }
    if policy.require_client_auth && !has_cca && !has_transport_identity {
        return Err((
            "invalid_client",
            "client authentication required (TS 33.501 §13.3.1): present a Client \
             Credentials Assertion signed with a key this NRF trusts for your \
             nfInstanceId, or an mTLS client certificate. A self-asserted nfInstanceId \
             is not sufficient"
                .to_string(),
        ));
    }
    Ok(())
}

/// #1964 (the #1828 residual): a type-targeted token carrying a resource-level
/// scope was granted because EVERY registered producer of the type allowed that
/// scope (#1828). With `aud` the bare NF type, a producer that registered later,
/// or one that would have refused the scope, accepted it too: a token minted
/// while only a rogue AUSF was registered carried scopes the legitimate AUSF then
/// honoured. Such a token's `aud` is therefore the NF instance IDs the scope was
/// evaluated over (TS 29.510 Table 6.3.5.2.4-1: the producer's NF instance ID(s)
/// "if the exact NF instance(s)" is known). A token with only service-level
/// scopes keeps the NF-type audience, so a producer that scales out still
/// accepts it; an instance-targeted token is already pinned.
fn pin_audience_to_acceptors(
    claims: &mut serde_json::Value,
    target_instance: Option<&NfProfile>,
    acceptors: &[NfProfile],
    granted: &[String],
) {
    if target_instance.is_some() || !granted.iter().any(|s| s.contains(':')) {
        return;
    }
    let ids: Vec<&str> = acceptors
        .iter()
        .map(|p| p.nf_instance_id.as_str())
        .collect();
    claims["aud"] = serde_json::json!(ids);
}

/// nrfd-07: build the AccessTokenClaims (TS 29.510 §6.3.5.2.4). When the grant
/// resolved a specific producer instance, `aud` becomes that instance-ID array
/// and the optional producer claims (`producerPlmnId`, `producerSnssaiList`,
/// `producerNfSetId`) are populated from its profile; otherwise `aud` is the
/// bare target NF type string. `consumerPlmnId` is taken from the consumer
/// profile when present.
#[allow(clippy::too_many_arguments)]
fn build_access_token_claims(
    iss: &str,
    sub: &str,
    target_nf_type: &str,
    target_instance: Option<&NfProfile>,
    consumer: &NfProfile,
    scope: &str,
    iat: u64,
    exp: u64,
) -> serde_json::Value {
    let aud = match target_instance {
        Some(p) => serde_json::json!([p.nf_instance_id]),
        None => serde_json::Value::String(target_nf_type.to_string()),
    };
    let mut claims = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "scope": scope,
        "exp": exp,
        "iat": iat,
    });
    let obj = claims.as_object_mut().expect("claims is an object");

    if let Some(plmn) = consumer.plmns().into_iter().next() {
        obj.insert("consumerPlmnId".to_string(), plmn);
    }
    if let Some(p) = target_instance {
        if let Some(plmn) = p.plmns().into_iter().next() {
            obj.insert("producerPlmnId".to_string(), plmn);
        }
        let snssais = p.snssais();
        if !snssais.is_empty() {
            obj.insert(
                "producerSnssaiList".to_string(),
                serde_json::Value::Array(snssais),
            );
        }
        // Issue #64 gap 5: both producer claims read the WRONG NFProfile member.
        //
        // `producerNsiList` is an array of NSI-IDs
        // (TS29510_Nnrf_AccessToken.yaml:400-404) whose source is
        // `NFProfile.nsiList` (TS29510_Nnrf_NFManagement.yaml:1498-1502). It was
        // filled from `nfSetIdList`, i.e. NF SET IDs, so any consumer or producer
        // keying slice scoping on this claim received NF Set IDs and mis-scoped.
        //
        // `producerNfSetId` is a SINGLE `NfSetId` (yaml:405-406) and was read from
        // a `nfSetId` attribute that `NFProfile` does not define at all -- only
        // `nfSetIdList` exists (yaml:1743-1747) -- so in production the claim was
        // NEVER populated and anything gating on it silently saw nothing.
        if let Some(nsi_list) = p
            .attributes
            .get("nsiList")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty())
        {
            obj.insert(
                "producerNsiList".to_string(),
                serde_json::Value::Array(nsi_list.clone()),
            );
        }
        // The claim is singular where the profile member is a list, so the first
        // entry is the only representable one. A producer belonging to several NF
        // Sets cannot be fully expressed in this claim -- that is a shape
        // limitation of TS 29.510 §6.3.5.2.4, not a choice made here.
        if let Some(set_id) = p
            .attributes
            .get("nfSetIdList")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .filter(|v| v.is_string())
        {
            obj.insert("producerNfSetId".to_string(), set_id.clone());
        }
    }
    claims
}

/// nrfd-04/-05/-09: parsed Nnrf_AccessToken request (TS 29.510
/// Table 6.3.5.2.2-1). `nfType`/`targetNfType` are Conditional; the conditional
/// `targetNfInstanceId` is an alternative target selector and the optional
/// `requesterPlmnList`/`requesterSnssaiList` and `cca` are surfaced for the
/// authorization and client-authentication decisions.
#[derive(Debug, Default)]
struct TokenRequestParams {
    grant_type: String,
    nf_instance_id: String,
    nf_type: String,
    target_nf_type: String,
    target_nf_instance_id: String,
    scope: String,
    requester_plmns: Vec<serde_json::Value>,
    requester_snssais: Vec<serde_json::Value>,
    cca: String,
}

/// Parses an Nnrf_AccessToken request body from JSON or, failing that,
/// `application/x-www-form-urlencoded`. nrfd-09: every form key AND value is
/// percent-decoded (and `+` treated as space) so an encoded `nfInstanceId`
/// (e.g. a URN with `%3A`) round-trips correctly. Array-valued form fields
/// carry JSON in the value.
fn parse_token_request(body: &str) -> TokenRequestParams {
    let json_array = |v: Option<&serde_json::Value>| -> Vec<serde_json::Value> {
        v.and_then(|v| v.as_array()).cloned().unwrap_or_default()
    };
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
        let s = |k: &str| {
            parsed
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        TokenRequestParams {
            grant_type: s("grant_type"),
            nf_instance_id: s("nfInstanceId"),
            nf_type: s("nfType"),
            target_nf_type: s("targetNfType"),
            target_nf_instance_id: s("targetNfInstanceId"),
            scope: s("scope"),
            requester_plmns: json_array(parsed.get("requesterPlmnList")),
            requester_snssais: json_array(parsed.get("requesterSnssaiList")),
            cca: s("cca"),
        }
    } else {
        let mut p = TokenRequestParams::default();
        // Array values are JSON; decode then parse.
        let parse_json_array = |raw: &str| -> Vec<serde_json::Value> {
            serde_json::from_str::<serde_json::Value>(raw)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
        };
        for pair in body.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                // nrfd-09: percent-decode key AND value (+ => space). #65: this
                // is the FORM decoder, not the query one -- `application/x-www-
                // form-urlencoded` defines `+` as a space, and nextgcore-sbi's
                // `encode_form_value` emits it that way when minting this body.
                let key = nextgcore_sbi::uri_encode::decode_form_value(key);
                let value = nextgcore_sbi::uri_encode::decode_form_value(value);
                match key.as_str() {
                    "grant_type" => p.grant_type = value,
                    "nfInstanceId" => p.nf_instance_id = value,
                    "nfType" => p.nf_type = value,
                    "targetNfType" => p.target_nf_type = value,
                    "targetNfInstanceId" => p.target_nf_instance_id = value,
                    "scope" => p.scope = value,
                    "requesterPlmnList" => p.requester_plmns = parse_json_array(&value),
                    "requesterSnssaiList" => p.requester_snssais = parse_json_array(&value),
                    "cca" => p.cca = value,
                    _ => {}
                }
            }
        }
        p
    }
}

async fn handle_access_token_request(request: &SbiRequest) -> SbiResponse {
    handle_access_token_request_with_policy(request, nrf_policy()).await
}

/// The token endpoint, against an explicit policy.
///
/// Split out from [`handle_access_token_request`] so a test can state the posture
/// it is exercising instead of inheriting the process-global [`nrf_policy`]: that
/// is a `OnceLock`, so a single test process can otherwise only ever see one
/// policy, and the security-relevant cases here (authenticated vs not, trusted
/// terminator vs not) each need a different one.
/// #1667: the consumer a token for THIS NRF's own APIs is authorized for, when it
/// is not (yet) in the registry.
///
/// TS 29.510 §6.1.8 (`29510-k00.txt:18897-18902`) and §6.2.8 (`:25345-25349`):
/// when OAuth2 is used on Nnrf_NFManagement or Nnrf_NFDiscovery, the consumer
/// "prior to consuming services offered by the" API "shall obtain a token". So
/// the token for its first NFRegister is requested before it is registered, and
/// refusing every unregistered consumer would make that impossible (TS 33.501
/// §13.3.1.3, `33501-k20.txt:14183`, makes the token optional there, not
/// forbidden). Without a profile, the grant rests on what was PROVEN instead:
///
/// - an identity, from a verified client certificate or a signature-verified
///   CCA (never a self-asserted `nfInstanceId`);
/// - the target is this NRF: `targetNfType` NRF, or this NRF's instance ID;
/// - every scope is an Nnrf_NFManagement or Nnrf_NFDiscovery one (Tables
///   6.1.8-1, 6.2.8-1): `nnrf-nfm`, `nnrf-disc`, or a `nnrf-nfm:` / `nnrf-disc:`
///   resource scope;
/// - when the caller's verified certificate names NF types (RFC 9310), the
///   asserted `nfType` is one of them. Where the NRF requires verified NF types
///   ([`registrant_nf_types_required`], #1917/#1926), a certificate naming none,
///   a forwarded identity and a CCA get no token at all (#1952). Elsewhere (a
///   dev NRF without TLS) they leave `nfType` asserted, as the registration that
///   follows does.
///
/// `Err` is the reason appended to the `invalid_client` description.
fn unregistered_nrf_api_consumer(
    request: &SbiRequest,
    policy: &NrfPolicy,
    authentication: &ClientAuthentication,
    nf_type: &str,
    target_nf_type: &str,
    target_nf_instance_id: &str,
    scope: &str,
) -> Result<NfProfile, String> {
    let Some(identity) = authentication.identity.as_deref() else {
        return Err(String::new());
    };
    let to_this_nrf = if target_nf_instance_id.is_empty() {
        target_nf_type.eq_ignore_ascii_case("NRF")
    } else {
        nextgcore_nrfd::nnrf_handler::same_nf_instance_id(target_nf_instance_id, nrf_instance_id())
            && (target_nf_type.is_empty() || target_nf_type.eq_ignore_ascii_case("NRF"))
    };
    if !to_this_nrf {
        return Err(String::new());
    }
    let nrf_api_scope = |s: &str| {
        ["nnrf-nfm", "nnrf-disc"]
            .iter()
            .any(|api| s == *api || s.strip_prefix(api).is_some_and(|r| r.starts_with(':')))
    };
    if !scope.split_whitespace().all(nrf_api_scope) {
        return Err(String::new());
    }
    // A forwarded identity's connection certificate is the terminator's, so its
    // NF types are not the caller's (as in `RegistrantIdentity::of`).
    let direct = direct_certificate(request, policy);
    let cert_types = &request.peer_cert_nf_types;
    if authentication.via_transport
        && direct
        && !cert_types.is_empty()
        && !cert_types.iter().any(|t| t.eq_ignore_ascii_case(nf_type))
    {
        return Err(format!(
            ", and nfType {nf_type:?} is not among the NF types of its client certificate \
             ({cert_types:?})"
        ));
    }
    // #1952: where NF management needs the certificate's NF type (#1917, #1926),
    // so does this bootstrap grant: an asserted nfType is not put in a token the
    // NRF would then trust. Only a client certificate THIS NRF verified, naming
    // the type in its NFTypes, proves it; a certificate naming none, a forwarded
    // identity and a CCA do not.
    if registrant_nf_types_required(policy) {
        // #1979: a trusted forwarded identity proves the NF types of the
        // certificate the terminator forwarded (XFCC `Cert=`).
        let forwarded_types = (!direct)
            .then(|| forwarded_client_cert(request, policy))
            .flatten()
            .map(|c| c.nf_types)
            .unwrap_or_default();
        let verified = authentication.via_transport
            && if direct {
                cert_types.iter().any(|t| t.eq_ignore_ascii_case(nf_type))
            } else {
                forwarded_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(nf_type))
            };
        if !verified {
            return Err(format!(
                ", and nfType {nf_type:?} cannot be verified: no client certificate this NRF \
                 verified names it in RFC 9310 NFTypes (TS 33.310 §6.1.3c.3)"
            ));
        }
    }
    NfProfile::from_json(&serde_json::json!({
        "nfInstanceId": identity,
        "nfType": nf_type,
        "nfStatus": "REGISTERED",
    }))
    .map_err(|missing| format!(" (profile for the token: {missing:?})"))
}

async fn handle_access_token_request_with_policy(
    request: &SbiRequest,
    policy: &NrfPolicy,
) -> SbiResponse {
    log::info!("OAuth2 Access Token Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // nrfd-04/-09: parse JSON or percent-decoded form, including the
    // conditional targetNfInstanceId and optional requester PLMN/S-NSSAI lists.
    let req = parse_token_request(body);
    let nf_instance_id = req.nf_instance_id;
    let nf_type = req.nf_type;
    let mut target_nf_type = req.target_nf_type;
    let mut target_nf_instance_id = req.target_nf_instance_id;

    // RFC 6749 §5.2 error responses, carried as TS 29.510 AccessTokenErr.
    if req.grant_type != "client_credentials" {
        return token_error(
            "unsupported_grant_type",
            &format!(
                "Unsupported grant_type: {:?} (expected client_credentials)",
                req.grant_type
            ),
        );
    }

    if nf_instance_id.is_empty() {
        return token_error("invalid_request", "Missing nfInstanceId");
    }
    if nf_type.is_empty() {
        return token_error("invalid_request", "Missing nfType");
    }
    // nrfd-04: targetNfType is Conditional — accept targetNfInstanceId as an
    // alternative target selector; require at least one of the two.
    if target_nf_type.is_empty() && target_nf_instance_id.is_empty() {
        return token_error(
            "invalid_request",
            "Missing target selector (one of targetNfType or targetNfInstanceId required)",
        );
    }
    if req.scope.is_empty() {
        return token_error("invalid_scope", "Missing scope");
    }
    // #1753: never mint a token whose audience is an NF type no NF of the current
    // release can be. NFType is extensible (TS 29.501 §5.3.12: the free-string
    // alternative exists "only ... for forward compatibility"), so NFRegister keeps
    // a profile with an unknown nfType; but `aud` = targetNfType means "any
    // producer of this type", and for a type outside the enum that class is
    // whatever a registrant chose to call itself. A pinned instance
    // (targetNfInstanceId alone) is still served: its `aud` names that instance.
    if !target_nf_type.is_empty() && !is_ts29510_nf_type(&target_nf_type) {
        return token_error(
            "invalid_request",
            &format!(
                "targetNfType {target_nf_type:?} is not a TS 29.510 NFType, so no access token \
                 is issued for it"
            ),
        );
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_secs();

    // Issue #64 gaps 1+2 (TS 33.501 §13.3.1/§13.3.8.3/§13.4.1.1): establish WHO
    // is asking before minting anything for them. Returns only the identity that
    // unforgeable evidence proved — a certificate identity from a trusted TLS
    // terminator, or a CCA whose ES256 signature verified against a key this NRF
    // trusts for that issuer. Every binding or signature failure is fail-closed.
    let authentication =
        match authenticate_token_client(policy, request, &nf_instance_id, &req.cca, now) {
            Ok(auth) => auth,
            Err((code, desc)) => return token_error(code, &desc),
        };

    // nrfd-05 + I2: enforce the client-authentication policy against what was
    // actually proven. `require_client_auth` defaults ON, so an unauthenticated
    // request is rejected unless an operator explicitly opted out.
    if let Err((code, desc)) = enforce_client_authentication(
        policy,
        authentication.is_authenticated(),
        authentication.via_transport,
    ) {
        return token_error(code, &desc);
    }

    // Verify that the requesting NF is registered: an unknown client is an
    // invalid_client error (RFC 6749 §5.2; TS 29.510 carries it in a 400
    // AccessTokenErr rather than a bare 401). The one exception is a token for
    // this NRF's own APIs (#1667): see `unregistered_nrf_api_consumer`.
    let manager = nf_manager();
    let consumer = match manager.get(&nf_instance_id) {
        Some(consumer) => consumer,
        None => match unregistered_nrf_api_consumer(
            request,
            policy,
            &authentication,
            &nf_type,
            &target_nf_type,
            &target_nf_instance_id,
            &req.scope,
        ) {
            Ok(consumer) => {
                // #1750: this grant was authorized on "the target is THIS NRF", so
                // the exact producer instance is known, and TS 29.510 Table
                // 6.3.5.2.4-1 then makes `aud` "the NF service producer's NF
                // instance ID(s) (if the exact NF instance(s) ... is known)", not
                // the NF type: pin the target to this NRF, so the token names
                // this NRF's instance and no other NRF trusting this issuer
                // (another NRF of a set, a peer in the PLMN) accepts it.
                target_nf_instance_id = nrf_instance_id().to_string();
                consumer
            }
            Err(why) => {
                return token_error(
                    "invalid_client",
                    &format!("NF instance {nf_instance_id} is not registered with this NRF{why}"),
                );
            }
        },
    };

    // nrfd-04/-07: resolve the producer set. With targetNfInstanceId, pin the
    // single producer instance and derive its nfType (filling an absent
    // targetNfType); otherwise take all registered producers of the type.
    //
    // Issue #1391: only an OPERATIVE producer authorizes a scope. TS 29.510
    // Table 6.1.6.3.7-1 (29510-k00 l.17705-17760): REGISTERED, UNDISCOVERABLE
    // and CANARY_RELEASE are all "registered in NRF" and "operative" (an
    // UNDISCOVERABLE NF still serves its existing resources, so a consumer
    // already bound to it must be able to refresh its token); SUSPENDED is "not
    // operative" (e.g. heartbeat failure), so it cannot vouch for a token. An
    // unknown status is treated as not operative.
    // #1828: every registered producer, whatever its status: the set a
    // type-targeted token's resource scopes are checked against.
    let registered: Vec<NfProfile> = manager.list();
    let mut all: Vec<NfProfile> = registered
        .clone()
        .into_iter()
        .filter(|p| {
            ["REGISTERED", "UNDISCOVERABLE", "CANARY_RELEASE"]
                .iter()
                .any(|s| p.nf_status.eq_ignore_ascii_case(s))
        })
        .collect();
    // #1667: this NRF produces its own APIs whether or not its registry holds its
    // own entry (it does only when `registers_itself`). Without this, an NF that
    // attaches tokens to its NRF calls (its `sbi.oauth2.require` on) would be
    // refused `invalid_scope` for nnrf-nfm by an NRF that does not gate its own
    // APIs, and, the client failing closed (#63), could not register at all.
    if !all.iter().any(|p| {
        nextgcore_nrfd::nnrf_handler::same_nf_instance_id(&p.nf_instance_id, nrf_instance_id())
    }) {
        if let Ok(own) = NfProfile::from_json(&nrf_self_profile()) {
            all.push(own);
        }
    }
    let target_instance: Option<NfProfile> = if !target_nf_instance_id.is_empty() {
        let inst = all
            .iter()
            .find(|p| {
                nextgcore_nrfd::nnrf_handler::same_nf_instance_id(
                    &p.nf_instance_id,
                    &target_nf_instance_id,
                )
            })
            .cloned();
        match inst {
            Some(ref p) => {
                if target_nf_type.is_empty() {
                    target_nf_type = p.nf_type.clone();
                } else if !p.nf_type.eq_ignore_ascii_case(&target_nf_type) {
                    // Issue #1391: the two target selectors contradict each
                    // other. Minting a token whose audience is targetNfType on
                    // the strength of an instance of a different type would let
                    // one producer's allowedNfTypes authorize another type.
                    return token_error(
                        "invalid_request",
                        &format!(
                            "targetNfInstanceId {target_nf_instance_id} is a {} producer, not \
                             the requested targetNfType {target_nf_type}",
                            p.nf_type
                        ),
                    );
                }
            }
            // Issue #1391: a pinned producer that is not registered authorizes
            // nothing. Without this, an absent targetNfType made the type filter
            // below match no producer and reach the same empty-set decision by a
            // second route; answer it here, explicitly, so neither route depends
            // on the other.
            None => {
                return token_error(
                    "invalid_scope",
                    &format!(
                        "targetNfInstanceId {target_nf_instance_id} is not an operative NF \
                         instance registered with this NRF, so it authorizes no service"
                    ),
                );
            }
        }
        inst
    } else {
        None
    };
    let producers: Vec<NfProfile> = match target_instance {
        Some(ref p) => vec![p.clone()],
        None => all
            .into_iter()
            .filter(|p| p.nf_type.eq_ignore_ascii_case(&target_nf_type))
            .collect(),
    };

    // Authorization decision (TS 33.501 §13.4.1.1.2 step 2; TS 29.510
    // §5.4.2.2.2): the NRF must verify the consumer profile and that the
    // requested scope is permitted by the target producer set BEFORE minting a
    // token. Without this, the endpoint is an OAuth2 authorization bypass.
    let requested_scopes: Vec<String> = req.scope.split_whitespace().map(String::from).collect();
    let acceptors = token_acceptors(&registered, &target_nf_type, target_instance.as_ref());
    let granted_scopes = match authorize_access_token_for(
        &consumer,
        &nf_type,
        &target_nf_type,
        &requested_scopes,
        &producers,
        &acceptors,
        &req.requester_plmns,
        &req.requester_snssais,
    ) {
        Ok(granted) => granted,
        Err((code, desc)) => return token_error(code, &desc),
    };
    let scope = granted_scopes.join(" ");

    // Issue a JWT access token signed with ES256 (ECDSA P-256).
    // Issue #64 gap 4: operator-configurable via --token-expires-in.
    let expires_in = nrf_token_expires_in();

    let header_json = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{NRF_KID}"}}"#);
    // Issue #64 gap 2 (TS 33.501 §13.4.1.1): the token subject is the
    // AUTHENTICATED client identity, not the value the body asserted. Both
    // binding checks force the two equal whenever an identity was proven, so this
    // changes nothing on the wire today — it means a later edit that loosens a
    // binding cannot silently re-introduce a self-asserted subject, because the
    // subject no longer comes from the request at all.
    // #1633 review: with no proven identity (require_client_auth off) the
    // asserted ID stands in, in the registry's spelling like a proven one.
    let unproven = canonical_nf_instance_id(&nf_instance_id);
    let subject = authentication.identity.as_deref().unwrap_or(&unproven);
    // nrfd-07: `iss` is the NRF NF Instance ID (TS 29.510 §6.3.5.2.4); when a
    // producer instance was pinned, `aud` is its instance-ID array and the
    // optional producer/consumer claims are populated.
    let mut claims_json = build_access_token_claims(
        nrf_instance_id(),
        subject,
        &target_nf_type,
        target_instance.as_ref(),
        &consumer,
        &scope,
        now,
        now + expires_in,
    );
    pin_audience_to_acceptors(
        &mut claims_json,
        target_instance.as_ref(),
        &acceptors,
        &granted_scopes,
    );
    let claims_str = claims_json.to_string();

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(claims_str.as_bytes());

    // Sign header.payload with ES256 (ECDSA P-256). The JOSE signature is the
    // raw r||s (64 bytes), base64url-encoded.
    use p256::ecdsa::{signature::Signer, Signature};
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature: Signature = nrf_signing_key().sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let access_token = format!("{header_b64}.{payload_b64}.{signature_b64}");

    log::info!(
        "Issued access token for {nf_instance_id} ({nf_type}) -> {target_nf_type} scope={scope}"
    );

    let response = AccessTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: Some(expires_in),
        scope: Some(scope),
    };

    // Cache-Control: no-store and Pragma: no-cache are mandatory on the
    // token response (TS29510_Nnrf_AccessToken.yaml response headers).
    SbiResponse::with_status(200)
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    // RUST_LOG if set, else --log-level: the same for every NF (#691).
    let mut builder = nextgcore_core::log::nf_log_builder(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ));

    if args.no_color {
        builder.write_style(env_logger::WriteStyle::Never);
    }

    builder.init();

    Ok(())
}

/// Set up signal handlers for graceful shutdown
fn setup_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<()> {
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    Ok(())
}

/// Async main event loop with timer integration
async fn run_event_loop_async(_nrf_sm: &mut NrfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let mut interval = tokio::time::interval(Duration::from_millis(100));

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Wait for next tick
        interval.tick().await;

        // Process timer expirations
        let expired_events = timer_manager().get_expired_events();
        for event in expired_events {
            log::debug!("Processing timer event: {event:?}");

            match event.timer_id {
                Some(nextgcore_nrfd::NrfTimerId::SubscriptionValidity) => {
                    // Subscription has expired -- remove it
                    if let Some(ref subscription_id) = event.subscription_id {
                        log::info!("Subscription {subscription_id} validity expired, removing");
                        let manager = nf_manager();
                        manager.remove_subscription(subscription_id);
                    }
                }
                Some(nextgcore_nrfd::NrfTimerId::NfInstanceNoHeartbeat) => {
                    // NF instance missed heartbeat (TS 29.510)
                    if let Some(ref nf_instance_id) = event.nf_instance_id {
                        let manager = nf_manager();

                        if manager.is_suspended(nf_instance_id) {
                            // Already SUSPENDED - now auto-deregister
                            log::warn!(
                                "NF instance {nf_instance_id} still no heartbeat after suspension, deregistering"
                            );

                            let profile = manager.get(nf_instance_id);
                            manager.deregister(nf_instance_id).ok();
                            disarm_heartbeat_timer(nf_instance_id);

                            // Send NF_DEREGISTERED notification
                            if let Some(profile) = profile {
                                let server_uri = nrf_self_uri().to_string();
                                tokio::spawn(async move {
                                    if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                                        NotificationEventType::NfDeregistered,
                                        &profile,
                                        &server_uri,
                                    )
                                    .await
                                    {
                                        log::error!(
                                            "Failed to send NF_DEREGISTERED notifications: {e}"
                                        );
                                    }
                                });
                            }
                        } else {
                            // First missed heartbeat - mark as SUSPENDED
                            log::warn!(
                                "NF instance {nf_instance_id} missed heartbeat, marking SUSPENDED"
                            );
                            manager.suspend(nf_instance_id);

                            // TS 29.510 Section 5.2.2.6: the REGISTERED ->
                            // SUSPENDED transition is a profile change and must
                            // be notified. Without this, subscribers only learn
                            // of the failure when the NF is fully deregistered a
                            // grace period later, and keep selecting a producer
                            // the NRF already knows is not answering.
                            if let Some(suspended) = manager.get(nf_instance_id) {
                                let server_uri = nrf_self_uri().to_string();
                                tokio::spawn(async move {
                                    if let Err(e) = nrf_nnrf_nfm_send_nf_status_notify_all_async(
                                        NotificationEventType::NfProfileChanged,
                                        &suspended,
                                        &server_uri,
                                    )
                                    .await
                                    {
                                        log::error!(
                                            "Failed to send NF_PROFILE_CHANGED on suspend: {e}"
                                        );
                                    }
                                });
                            }

                            // Start a grace period timer for auto-deregistration
                            // Use same interval as heartbeat for the grace period
                            if let Some(profile) = manager.get(nf_instance_id) {
                                let grace_secs = profile.heartbeat_timer.unwrap_or(10) as u64;
                                arm_heartbeat_timer(
                                    nf_instance_id,
                                    std::time::Duration::from_secs(grace_secs),
                                );
                                log::info!(
                                    "NF instance {nf_instance_id} grace period: {grace_secs}s before deregistration"
                                );
                            }
                        }
                    }
                }
                Some(nextgcore_nrfd::NrfTimerId::SbiClientWait) => {
                    log::debug!("SBI client wait timer expired");
                }
                None => {
                    log::warn!("Timer event with no timer ID");
                }
            }
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    log::debug!("Exiting async main event loop");
    Ok(())
}

/// #1990 (R30), tests: the URI SAN of the TLS terminator test requests come
/// through, listed in a trusting test policy's `trusted_xfcc_terminators`.
#[cfg(test)]
const TEST_TERMINATOR: &str = "spiffe://cluster.local/ns/5gc/sa/envoy";

/// #1990 (R30), tests: `req` as it would arrive over plaintext, without the
/// test terminator's connection [`from_test_terminator`] gave it: for checking
/// that a header is NOT evidence when no terminator is involved.
#[cfg(test)]
fn plaintext(mut req: SbiRequest) -> SbiRequest {
    if req.peer_cert_nf_instance_id.as_deref() == Some(TEST_TERMINATOR) {
        req.peer_cert_nf_instance_id = None;
        req.peer_cert_present = false;
    }
    req
}

/// #1990 (R30), tests: mark `req` as arriving over the test terminator's mTLS
/// connection, unless it already carries a peer certificate of its own.
#[cfg(test)]
fn from_test_terminator(req: &mut SbiRequest) {
    if req.peer_cert_nf_instance_id.is_none() {
        req.peer_cert_nf_instance_id = Some(TEST_TERMINATOR.to_string());
        req.peer_cert_present = true;
    }
}

/// #1990, tests: an Envoy-style XFCC entry for a client certificate whose URI SAN
/// is `urn:uuid:<id>` (or `id` verbatim when it already has a scheme) and whose
/// RFC 9310 NFTypes are `nf_types`: `Hash=` (SHA-256 of the DER), the URL-encoded
/// PEM in `Cert=`, and a quoted `Subject=`. Self-signed: chain verification is the
/// terminator's job.
#[cfg(test)]
fn test_xfcc(id: &str, nf_types: &[&str]) -> String {
    use sha2::Digest;
    let uri = if id.contains(':') {
        id.to_string()
    } else {
        format!("urn:uuid:{id}")
    };
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
    params.subject_alt_names.push(rcgen::SanType::URI(
        uri.as_str().try_into().expect("ia5 uri"),
    ));
    if !nf_types.is_empty() {
        let mut body = Vec::new();
        for t in nf_types {
            body.push(0x16);
            body.push(t.len() as u8);
            body.extend_from_slice(t.as_bytes());
        }
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 5, 5, 7, 1, 34],
                der,
            ));
    }
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let hash: String = sha2::Sha256::digest(cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "By=spiffe://nrf;Hash={hash};Cert=\"{}\";Subject=\"CN=test,O=Op\"",
        nextgcore_sbi::uri_encode::encode_query_value(&cert.pem())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy with the documented client-authentication opt-out applied, for
    /// tests whose subject is something OTHER than authentication (target
    /// resolution, scope, claim shapes). Issue #64's own criteria are exercised
    /// against the real default in the tests named for them.
    fn policy_without_client_auth() -> NrfPolicy {
        NrfPolicy {
            require_client_auth: false,
            ..NrfPolicy::default()
        }
    }

    /// #1570: `ml-analytics-info-list` reaches the filter through the real
    /// SearchNFInstances handler (TS 29.510 Table 6.2.3.2.3.1-1): an NWDAF whose
    /// `nwdafInfo.mlAnalyticsList` supports an item is returned, one with no
    /// list or a list for other events is not, and a malformed list is a 400.
    #[tokio::test]
    async fn discovery_filters_on_ml_analytics_info_list_1570() {
        let pid = std::process::id();
        let mtlf = format!("6b1d7e3c-1570-4000-8000-{pid:012x}");
        let anlf = format!("6b1d7e3c-1570-4000-8001-{pid:012x}");
        let other = format!("6b1d7e3c-1570-4000-8002-{pid:012x}");
        let profile = |id: &str, info: serde_json::Value| {
            nextgcore_nrfd::NfProfile::from_json(&serde_json::json!({
                "nfInstanceId": id,
                "nfType": "NWDAF",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["127.0.0.1"],
                "nwdafInfo": info,
            }))
            .expect("valid profile")
        };
        nf_manager()
            .register(profile(
                &mtlf,
                serde_json::json!({
                    "nwdafEvents": ["NF_LOAD"],
                    "mlAnalyticsList": [{ "mlAnalyticsIds": ["NF_LOAD"] }],
                }),
            ))
            .expect("register MTLF");
        nf_manager()
            .register(profile(
                &anlf,
                serde_json::json!({ "nwdafEvents": ["NF_LOAD"] }),
            ))
            .expect("register AnLF");
        nf_manager()
            .register(profile(
                &other,
                serde_json::json!({
                    "mlAnalyticsList": [{ "mlAnalyticsIds": ["UE_MOBILITY"] }],
                }),
            ))
            .expect("register other MTLF");

        let discover = |list: &str| {
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "NWDAF");
            req.http.set_param("requester-nf-type", "NWDAF");
            req.http.set_param("ml-analytics-info-list", list);
            req
        };
        let ids = |resp: SbiResponse| -> Vec<String> {
            assert_eq!(resp.status, 200);
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            body["nfInstances"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|p| p["nfInstanceId"].as_str().map(String::from))
                .collect()
        };

        let nf_load =
            ids(handle_nf_discover(&discover(r#"[{"mlAnalyticsIds":["NF_LOAD"]}]"#)).await);
        let ue_mob =
            ids(handle_nf_discover(&discover(r#"[{"mlAnalyticsIds":["UE_MOBILITY"]}]"#)).await);
        let either = ids(handle_nf_discover(&discover(
            r#"[{"mlAnalyticsIds":["SLICE_LOAD_LEVEL"]},{"mlAnalyticsIds":["NF_LOAD"]}]"#,
        ))
        .await);
        let bad = handle_nf_discover(&discover(r#"["NF_LOAD"]"#)).await;
        let not_json = handle_nf_discover(&discover("NF_LOAD")).await;
        for id in [&mtlf, &anlf, &other] {
            let _ = nf_manager().deregister(id);
        }

        assert!(
            nf_load.contains(&mtlf),
            "the NF_LOAD MTLF is returned: {nf_load:?}"
        );
        assert!(!nf_load.contains(&anlf), "no mlAnalyticsList, not returned");
        assert!(
            !nf_load.contains(&other),
            "a UE_MOBILITY-only list, not returned"
        );
        assert!(
            ue_mob.contains(&other) && !ue_mob.contains(&mtlf),
            "{ue_mob:?}"
        );
        assert!(
            either.contains(&mtlf),
            "one item supported is enough: {either:?}"
        );
        for resp in [bad, not_json] {
            assert_eq!(resp.status, 400);
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(problem["cause"], "INVALID_QUERY_PARAM");
        }
    }

    /// #1308: with no flag the SBI listener binds loopback, not every interface.
    #[test]
    fn sbi_listener_defaults_to_loopback_1308() {
        let args = Args::parse_from(["nextgcore-nrfd"]);
        let l = resolve_sbi_listen(args.sbi_addr.as_deref(), args.sbi_port, None);
        assert_eq!((l.host.as_str(), l.port), ("127.0.0.1", 7777));
    }

    /// #1313 review: now that a config that does not parse fails startup, every
    /// shipped nrf.yaml must parse.
    #[test]
    fn the_shipped_configs_parse() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        for rel in [
            "docker/rust/configs/5gc/nrf.yaml",
            "docker/rust/configs/5gc/nrf-oauth2.yaml",
        ] {
            let text = std::fs::read_to_string(root.join(rel)).unwrap();
            serde_yaml::from_str::<NrfYaml>(&text).unwrap_or_else(|e| panic!("{rel}: {e}"));
        }
        let cm: serde_yaml::Value = serde_yaml::from_str(
            &std::fs::read_to_string(root.join("k8s/manifests/configmap.yaml")).unwrap(),
        )
        .unwrap();
        let text = cm["data"]["nrf.yaml"]
            .as_str()
            .expect("the ConfigMap's nrf.yaml");
        serde_yaml::from_str::<NrfYaml>(text).expect("k8s nrf.yaml");
        // #1312 (#1317 review): and as the Helm chart renders it (CI installs helm
        // and sets NEXTGCORE_HELM_REQUIRED, so this is never skipped there).
        if let Some(text) = nextgcore_core::helm_render::helm_rendered_config(&root, "nrf.yaml") {
            serde_yaml::from_str::<NrfYaml>(&text).expect("Helm nrf.yaml");
        }
    }

    /// #1313 review: a config that does not parse fails startup; no file is no config.
    #[test]
    fn a_config_that_does_not_parse_fails_startup() {
        let dir = std::env::temp_dir().join(format!("nrfd-badcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("nrf.yaml");
        std::fs::write(&bad, "nrf:\n  sbi: [\n").unwrap();
        let err = load_config(bad.to_str().unwrap()).unwrap_err().to_string();
        assert!(err.contains("does not parse"), "{err}");
        assert!(load_config("/nonexistent/nrf.yaml").unwrap().is_none());
    }

    /// #1311: the YAML `nrf.sbi.server` is the listen address (and `advertise` the
    /// NRF's URI host) unless the command line names one, which wins.
    #[test]
    fn the_yaml_sbi_server_is_bound_unless_the_command_line_overrides_1311() {
        let yaml: NrfYaml = serde_yaml::from_str(
            "nrf:\n  sbi:\n    server:\n      - address: 10.0.0.10\n        advertise: nrf.example\n        port: 7788\n",
        )
        .unwrap();
        assert_eq!(
            resolve_sbi_listen(None, None, Some(&yaml)),
            SbiListen {
                host: "10.0.0.10".into(),
                port: 7788,
                advertise: "nrf.example".into(),
            }
        );
        let l = resolve_sbi_listen(Some("0.0.0.0"), Some(7777), Some(&yaml));
        assert_eq!((l.host.as_str(), l.port), ("0.0.0.0", 7777));
        let none: NrfYaml = serde_yaml::from_str("nrf:\n  sbi: {}\n").unwrap();
        assert_eq!(
            resolve_sbi_listen(None, None, Some(&none)).host,
            "127.0.0.1"
        );
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nrfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nrf.yaml");
        assert_eq!(args.log_level, None);
        assert_eq!(args.sbi_addr, None);
        assert_eq!(args.sbi_port, None);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nrfd",
            "-c",
            "/custom/nrf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/nrf.yaml");
        assert_eq!(args.log_level.as_deref(), Some("debug"));
        assert_eq!(args.sbi_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(args.sbi_port, Some(8080));
        assert_eq!(args.max_ue, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-nrfd",
            "--tls",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]);
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert.pem".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key.pem".to_string()));
    }

    #[test]
    fn test_jwks_public_key_verifies_signed_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::signature::{Signer, Verifier};
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::EncodedPoint;

        // Sign as the token endpoint does.
        let msg = b"header.payload";
        let sig: Signature = nrf_signing_key().sign(msg);

        // Reconstruct the public key purely from the published JWKS.
        let jwks = nrf_jwks_json();
        let key = &jwks["keys"][0];
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["kid"], NRF_KID);
        let x = URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap()).unwrap();
        let point = EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(&x),
            p256::FieldBytes::from_slice(&y),
            false,
        );
        let vk = VerifyingKey::from_encoded_point(&point).expect("valid JWKS key");

        // The JWKS key verifies the NRF signature — consumers can verify tokens.
        assert!(vk.verify(msg, &sig).is_ok());
        // A tampered signing input must fail verification.
        assert!(vk.verify(b"header.tampered", &sig).is_err());
    }

    /// #65: nrfd's local `percent_decode` is gone. What it did for a FORM body is
    /// now `decode_form_value`; what it did for a QUERY value is
    /// `decode_query_value`, which differs on `+` -- and that difference is the
    /// defect the split fixed, so both are pinned here from nrfd's side too.
    #[test]
    fn test_percent_decode() {
        use nextgcore_sbi::uri_encode::{decode_form_value, decode_query_value};
        assert_eq!(decode_query_value("plain"), "plain");
        assert_eq!(
            decode_query_value("%5B%7B%22sst%22%3A1%7D%5D"),
            r#"[{"sst":1}]"#
        );
        // Malformed escapes pass through unchanged.
        assert_eq!(decode_query_value("100%"), "100%");
        assert_eq!(decode_query_value("%zz"), "%zz");
        // The form body keeps the `+`-as-space rule the old copy applied
        // everywhere; a query value keeps the plus.
        assert_eq!(decode_form_value("a+b"), "a b");
        assert_eq!(decode_query_value("a+b"), "a+b");
    }

    #[test]
    fn test_token_error_shape() {
        // RFC 6749 §5.2 / TS 29.510 AccessTokenErr: 400 + {"error": ...},
        // Cache-Control: no-store, Pragma: no-cache, application/json.
        let resp = token_error("invalid_client", "nope");
        assert_eq!(resp.status, 400);
        assert_eq!(
            resp.http.get_header("Cache-Control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            resp.http.get_header("Pragma").map(String::as_str),
            Some("no-cache")
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["error"], "invalid_client");
    }

    // -----------------------------------------------------------------
    // nrfd-01: access-token authorization decision (TS 33.501
    // §13.4.1.1.2 step 2 / TS 29.510 §5.4.2.2.2). These exercise the pure
    // decision function in isolation (no global manager / no server), so
    // they are deterministic and parallel-safe.
    // -----------------------------------------------------------------

    /// A consumer NF profile of the given type.
    fn auth_consumer(nf_type: &str) -> NfProfile {
        NfProfile::from_json(&serde_json::json!({
            "nfInstanceId": "11111111-1111-1111-1111-111111111111",
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
        }))
        .expect("valid consumer profile")
    }

    /// A producer NF profile advertising `services`, with an optional
    /// profile-level `allowedNfTypes`.
    fn auth_producer(
        nf_type: &str,
        services: serde_json::Value,
        allowed: Option<serde_json::Value>,
    ) -> NfProfile {
        let mut doc = serde_json::json!({
            "nfInstanceId": format!("prod-{nf_type}"),
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "nfServices": services,
        });
        if let Some(a) = allowed {
            doc.as_object_mut()
                .unwrap()
                .insert("allowedNfTypes".into(), a);
        }
        NfProfile::from_json(&doc).expect("valid producer profile")
    }

    #[test]
    fn test_authorize_token_happy_path_permitted_scope() {
        // Valid registered consumer + a producer that offers the service and
        // permits the consumer type -> token (granted scope == requested).
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudm-sdm"}]),
            Some(serde_json::json!(["SMF", "AMF"])),
        );
        let granted = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect("permitted scope must be granted");
        assert_eq!(granted, vec!["nudm-sdm".to_string()]);
    }

    /// #1811: a UDR as udrd registers it -- nudr-dr open to UDM, PCF and NEF,
    /// with `allowedOperationsPerNfType` granting the TS 29.505
    /// AuthenticationSubscription scopes to the UDM alone.
    fn udr_with_resource_scopes() -> NfProfile {
        auth_producer(
            "UDR",
            serde_json::json!([{
                "serviceInstanceId": "udr-dr",
                "serviceName": "nudr-dr",
                "allowedNfTypes": ["UDM", "PCF", "NEF"],
                "allowedOperationsPerNfType": {
                    "UDM": ["nudr-dr", AUTH_SUBS_READ, AUTH_SUBS_MODIFY],
                    "PCF": ["nudr-dr"],
                    "NEF": ["nudr-dr"]
                }
            }]),
            Some(serde_json::json!(["UDM", "PCF", "NEF"])),
        )
    }

    const AUTH_SUBS_READ: &str = "nudr-dr:subscription-data:authentication-subscription:read";
    const AUTH_SUBS_MODIFY: &str = "nudr-dr:subscription-data:authentication-subscription:modify";

    /// #1918: the AUSF profile ausfd registers (`build_nf_profile`, pinned by
    /// ausfd's `the_profile_grants_the_deregister_scope_to_the_udm_only_1918`).
    /// The two must stay in step: this is the NRF half of that exchange.
    fn ausf_with_deregister_scope() -> NfProfile {
        auth_producer(
            "AUSF",
            serde_json::json!([{
                "serviceInstanceId": "ausf-auth",
                "serviceName": "nausf-auth",
                "allowedNfTypes": ["AMF", "UDM", "SCP"],
                "allowedOperationsPerNfType": {
                    "AMF": ["nausf-auth", nextgcore_sbi::resource_scope::NAUSF_AUTH_UE_AUTHENTICATIONS],
                    "UDM": ["nausf-auth", nextgcore_sbi::resource_scope::NAUSF_AUTH_UE_AUTHENTICATIONS],
                    "SCP": ["nausf-auth"]
                }
            }]),
            Some(serde_json::json!(["AMF", "UDM", "SCP"])),
        )
    }

    /// #1918: the NRF grants the UDM the AUSF's Deregister resource scope with
    /// the service scope, and an AMF only the service scope, so a token carrying
    /// `nausf-auth:ue-authentications` proves a UDM even through an SCP.
    #[test]
    fn the_deregister_scope_is_granted_to_the_udm_only_1918() {
        let ausf = ausf_with_deregister_scope();
        let requested: Vec<String> = vec![
            "nausf-auth".into(),
            nextgcore_sbi::resource_scope::NAUSF_AUTH_UE_AUTHENTICATIONS.into(),
        ];
        let udm = authorize_access_token(
            &auth_consumer("UDM"),
            "UDM",
            "AUSF",
            &requested,
            std::slice::from_ref(&ausf),
            &[],
            &[],
        )
        .expect("the UDM is authorized");
        assert_eq!(udm, requested, "the UDM gets both scopes");
        let amf = authorize_access_token(
            &auth_consumer("AMF"),
            "AMF",
            "AUSF",
            &requested,
            std::slice::from_ref(&ausf),
            &[],
            &[],
        )
        .expect("the AMF is authorized");
        // #1964: the AMF holds the ue-authentications scope too (authenticate);
        // the SCP, which only relays, does not.
        assert_eq!(amf, requested, "the AMF gets both scopes");
        let scp = authorize_access_token(
            &auth_consumer("SCP"),
            "SCP",
            "AUSF",
            &requested,
            std::slice::from_ref(&ausf),
            &[],
            &[],
        )
        .expect("the SCP keeps its service scope");
        assert_eq!(scp, vec!["nausf-auth".to_string()]);
    }

    /// #1811: only the UDM is granted the AuthenticationSubscription scope.
    /// A PCF or NEF asking for it gets the service scope alone (RFC 6749 §3.3
    /// lets the server narrow the request), so its token cannot read K at the
    /// UDR; asking for the resource scope ALONE gets nothing.
    ///
    /// REVERT-VERIFIED: with `authorize_access_token` calling
    /// `authorizes_service(.., service)` again instead of `authorizes_scope`, the
    /// UDM's token loses the resource scope and the first assertion fails.
    #[test]
    fn the_auth_subscription_scope_is_granted_to_the_udm_only_1811() {
        let udr = udr_with_resource_scopes();
        let requested: Vec<String> = vec!["nudr-dr".into(), AUTH_SUBS_READ.into()];
        let udm = authorize_access_token(
            &auth_consumer("UDM"),
            "UDM",
            "UDR",
            &requested,
            std::slice::from_ref(&udr),
            &[],
            &[],
        )
        .expect("the UDM is authorized");
        assert_eq!(udm, requested, "the UDM gets both scopes");
        for nf_type in ["PCF", "NEF"] {
            let granted = authorize_access_token(
                &auth_consumer(nf_type),
                nf_type,
                "UDR",
                &requested,
                std::slice::from_ref(&udr),
                &[],
                &[],
            )
            .expect("the service scope is still granted");
            assert_eq!(granted, vec!["nudr-dr".to_string()], "{nf_type}");
            let err = authorize_access_token(
                &auth_consumer(nf_type),
                nf_type,
                "UDR",
                &[AUTH_SUBS_MODIFY.into()],
                std::slice::from_ref(&udr),
                &[],
                &[],
            )
            .expect_err("the resource scope alone is refused");
            assert_eq!(err.0, "unauthorized_client", "{nf_type}");
        }
    }

    /// #1828: two UDRs whose `allowedOperationsPerNfType` maps disagree. One
    /// grants the PCF the AuthenticationSubscription read scope; the standard
    /// one grants it to the UDM alone. A type-targeted token (aud=UDR, accepted
    /// by both) carries the resource scope only for a consumer EVERY candidate
    /// allows, so the PCF gets the service scope alone while the UDM, allowed
    /// by both, keeps the resource scope. Pinned to the wider UDR by instance,
    /// the PCF's token names that UDR alone and is granted.
    ///
    /// REVERT-VERIFIED: with the any-producer rule restored for resource
    /// scopes, the PCF's type-targeted token carries the K-read scope and the
    /// first assertion fails.
    #[test]
    fn a_resource_scope_needs_every_candidate_udr_to_allow_it_1828() {
        let udr = |id: &str, pcf_scopes: serde_json::Value| {
            let mut attrs = udr_with_resource_scopes().attributes;
            attrs["nfInstanceId"] = id.into();
            attrs["nfServices"][0]["allowedOperationsPerNfType"]["PCF"] = pcf_scopes;
            NfProfile::from_json(&attrs).expect("profile")
        };
        let standard = udr("udr-standard-1828", serde_json::json!(["nudr-dr"]));
        let wider = udr(
            "udr-wider-1828",
            serde_json::json!(["nudr-dr", AUTH_SUBS_READ]),
        );
        let requested: Vec<String> = vec!["nudr-dr".into(), AUTH_SUBS_READ.into()];
        let both = [standard.clone(), wider.clone()];

        let pcf = authorize_access_token(
            &auth_consumer("PCF"),
            "PCF",
            "UDR",
            &requested,
            &both,
            &[],
            &[],
        )
        .expect("the service scope is still granted");
        assert_eq!(
            pcf,
            vec!["nudr-dr".to_string()],
            "one UDR's wider map does not grant the resource scope to every UDR"
        );
        // Either order of the candidates.
        let reversed = [wider.clone(), standard.clone()];
        let pcf = authorize_access_token(
            &auth_consumer("PCF"),
            "PCF",
            "UDR",
            &requested,
            &reversed,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(pcf, vec!["nudr-dr".to_string()]);

        let udm = authorize_access_token(
            &auth_consumer("UDM"),
            "UDM",
            "UDR",
            &requested,
            &both,
            &[],
            &[],
        )
        .expect("the UDM is allowed by both");
        assert_eq!(udm, requested, "allowed by every candidate");

        // Instance-targeted: the one candidate's own map decides.
        let pinned = authorize_access_token(
            &auth_consumer("PCF"),
            "PCF",
            "UDR",
            &requested,
            std::slice::from_ref(&wider),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(pinned, requested, "the pinned UDR allows it");
    }

    /// R26 on #1922: a permissive UDR on a slice of its own, and a PCF naming
    /// that slice in its token request. The eligible set is then the permissive
    /// UDR alone, but the token's audience is still "UDR", so the standard UDR
    /// accepts it too: the K-read scope must not be granted.
    ///
    /// REVERT-VERIFIED: with the acceptor check reading `decisions` (the
    /// requester-filtered set) instead of `acceptors`, the PCF gets the scope.
    #[test]
    fn a_requester_chosen_slice_does_not_narrow_the_acceptors_1828() {
        let udr = |id: &str, pcf_scopes: serde_json::Value, sst: Option<u64>| {
            let mut attrs = udr_with_resource_scopes().attributes;
            attrs["nfInstanceId"] = id.into();
            attrs["nfServices"][0]["allowedOperationsPerNfType"]["PCF"] = pcf_scopes;
            if let Some(sst) = sst {
                attrs["sNssais"] = serde_json::json!([{ "sst": sst }]);
            }
            NfProfile::from_json(&attrs).expect("profile")
        };
        let standard = udr(
            "udr-standard-1828b",
            serde_json::json!(["nudr-dr"]),
            Some(1),
        );
        let permissive = udr(
            "udr-permissive-1828b",
            serde_json::json!(["nudr-dr", AUTH_SUBS_READ]),
            Some(99),
        );
        let all = [standard, permissive];
        let requested: Vec<String> = vec!["nudr-dr".into(), AUTH_SUBS_READ.into()];
        let slice = [serde_json::json!({ "sst": 99 })];
        let granted = authorize_access_token_for(
            &auth_consumer("PCF"),
            "PCF",
            "UDR",
            &requested,
            &all,
            &token_acceptors(&all, "UDR", None),
            &[],
            &slice,
        )
        .expect("the service scope is granted");
        assert_eq!(
            granted,
            vec!["nudr-dr".to_string()],
            "the standard UDR accepts the token too, so no K-read scope"
        );
    }

    /// R26 on #1922: a SUSPENDED UDR still accepts a type-targeted token once
    /// it resumes, so it is an acceptor; the eligible set skips it.
    ///
    /// REVERT-VERIFIED: with `token_acceptors` filtering out non-operative
    /// producers, the suspended standard UDR is ignored and the PCF gets the
    /// scope; the first assertion fails.
    #[test]
    fn a_suspended_udr_still_counts_as_an_acceptor_1828() {
        let udr = |id: &str, pcf_scopes: serde_json::Value, status: &str| {
            let mut attrs = udr_with_resource_scopes().attributes;
            attrs["nfInstanceId"] = id.into();
            attrs["nfStatus"] = status.into();
            attrs["nfServices"][0]["allowedOperationsPerNfType"]["PCF"] = pcf_scopes;
            NfProfile::from_json(&attrs).expect("profile")
        };
        let suspended = udr(
            "udr-suspended-1828c",
            serde_json::json!(["nudr-dr"]),
            "SUSPENDED",
        );
        let permissive = udr(
            "udr-permissive-1828c",
            serde_json::json!(["nudr-dr", AUTH_SUBS_READ]),
            "REGISTERED",
        );
        let registered = [suspended.clone(), permissive.clone()];
        let acceptors = token_acceptors(&registered, "UDR", None);
        assert_eq!(acceptors.len(), 2, "the suspended UDR is an acceptor");
        let requested: Vec<String> = vec!["nudr-dr".into(), AUTH_SUBS_READ.into()];
        // The handler's operative set: the suspended UDR is not in it.
        let granted = authorize_access_token_for(
            &auth_consumer("PCF"),
            "PCF",
            "UDR",
            &requested,
            std::slice::from_ref(&permissive),
            &acceptors,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(granted, vec!["nudr-dr".to_string()]);
        // Pinned to the permissive UDR, its own map decides.
        let pinned = token_acceptors(&registered, "UDR", Some(&permissive));
        let granted = authorize_access_token_for(
            &auth_consumer("PCF"),
            "PCF",
            "UDR",
            &requested,
            std::slice::from_ref(&permissive),
            &pinned,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(granted, requested);
    }

    /// #1811, TS 29.510 Table 6.1.6.2.3-1 NOTE 11: with neither
    /// allowedOperationsPerNf* registered only the service scope is grantable,
    /// even to a UDM; once one is registered, a type it does not list is barred
    /// from the service scope too.
    #[test]
    fn resource_scopes_follow_note_11_of_the_nf_service_table_1811() {
        let plain = auth_producer(
            "UDR",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudr-dr"}]),
            None,
        );
        let granted = authorize_access_token(
            &auth_consumer("UDM"),
            "UDM",
            "UDR",
            &["nudr-dr".into(), AUTH_SUBS_READ.into()],
            &[plain],
            &[],
            &[],
        )
        .expect("service scope granted");
        assert_eq!(granted, vec!["nudr-dr".to_string()]);

        // AUSF passes allowedNfTypes (absent) but is not in the map.
        let unlisted = auth_producer(
            "UDR",
            serde_json::json!([{
                "serviceInstanceId": "s0", "serviceName": "nudr-dr",
                "allowedOperationsPerNfType": {"UDM": ["nudr-dr", AUTH_SUBS_READ]}
            }]),
            None,
        );
        let err = authorize_access_token(
            &auth_consumer("AUSF"),
            "AUSF",
            "UDR",
            &["nudr-dr".into()],
            &[unlisted],
            &[],
            &[],
        )
        .expect_err("a type the map does not list is barred");
        assert_eq!(err.0, "unauthorized_client");
    }

    /// #1811, NOTE 11's instance map: by default either map grants; with
    /// `allowedOperationsPerNfInstanceOverrides` the instance's own entry
    /// replaces its type's.
    #[test]
    fn the_instance_map_adds_to_or_overrides_the_type_map_1811() {
        let consumer = auth_consumer("PCF");
        let id = consumer.nf_instance_id.clone();
        let udr = |overrides: bool, instance_scopes: serde_json::Value| {
            auth_producer(
                "UDR",
                serde_json::json!([{
                    "serviceInstanceId": "s0", "serviceName": "nudr-dr",
                    "allowedOperationsPerNfType": {"PCF": ["nudr-dr", AUTH_SUBS_READ]},
                    "allowedOperationsPerNfInstance": {id.clone(): instance_scopes},
                    "allowedOperationsPerNfInstanceOverrides": overrides
                }]),
                None,
            )
        };
        let grant = |p: NfProfile, scope: &str| {
            authorize_access_token(
                &consumer,
                "PCF",
                "UDR",
                &[scope.to_string()],
                &[p],
                &[],
                &[],
            )
            .is_ok()
        };
        let modify = serde_json::json!(["nudr-dr", AUTH_SUBS_MODIFY]);
        assert!(
            grant(udr(false, modify.clone()), AUTH_SUBS_MODIFY),
            "instance map adds"
        );
        assert!(
            grant(udr(false, modify.clone()), AUTH_SUBS_READ),
            "type map still grants"
        );
        assert!(grant(udr(true, modify.clone()), AUTH_SUBS_MODIFY));
        assert!(
            !grant(udr(true, modify), AUTH_SUBS_READ),
            "overridden: the type map no longer grants this instance"
        );
    }

    #[test]
    fn test_authorize_token_unoffered_service_is_invalid_scope() {
        // The only producer offers a different service -> invalid_scope, no token.
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudm-uecm"}]),
            None,
        );
        let err = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect_err("unoffered service must be rejected");
        assert_eq!(err.0, "invalid_scope");
    }

    #[test]
    fn test_authorize_token_consumer_type_barred_is_unauthorized_client() {
        // Producer offers the service but restricts it to AMF -> the SMF
        // consumer is unauthorized_client, no token.
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([{"serviceInstanceId": "s0", "serviceName": "nudm-sdm"}]),
            Some(serde_json::json!(["AMF"])),
        );
        let err = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect_err("barred consumer type must be rejected");
        assert_eq!(err.0, "unauthorized_client");
    }

    #[test]
    fn test_authorize_token_nftype_mismatch_is_invalid_request() {
        // Asserted nfType differs from the registered consumer profile.
        let consumer = auth_consumer("SMF");
        let err = authorize_access_token(
            &consumer,
            "AUSF",
            "UDM",
            &["nudm-sdm".into()],
            &[],
            &[],
            &[],
        )
        .expect_err("nfType mismatch must be rejected");
        assert_eq!(err.0, "invalid_request");
    }

    #[test]
    fn test_authorize_token_no_producer_is_invalid_scope() {
        // Issue #1391: with no registered producer of the target type nothing
        // authorizes the scope, so the NRF fails closed (TS 33.501 §13.4.1.1.2
        // step 2: "the NRF shall not issue an access token").
        let consumer = auth_consumer("SMF");
        let err =
            authorize_access_token(&consumer, "SMF", "UDM", &["nudm-sdm".into()], &[], &[], &[])
                .expect_err("no producer registered must not grant a scope");
        assert_eq!(err.0, "invalid_scope");
        assert!(
            err.1.contains("no operative UDM producer is registered"),
            "{}",
            err.1
        );
    }

    #[test]
    fn test_authorize_token_grants_only_permitted_subset() {
        // Two requested services; one is barred at the per-service level.
        let consumer = auth_consumer("SMF");
        let udm = auth_producer(
            "UDM",
            serde_json::json!([
                {"serviceInstanceId": "s0", "serviceName": "nudm-sdm"},
                {"serviceInstanceId": "s1", "serviceName": "nudm-uecm",
                 "allowedNfTypes": ["AMF"]}
            ]),
            Some(serde_json::json!(["SMF", "AMF"])),
        );
        let granted = authorize_access_token(
            &consumer,
            "SMF",
            "UDM",
            &["nudm-sdm".into(), "nudm-uecm".into()],
            &[udm],
            &[],
            &[],
        )
        .expect("at least one service is permitted");
        assert_eq!(granted, vec!["nudm-sdm".to_string()]);
    }

    /// Full HTTP-level lifecycle over a real HTTP/2 SBI server on an
    /// ephemeral port: register -> GET (fidelity) -> discover (filter
    /// matrix) -> PATCH (RFC 6902 + RFC 7396) -> token -> deregister.
    /// Everything is bounded by a 30s timeout; the server is stopped at the
    /// end so no blocking threads leak.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_lifecycle_register_discover_patch_deregister() {
        use serde_json::json;

        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();

        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), addr_listener);
        server
            .start(nrf_handler_as_path_certificate)
            .await
            .expect("SBI server starts");

        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let nf_id = "5e9b1c0a-1111-4f6a-8888-0123456789ab";

        let lifecycle = async {
            // --- Register: missing mandatory attrs -> 400 ProblemDetails ---
            let bad = json!({"nfInstanceId": nf_id, "nfStatus": "REGISTERED"});
            let resp = client
                .put_json(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"), &bad)
                .await
                .expect("PUT (invalid)");
            assert_eq!(resp.status, 400);
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(problem["status"], 400);
            assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");
            assert!(problem["detail"].as_str().unwrap().contains("nfType"));

            // --- Register: full profile -> 201 + Location + full echo ---
            let profile = json!({
                "nfInstanceId": nf_id,
                "nfType": "SMF",
                "nfStatus": "REGISTERED",
                "heartBeatTimer": 10,
                "plmnList": [{"mcc": "001", "mnc": "01"}],
                "sNssais": [{"sst": 1, "sd": "010203"}],
                "ipv4Addresses": ["10.1.2.3"],
                "fqdn": "smf.example.com",
                "capacity": 100,
                "nfServices": [{
                    "serviceInstanceId": "svc-0",
                    "serviceName": "nsmf-pdusession",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "ipEndPoints": [{"ipv4Address": "10.1.2.3", "port": 7777}]
                }],
                "smfInfo": {
                    "sNssaiSmfInfoList": [{
                        "sNssai": {"sst": 1, "sd": "010203"},
                        "dnnSmfInfoList": [{"dnn": "internet"}]
                    }]
                }
            });
            let resp = client
                .put_json(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"), &profile)
                .await
                .expect("PUT register");
            assert_eq!(resp.status, 201);
            assert!(resp
                .http
                .get_header("Location")
                .expect("Location header on 201")
                .ends_with(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}")));

            // --- GET: round-trip preserves every attribute ---
            let resp = client
                .get(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("GET profile");
            assert_eq!(resp.status, 200);
            let stored: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(stored, profile, "register -> GET must be lossless");

            // --- Discover: matching filters ---
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "SMF");
            req.http.set_param("requester-nf-type", "AMF");
            req.http.set_param("service-names", "nsmf-pdusession");
            req.http.set_param("dnn", "internet");
            // Issue #101: the RAW JSON. This used to be hand-percent-encoded
            // here, compensating for a client that did not encode -- so the test
            // exercised a path no real consumer takes. The client encodes now, and
            // the shared SBI server decodes it on the way in (#65), so this
            // asserts the real round trip.
            req.http
                .set_param("snssais", r#"[{"sst":1,"sd":"010203"}]"#);
            let resp = client.send_request(req).await.expect("discover");
            assert_eq!(resp.status, 200);
            let result: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let instances = result["nfInstances"].as_array().unwrap();
            assert!(
                instances.iter().any(|p| p["nfInstanceId"] == nf_id),
                "registered SMF must be discoverable: {result}"
            );

            // --- Discover: no match -> 200 with EMPTY SearchResult, not 404 ---
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "AUSF");
            req.http.set_param("requester-nf-type", "AMF");
            let resp = client.send_request(req).await.expect("discover empty");
            assert_eq!(resp.status, 200);
            let result: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(result["nfInstances"], json!([]));

            // --- Discover: missing mandatory requester-nf-type -> 400 ---
            let mut req = SbiRequest::get("/nnrf-disc/v1/nf-instances");
            req.http.set_param("target-nf-type", "SMF");
            let resp = client.send_request(req).await.expect("discover invalid");
            assert_eq!(resp.status, 400);
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(problem["cause"], "MANDATORY_QUERY_PARAM_MISSING");

            // --- PATCH: RFC 6902 json-patch+json (the TS 29.510 format) ---
            let patch = json!([
                {"op": "test", "path": "/nfStatus", "value": "REGISTERED"},
                {"op": "replace", "path": "/capacity", "value": 55},
                {"op": "add", "path": "/load", "value": 12}
            ]);
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/json-patch+json");
            req.http.set_content(patch.to_string());
            let resp = client.send_request(req).await.expect("PATCH json-patch");
            assert_eq!(resp.status, 200);
            let updated: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(updated["capacity"], 55);
            assert_eq!(updated["load"], 12);
            // Untouched attributes survive the patch.
            assert_eq!(updated["smfInfo"], profile["smfInfo"]);

            // --- PATCH: failed RFC 6902 test op -> 409 Conflict ---
            let patch = json!([{"op": "test", "path": "/capacity", "value": 1}]);
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/json-patch+json");
            req.http.set_content(patch.to_string());
            let resp = client.send_request(req).await.expect("PATCH failing test");
            assert_eq!(resp.status, 409);

            // --- PATCH: RFC 7396 merge-patch+json ---
            let merge = json!({"load": 70, "priority": 3});
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/merge-patch+json");
            req.http.set_content(merge.to_string());
            let resp = client.send_request(req).await.expect("PATCH merge-patch");
            assert_eq!(resp.status, 200);
            let updated: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(updated["load"], 70);
            assert_eq!(updated["priority"], 3);
            assert_eq!(updated["capacity"], 55, "merge patch keeps earlier patch");

            // --- PATCH: removing a mandatory attribute -> 400 ---
            let patch = json!([{"op": "remove", "path": "/nfType"}]);
            let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
            req.http
                .set_header("Content-Type", "application/json-patch+json");
            req.http.set_content(patch.to_string());
            let resp = client
                .send_request(req)
                .await
                .expect("PATCH remove mandatory");
            assert_eq!(resp.status, 400);

            // --- PATCH on unknown NF -> 404 ---
            let resp = client
                .patch_json(
                    "/nnrf-nfm/v1/nf-instances/00000000-dead-beef-0000-000000000000",
                    &json!([{"op": "replace", "path": "/load", "value": 1}]),
                )
                .await
                .expect("PATCH unknown NF");
            assert_eq!(resp.status, 404);

            // --- OAuth2 token, through the REAL router and the process-global
            // default policy: an unauthenticated request is refused (issue #64
            // gap 1). This assertion INVERTED with the posture change — it used to
            // expect 200 — and it is the full-stack proof that the secure default
            // is what a deployment actually gets, not just what the struct says.
            let token_body = json!({
                "grant_type": "client_credentials",
                "nfInstanceId": nf_id,
                "nfType": "SMF",
                "targetNfType": "UDM",
                "scope": "nudm-sdm"
            });
            let resp = client
                .post_json("/nnrf-oauth2/v1/access-token", &token_body)
                .await
                .expect("token request");
            assert_eq!(
                resp.status, 400,
                "the default policy must refuse an unauthenticated token request: {:?}",
                resp.http.content
            );
            let err: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(err["error"], "invalid_client");

            // The claim shape is asserted against the handler with the documented
            // opt-out applied, because the router reads the process-global
            // `nrf_policy()` OnceLock, which a test cannot steer without racing
            // every other test in this binary.
            //
            // Issue #1391: a token is only minted when a registered producer of
            // the target type authorizes the scope, so register one. A unique NF
            // type keeps it out of every other test's producer set.
            let producer_id = "5e9b1c0a-1391-4f6a-8888-0123456789ab";
            nf_manager()
                .register(
                    NfProfile::from_json(&json!({
                        "nfInstanceId": producer_id, "nfType": "SLPKMF",
                        "nfStatus": "REGISTERED",
                        "nfServices": [{"serviceInstanceId": "s0",
                                        "serviceName": "nrfdlife-svc"}],
                    }))
                    .unwrap(),
                )
                .unwrap();
            let mut token_req = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            token_req.http.set_content(
                json!({
                    "grant_type": "client_credentials",
                    "nfInstanceId": nf_id,
                    "nfType": "SMF",
                    "targetNfType": "SLPKMF",
                    "scope": "nrfdlife-svc"
                })
                .to_string(),
            );
            let resp =
                handle_access_token_request_with_policy(&token_req, &policy_without_client_auth())
                    .await;
            nf_manager().deregister(producer_id).ok();
            assert_eq!(resp.status, 200, "opt-out path: {:?}", resp.http.content);
            let token_resp: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let token = token_resp["access_token"].as_str().unwrap();
            let payload_b64 = token.split('.').nth(1).unwrap();
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let claims: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
            assert_eq!(claims["iss"], nrf_instance_id(), "iss must be NRF UUID");
            assert_ne!(claims["iss"], "NRF");
            assert_eq!(claims["sub"], nf_id, "sub must be the requesting NF");

            // --- OAuth2 token: RFC 6749 §5.2 error JSON, not bare statuses ---
            let resp = client
                .post_json(
                    "/nnrf-oauth2/v1/access-token",
                    &json!({"grant_type": "password", "nfInstanceId": nf_id,
                            "nfType": "SMF", "targetNfType": "UDM", "scope": "x"}),
                )
                .await
                .expect("token bad grant");
            assert_eq!(resp.status, 400);
            let err: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(err["error"], "unsupported_grant_type");

            // An UNREGISTERED client is invalid_client for the registry-lookup
            // reason. Exercised with the opt-out applied so authentication does not
            // short-circuit it first — otherwise the assertion would still pass
            // while testing something else entirely.
            let mut unknown_req = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            unknown_req.http.set_content(
                json!({"grant_type": "client_credentials",
                       "nfInstanceId": "11111111-2222-3333-4444-555555555555",
                       "nfType": "SMF", "targetNfType": "UDM", "scope": "nudm-sdm"})
                .to_string(),
            );
            let resp = handle_access_token_request_with_policy(
                &unknown_req,
                &policy_without_client_auth(),
            )
            .await;
            assert_eq!(resp.status, 400);
            let err: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(err["error"], "invalid_client");
            assert!(
                err["error_description"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("not registered"),
                "must fail the registry lookup, not the authentication check: {err}"
            );

            // --- Deregister -> 204, heartbeat timer disarmed, GET -> 404 ---
            assert!(
                HEARTBEAT_TIMERS.lock().unwrap().contains_key(nf_id),
                "registration must arm the heartbeat timer"
            );
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("DELETE deregister");
            assert_eq!(resp.status, 204);
            assert!(
                !HEARTBEAT_TIMERS.lock().unwrap().contains_key(nf_id),
                "explicit deregister must cancel the heartbeat timer"
            );
            let resp = client
                .get(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("GET after deregister");
            assert_eq!(resp.status, 404);
        };

        let outcome = tokio::time::timeout(Duration::from_secs(30), lifecycle).await;
        client.close().await;
        server.stop().await.expect("server stops");
        outcome.expect("lifecycle test timed out");
    }

    /// #235: the SHARED shutdown-path deregistration client really does remove
    /// the profile from this NRF's real registry.
    ///
    /// The lifecycle test above already proves `nrfd`'s DELETE handler over HTTP,
    /// but it drives the DELETE by hand. What was unproven is that
    /// `nextgcore_sbi::heartbeat::deregister_self()` — the one line now added to
    /// every registering NF's shutdown path — reaches that handler: the right
    /// method, the right URI, and the instance ID it recorded at registration
    /// rather than one passed in. So this drives the client, not the request.
    ///
    /// Takes `lock_registration_state_for_test`: the #434 re-registration test
    /// below mutates the same heartbeat statics (pause flag, registered ID), so
    /// the two must not interleave. The test restores what it mutates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // a std guard held to serialise globals, by design
    async fn test_shared_deregister_self_removes_the_profile_from_the_real_nrf() {
        // A plaintext NRF: the dev profile, or #1617's NRF client dials https.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use serde_json::json;
        let _registration_guard = nextgcore_sbi::heartbeat::lock_registration_state_for_test();

        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), addr_listener);
        server
            .start(nrf_handler_as_path_certificate)
            .await
            .expect("SBI server starts");

        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let nf_id = "5e9b1c0a-4444-4f6a-8888-0123456789ab";

        let body = async {
            // Register a real profile through the real handler.
            let profile = json!({
                "nfInstanceId": nf_id,
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "heartBeatTimer": 10,
                "ipv4Addresses": ["10.4.4.4"],
                "nfServices": [{
                    "serviceInstanceId": "svc-0",
                    "serviceName": "nudm-sdm",
                    "versions": [{"apiVersionInUri": "v2", "apiFullVersion": "2.0.0"}],
                    "scheme": "http",
                    "ipEndPoints": [{"ipv4Address": "10.4.4.4", "port": 7777}]
                }]
            });
            let resp = client
                .put_json(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"), &profile)
                .await
                .expect("PUT register");
            assert_eq!(resp.status, 201);

            // Stand in for what an NF's startup does: point the global SBI
            // context at this NRF, and record the ID the heartbeat worker would
            // have recorded.
            let sbi_ctx = nextgcore_sbi::context::global_context();
            sbi_ctx
                .set_nrf_uri(format!("http://127.0.0.1:{}", addr.port()))
                .await;
            nextgcore_sbi::heartbeat::set_registered_nf_instance_id(nf_id);

            // The shutdown path, called exactly as the 17 NFs now call it.
            assert!(
                nextgcore_sbi::heartbeat::deregister_self().await,
                "a recorded instance ID must produce a DELETE"
            );

            // The profile is gone from the REAL registry, not merely from a
            // recorded request list.
            assert!(
                nf_manager().get(nf_id).is_none(),
                "deregister_self must remove the profile from the NRF registry"
            );
            let resp = client
                .get(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"))
                .await
                .expect("GET after deregister");
            assert_eq!(resp.status, 404);

            // Heartbeats are paused BEFORE the DELETE, so a tick cannot PATCH a
            // profile that no longer exists.
            assert!(
                nextgcore_sbi::heartbeat::heartbeat_paused(),
                "deregistration must pause the heartbeat worker"
            );

            // Deregistering again gets a real 404 from the real handler, and that
            // must read as success: a profile the NRF does not hold is the state
            // we wanted, and an NF shutting down after its supervision timer
            // already expired should not log an alarming warning.
            assert!(
                nextgcore_sbi::heartbeat::deregister_nf(nf_id).await.is_ok(),
                "a 404 from the NRF means the profile is gone, which is success"
            );

            // With no recorded ID there is nothing to deregister, and the caller
            // is told so rather than a bare DELETE being sent to /nf-instances/.
            nextgcore_sbi::heartbeat::clear_registered_nf_instance_id();
            assert!(
                !nextgcore_sbi::heartbeat::deregister_self().await,
                "no recorded instance ID must issue no DELETE"
            );
        };

        let outcome = tokio::time::timeout(Duration::from_secs(30), body).await;

        // Restore the process-globals this test mutated.
        nextgcore_sbi::heartbeat::set_heartbeat_paused(false);
        nextgcore_sbi::heartbeat::clear_registered_nf_instance_id();
        client.close().await;
        server.stop().await.expect("server stops");
        outcome.expect("deregister test timed out");
    }

    /// #1574 review M1: an NFRegister retry whose PUT is at the NRF when shutdown
    /// begins, and lands after it, is deregistered BY `deregister_self`, before it
    /// returns. Left to the retry task, that DELETE was cancelled when the process
    /// exited, and the profile stayed discoverable at the NRF.
    ///
    /// Against the real NRF registry: the retry's second attempt PUTs a real
    /// profile, but only once `deregister_self` is already running.
    ///
    /// REVERT-VERIFIED: with `deregister_self` not waiting for the in-flight
    /// attempt (the #1574 head), it returns `false` at once and the profile is
    /// still registered; with its DELETE replaced by a no-op, the profile is
    /// still registered.
    /// Without the attempt's `notify_waiters()` wake-up, it returns only when
    /// the 5 s bound runs out, and the "woken by it" assertion fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // a std guard held to serialise globals, by design
    async fn a_registration_landing_during_shutdown_is_deleted_before_deregister_self_returns() {
        // A plaintext NRF: the dev profile, or #1617's NRF client dials https.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use nextgcore_sbi::heartbeat as hb;
        use serde_json::json;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        let _registration_guard = hb::lock_registration_state_for_test();
        hb::clear_registration_abandoned();
        hb::clear_registered_nf_instance_id();

        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        server
            .start(nrf_handler_as_path_certificate)
            .await
            .expect("SBI server starts");
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{}", addr.port()))
            .await;
        // Distinct ID and NF type: nf_manager() is process-global.
        let nf_id = "5e9b1c0a-1574-4f6a-8888-0123456789ab";
        let port = addr.port();

        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let gates = std::sync::Arc::new(std::sync::Mutex::new(Some((started_tx, release_rx))));
        let attempts = std::sync::Arc::new(AtomicU32::new(0));
        let ran = std::sync::Arc::new(AtomicBool::new(false));

        let body = async {
            let (a, g, r) = (attempts.clone(), gates.clone(), ran.clone());
            let out = hb::register_or_retry(
                "TEST",
                hb::RegisterRetryPolicy {
                    initial: Duration::from_millis(10),
                    max: Duration::from_millis(10),
                    jitter_percent: 0,
                },
                move || {
                    let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                    let gate = if n == 2 {
                        g.lock().unwrap().take()
                    } else {
                        None
                    };
                    async move {
                        let Some((started, release)) = gate else {
                            return Err("NRF unreachable".to_string());
                        };
                        // In flight: hold the PUT until shutdown has begun.
                        let _ = started.send(());
                        let _ = release.await;
                        let client =
                            nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", port);
                        let profile = json!({
                            "nfInstanceId": nf_id,
                            "nfType": "NWDAF",
                            "nfStatus": "REGISTERED",
                            "heartBeatTimer": 10,
                            "ipv4Addresses": ["10.15.7.4"]
                        });
                        let resp = client
                            .put_json(&format!("/nnrf-nfm/v1/nf-instances/{nf_id}"), &profile)
                            .await
                            .map_err(|e| e.to_string())?;
                        assert_eq!(resp.status, 201);
                        Ok(Some(nf_id.to_string()))
                    }
                },
                move |_| r.store(true, Ordering::SeqCst),
            )
            .await;
            assert_eq!(out, hb::Registration::Retrying);
            started_rx.await.expect("the second attempt is in flight");

            let dereg = tokio::spawn(hb::deregister_self());
            nextgcore_sbi::test_support::poll_until(
                Duration::from_secs(5),
                Duration::from_millis(5),
                || async { hb::registration_abandoned().then_some(()) },
            )
            .await
            .expect("shutdown has begun");
            // The NRF now accepts the registration that was in flight.
            let released = std::time::Instant::now();
            release_tx.send(()).expect("release the PUT");

            assert!(
                dereg.await.expect("deregister_self"),
                "the late registration produced a DELETE"
            );
            // Woken by the landing attempt, not by the 5 s bound running out.
            let took = released.elapsed();
            assert!(
                took < Duration::from_secs(2),
                "deregister_self returned {took:?} after the landing, not woken by it"
            );
            assert!(
                nf_manager().get(nf_id).is_none(),
                "the late registration is gone by the time deregister_self returns"
            );
            assert!(
                !ran.load(Ordering::SeqCst),
                "and no heartbeat was started for it"
            );
        };
        let outcome = tokio::time::timeout(Duration::from_secs(30), body).await;

        hb::set_heartbeat_paused(false);
        hb::clear_registered_nf_instance_id();
        hb::clear_registration_abandoned();
        server.stop().await.expect("server stops");
        outcome.expect("late-registration test timed out");
    }

    /// #1574 review m1: `deregister_self` gives up on an NRF that never answers
    /// within `DEREGISTER_TIMEOUT` (5 s), well inside Kubernetes' default 30 s
    /// termination grace, and still reports that a DELETE was attempted.
    ///
    /// REVERT-VERIFIED: with `DEREGISTER_TIMEOUT` at 3600 s, the client's own
    /// 30 s request timeout ends the wait instead, and the bound assertion fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // a std guard held to serialise globals, by design
    async fn deregister_self_gives_up_on_a_silent_nrf_within_its_bound() {
        // A plaintext NRF: the dev profile, or #1617's NRF client dials https.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use nextgcore_sbi::heartbeat as hb;
        let _registration_guard = hb::lock_registration_state_for_test();
        hb::clear_registration_abandoned();

        // An NRF that accepts the connection and never answers.
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let silent = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        silent
            .start(|_req: SbiRequest| async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                SbiResponse::with_status(204)
            })
            .await
            .expect("silent NRF starts");
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{}", addr.port()))
            .await;
        hb::set_registered_nf_instance_id("5e9b1c0a-1574-4f6a-8888-00000000dead");

        let started = std::time::Instant::now();
        let issued = tokio::time::timeout(Duration::from_secs(60), hb::deregister_self())
            .await
            .expect("deregister_self returns");
        let took = started.elapsed();

        hb::set_heartbeat_paused(false);
        hb::clear_registered_nf_instance_id();
        hb::clear_registration_abandoned();
        let _ = tokio::time::timeout(Duration::from_secs(2), silent.stop()).await;

        assert!(issued, "a recorded ID produces a DELETE attempt");
        assert!(
            took >= hb::DEREGISTER_TIMEOUT - Duration::from_millis(100)
                && took < hb::DEREGISTER_TIMEOUT + Duration::from_secs(3),
            "gave up after {took:?}, not within the {:?} bound",
            hb::DEREGISTER_TIMEOUT
        );
    }

    /// #1334: the NRF's `/metrics`, scraped over HTTP, serves every NRF series the
    /// shipped rules and dashboards use, and the counters follow real Nnrf traffic
    /// through the production handler: a registration, a heartbeat, a discovery that
    /// finds it, one that finds nothing, one rejected, a deregistration.
    ///
    /// REVERT-VERIFIED: without the router's `observe` the registration / update /
    /// deregistration counts stay; without `observe_discovery(Some(total))` the
    /// success count stays; without `render_nrf_families` the series are missing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_scraped_endpoint_follows_nnrf_traffic_1334() {
        use serde_json::json;
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        server
            .start(nrf_handler_as_path_certificate)
            .await
            .expect("SBI server starts");
        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let (bound, handle) = nextgcore_metrics::nes_energy::serve_metrics(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(nextgcore_nrfd::metrics::render_prometheus),
        )
        .await
        .expect("metrics endpoint");
        let scrape = || nextgcore_metrics::nf::scrape_for_test(bound);
        let value =
            |body: &str, s: &str| nextgcore_metrics::nf::sample_value(body, s).unwrap_or(0.0);
        // A type no other nrfd test registers or discovers.
        let nf_id = "13340000-0000-4000-8000-0000000013a4";
        let path = format!("/nnrf-nfm/v1/nf-instances/{nf_id}");
        let names = [
            "nrf_nf_registrations_total",
            "nrf_nf_updates_total",
            "nrf_nf_deregistrations_total",
            "nrf_discovery_success_total",
            "nrf_discovery_empty_total",
            "nrf_discovery_failure_total",
        ];
        let before = scrape().await;
        let b: Vec<f64> = names.iter().map(|n| value(&before, n)).collect();

        let resp = client
            .put_json(
                &path,
                &json!({
                    "nfInstanceId": nf_id, "nfType": "TSCTSF", "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10, "ipv4Addresses": ["10.13.3.4"]
                }),
            )
            .await
            .expect("PUT");
        assert_eq!(resp.status, 201);
        let mid = scrape().await;
        assert!(
            value(
                &mid,
                r#"nrf_registered_nf_instances{nf_type="TSCTSF",nf_status="REGISTERED"}"#
            ) >= 1.0,
            "{mid}"
        );
        let patch = nextgcore_sbi::message::SbiRequest::patch(&path)
            .with_json_body(&nextgcore_sbi::heartbeat::build_load_patch(5))
            .expect("body")
            .with_header("Content-Type", "application/json-patch+json");
        let resp = client.send_request(patch).await.expect("PATCH");
        assert!(resp.status == 200 || resp.status == 204, "{}", resp.status);
        let resp = client
            .get("/nnrf-disc/v1/nf-instances?target-nf-type=TSCTSF&requester-nf-type=AF")
            .await
            .expect("discover");
        assert_eq!(resp.status, 200);
        let resp = client
            .get("/nnrf-disc/v1/nf-instances?target-nf-type=MFAF&requester-nf-type=AF")
            .await
            .expect("discover nothing");
        assert_eq!(resp.status, 200);
        let resp = client
            .get("/nnrf-disc/v1/nf-instances?target-nf-type=TSCTSF")
            .await
            .expect("discover without requester-nf-type");
        assert_eq!(resp.status, 400);
        let resp = client.delete(&path).await.expect("DELETE");
        assert_eq!(resp.status, 204);

        // #1334 review: an operation label is admitted on a 2xx, so a made-up resource
        // of every service this NF serves must be answered with an error, or a client
        // could mint label values.
        for service in ["nnrf-nfm", "nnrf-disc", "nnrf-oauth2"] {
            for path in [
                format!("/{service}/v1/madeup-resource-1334"),
                format!("/{service}/v1/imsi-001010000000001/madeup-resource-1334"),
            ] {
                for request in [
                    nextgcore_sbi::message::SbiRequest::get(&path),
                    nextgcore_sbi::message::SbiRequest::post(&path)
                        .with_body("{}", "application/json"),
                ] {
                    let resp = client.send_request(request).await.expect("answered");
                    assert!(resp.status >= 400, "{path} answered {}", resp.status);
                }
            }
        }
        let after = scrape().await;
        assert!(
            !after.contains("madeup"),
            "no made-up resource in a label: {after}"
        );
        // Discovery: the hit and the empty SearchResult are successes (TS 29.510
        // §5.3.2.2.2: 200 either way), the rejected query is the failure.
        for ((name, b), want) in names.iter().zip(&b).zip([1.0, 1.0, 1.0, 2.0, 1.0, 1.0]) {
            assert!(value(&after, name) >= b + want, "{name}: {b} -> {after}");
        }
        for name in [
            "nrf_registered_nf_count",
            "nrf_discovery_success_total",
            "nrf_discovery_failure_total",
            "nextgcore_sbi_request_total",
            "nextgcore_sbi_request_duration_seconds_bucket",
            "nextgcore_uptime_seconds",
            "process_resident_memory_bytes",
            "process_cpu_seconds_total",
        ] {
            assert!(
                nextgcore_metrics::nf::has_series(&after, name),
                "{name}:\n{after}"
            );
        }
        assert!(
            after.contains(r#"service="nnrf-nfm",operation="PUT nf-instances/{id}",status="201""#),
            "{after}"
        );
        assert!(!after.contains(nf_id), "no instance id in a label");
        assert!(
            !nextgcore_metrics::nf::has_series(&after, "nextgcore_nrf_registered"),
            "the NRF is no NRF client"
        );
        handle.abort();
        client.close().await;
        server.stop().await.expect("server stops");
    }

    /// #434: when this NRF loses an NF's profile, the NF's own heartbeat worker
    /// gets 404 and re-registers it, rather than warning forever while the NF
    /// stays undiscoverable.
    ///
    /// Drives the REAL worker against the REAL handler. The loss is a DELETE
    /// through the handler, the same state an NRF restart leaves. The assertion
    /// is on `nf_manager()`, the registry discovery reads, not on a recorded
    /// request. Also pins the NES carve-out: a paused worker must leave a
    /// deleted profile deleted, because NES deregisters on purpose.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // a std guard held to serialise globals, by design
    async fn test_a_404_heartbeat_re_registers_the_lost_profile_with_the_real_nrf() {
        // A plaintext NRF: the dev profile, or #1617's NRF client dials https.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use nextgcore_sbi::heartbeat as hb;
        use serde_json::json;
        let _registration_guard = hb::lock_registration_state_for_test();

        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), addr_listener);
        server
            .start(nrf_handler_as_path_certificate)
            .await
            .expect("SBI server starts");

        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        // Distinct ID AND NF type from every other test: nf_manager() is
        // process-global and the tests run in parallel. An AUSF here once made
        // the lifecycle test's "no AUSF is registered" discovery see this profile.
        // No other nrfd test registers or discovers an LMF.
        let nf_id = "5e9b1c0a-0434-4f6a-8888-0123456789ab";
        let path = format!("/nnrf-nfm/v1/nf-instances/{nf_id}");

        let body = async {
            let profile = json!({
                "nfInstanceId": nf_id,
                "nfType": "LMF",
                "nfStatus": "REGISTERED",
                "heartBeatTimer": 10,
                "ipv4Addresses": ["10.4.3.4"],
                "nfServices": [{
                    "serviceInstanceId": "svc-0",
                    "serviceName": "nlmf-loc",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "ipEndPoints": [{"ipv4Address": "10.4.3.4", "port": 7777}]
                }]
            });

            // What a daemon's startup does: register, record the profile in the
            // success arm, point the global context at the NRF, spawn the worker.
            let resp = client
                .put_json(&path, &profile)
                .await
                .expect("PUT register");
            assert_eq!(resp.status, 201);
            hb::set_registered_profile(&profile);
            nextgcore_sbi::context::global_context()
                .set_nrf_uri(format!("http://127.0.0.1:{}", addr.port()))
                .await;
            // Start PAUSED. The first tick fires on spawn, so an unpaused worker
            // can PATCH just after the DELETE below, get its 404, and re-register
            // before the premise check reads the registry -- the behaviour under
            // test racing the test's own premise. That failed once under full-
            // workspace load. Pausing first makes the premise deterministic.
            hb::set_heartbeat_paused(true);
            hb::spawn_heartbeat_worker_with_load(nf_id.to_string(), 1, || 0);

            // The NRF loses the profile.
            let resp = client.delete(&path).await.expect("DELETE");
            assert_eq!(resp.status, 204);
            assert!(
                nf_manager().get(nf_id).is_none(),
                "premise: the profile is gone"
            );

            // NES carve-out first: paused means deregistered on purpose, so the
            // deleted profile must STAY deleted across several ticks. A PATCH
            // already in flight when the pause landed gets its 404 here, which
            // also exercises the worker's re-check of the pause after the
            // response arrives.
            tokio::time::sleep(Duration::from_millis(3500)).await;
            assert!(
                nf_manager().get(nf_id).is_none(),
                "a paused (NES-deregistered) worker must not re-register"
            );

            // Unpaused, the worker's next tick gets 404 and must put it back.
            // #1334: and `/metrics` sees the loss and the re-registration.
            let lost_before = nextgcore_metrics::nf::nrf_heartbeat_count(
                nextgcore_metrics::nf::HeartbeatOutcome::NotFound,
            );
            hb::set_heartbeat_paused(false);
            let restored = nextgcore_sbi::test_support::poll_until(
                Duration::from_secs(15),
                Duration::from_millis(50),
                || async { nf_manager().get(nf_id).map(|_| ()) },
            )
            .await;
            assert_eq!(
                restored,
                Some(()),
                "a 404 heartbeat must re-register the recorded profile (#434)"
            );
            let resp = client.get(&path).await.expect("GET after re-register");
            assert_eq!(resp.status, 200, "and it must be readable through the API");
            assert!(
                nextgcore_metrics::nf::nrf_heartbeat_count(
                    nextgcore_metrics::nf::HeartbeatOutcome::NotFound
                ) > lost_before,
                "the 404 heartbeat is counted (#1334)"
            );
            // The next accepted heartbeat (1 s interval) marks it registered again.
            let registered = nextgcore_sbi::test_support::poll_until(
                Duration::from_secs(10),
                Duration::from_millis(50),
                || async { nextgcore_metrics::nf::is_nrf_registered().then_some(()) },
            )
            .await;
            assert_eq!(
                registered,
                Some(()),
                "nextgcore_nrf_registered returns to 1"
            );

            // Pause again before teardown, so no tick re-registers while the
            // globals are restored below.
            hb::set_heartbeat_paused(true);
        };

        let outcome = tokio::time::timeout(Duration::from_secs(45), body).await;

        // Restore the process-globals this test mutated. Paused stays true until
        // the profile is cleared, so a tick racing this teardown cannot
        // re-register.
        hb::clear_registered_profile();
        hb::clear_registered_nf_instance_id();
        hb::set_heartbeat_paused(false);
        let _ = nf_manager().remove_instance(nf_id);
        client.close().await;
        server.stop().await.expect("server stops");
        outcome.expect("re-registration test timed out");
    }

    // -----------------------------------------------------------------
    // SBI OAuth2 knob (T1.1): config parsing + the NRF-as-issuer rule
    // -----------------------------------------------------------------

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml = "nrf:\n  sbi:\n    oauth2:\n      require: true\n";
        let parsed: NrfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nrf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(require, "oauth2.require should parse to true");
    }

    #[test]
    fn test_yaml_oauth2_absent_defaults_off() {
        // Default config (no oauth2 block) leaves the knob off, preserving the
        // dev/E2E path and the unauthenticated token/jwks endpoints.
        let yaml = "nrf:\n  sbi:\n    server:\n      - address: 0.0.0.0\n        port: 7777\n";
        let parsed: NrfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nrf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(!require, "absent oauth2 block must default to off");
    }

    /// The NRF is the OAuth2 Authorization Server: its token endpoint must be
    /// reachable WITHOUT a bearer token. We never blanket-enable
    /// require_oauth2 on the NRF's own SBI server (no per-path exemption
    /// exists), so the token endpoint stays open even with the knob on. This
    /// guards that the default server config has require_oauth2 off.
    #[test]
    fn test_nrf_server_never_blanket_requires_oauth2() {
        let cfg = NextgcoreSbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 7777)));
        assert!(
            !cfg.require_oauth2,
            "the NRF server must not gate its own token/jwks endpoints"
        );
    }

    // -----------------------------------------------------------------
    // nrfd-02: NF_PROFILE_CHANGED on NFUpdate (TS 29.510 §5.2.2.3/§5.2.2.6)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_02_compute_changes_from_json_patch_replace() {
        use serde_json::json;
        let pre =
            json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED", "load": 40});
        let patch = json!([
            {"op": "test",    "path": "/nfStatus", "value": "REGISTERED"},
            {"op": "replace", "path": "/load",     "value": 75}
        ]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).unwrap();

        let changes = compute_profile_changes(&pre, &post, &patch, true);
        // "test" op must be filtered out — only the replace survives.
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "replace");
        assert_eq!(changes[0].path, "/load");
        assert_eq!(changes[0].value, Some(json!(75)));
        assert_eq!(changes[0].orig_value, Some(json!(40)));
    }

    #[test]
    fn test_nrfd_02_compute_changes_from_json_patch_add() {
        use serde_json::json;
        let pre = json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED"});
        let patch = json!([{"op": "add", "path": "/load", "value": 12}]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).unwrap();

        let changes = compute_profile_changes(&pre, &post, &patch, true);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "add");
        assert_eq!(changes[0].path, "/load");
        assert_eq!(changes[0].value, Some(json!(12)));
        assert!(changes[0].orig_value.is_none());
    }

    #[test]
    fn test_nrfd_02_compute_changes_from_merge_patch_replace_and_add() {
        use serde_json::json;
        let pre =
            json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED", "load": 40});
        let patch = json!({"load": 70, "priority": 3});
        let mut post = pre.clone();
        json_merge_patch(&mut post, &patch);

        let mut changes = compute_profile_changes(&pre, &post, &patch, false);
        // Sort for determinism
        changes.sort_by(|a, b| a.path.cmp(&b.path));

        assert_eq!(changes.len(), 2);
        let load = changes.iter().find(|c| c.path == "/load").unwrap();
        assert_eq!(load.op, "replace");
        assert_eq!(load.value, Some(json!(70)));
        assert_eq!(load.orig_value, Some(json!(40)));

        let prio = changes.iter().find(|c| c.path == "/priority").unwrap();
        assert_eq!(prio.op, "add");
        assert_eq!(prio.value, Some(json!(3)));
        assert!(prio.orig_value.is_none());
    }

    #[test]
    fn test_nrfd_02_compute_changes_from_merge_patch_null_is_remove() {
        use serde_json::json;
        let pre = json!({"nfInstanceId": "a", "nfType": "SMF", "nfStatus": "REGISTERED", "fqdn": "smf.example.com"});
        let patch = json!({"fqdn": null});
        let mut post = pre.clone();
        json_merge_patch(&mut post, &patch);

        let changes = compute_profile_changes(&pre, &post, &patch, false);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "remove");
        assert_eq!(changes[0].path, "/fqdn");
        assert_eq!(changes[0].orig_value, Some(json!("smf.example.com")));
        assert!(changes[0].value.is_none());
    }

    /// Register an NF + a matching subscriber, apply a load PATCH via the
    /// sync notify path, and assert that NF_PROFILE_CHANGED with the correct
    /// `profileChanges` payload is dispatched to the subscriber.
    #[test]
    fn test_nrfd_02_profile_changed_notify_dispatched_on_patch() {
        use nextgcore_nrfd::nnrf_handler::SubscrCond;
        use nextgcore_nrfd::{nrf_nnrf_nfm_send_nf_profile_changed_notify_all, SubscriptionData};
        use serde_json::json;

        // Build an NF profile.
        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": "nrfd02-test-nf-01",
            "nfType": "SMF",
            "nfStatus": "REGISTERED",
            "load": 40,
        }))
        .unwrap();

        // Build a subscription that matches this NF type.
        let subscription = SubscriptionData {
            id: "nrfd02-sub-01".to_string(),
            req_nf_type: Some("AMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://amf.example.com/nrfd02/notify".to_string(),
            subscr_cond: Some(SubscrCond::nf_type("SMF")),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
            owner: None,
        };

        // Simulate a PATCH replacing /load.
        let pre = profile.to_json();
        let patch = json!([{"op": "replace", "path": "/load", "value": 75}]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).unwrap();
        let updated = NfProfile::from_json(&post).unwrap();

        let changes = compute_profile_changes(&pre, &post, &patch, true);
        assert_eq!(changes.len(), 1, "one change item for /load replace");

        // Dispatch via the sync stub (no real HTTP, always returns Success).
        let result = nrf_nnrf_nfm_send_nf_profile_changed_notify_all(
            &updated,
            "http://nrf.example.com",
            &[subscription],
            changes,
        );
        assert!(result.is_ok(), "dispatch must succeed: {result:?}");
        assert_eq!(result.unwrap(), 1, "exactly one notification dispatched");
    }

    /// Issue #22 NES: a PATCH that itself sets nfStatus=SUSPENDED is a
    /// self-suspension and must NOT be treated as a reactivating heartbeat;
    /// ordinary heartbeat/load patches still reactivate.
    #[test]
    fn test_nes_self_suspension_detection() {
        use serde_json::json;

        // RFC 6902 self-suspension (the NES heartbeat shape).
        let suspend = json!([
            {"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"},
            {"op": "add",     "path": "/load",     "value": 0}
        ]);
        assert!(patch_requests_self_suspension(&suspend, true));

        // Ordinary heartbeat (REGISTERED) — reactivation stays allowed.
        let heartbeat = json!([
            {"op": "replace", "path": "/nfStatus", "value": "REGISTERED"},
            {"op": "add",     "path": "/load",     "value": 12}
        ]);
        assert!(!patch_requests_self_suspension(&heartbeat, true));

        // Load-only patch — not a self-suspension.
        let load_only = json!([{"op": "replace", "path": "/load", "value": 50}]);
        assert!(!patch_requests_self_suspension(&load_only, true));

        // Merge-patch object form.
        let merge = json!({"nfStatus": "SUSPENDED"});
        assert!(patch_requests_self_suspension(&merge, false));
        let merge_reg = json!({"nfStatus": "REGISTERED", "load": 3});
        assert!(!patch_requests_self_suspension(&merge_reg, false));
    }

    /// Assert that the SUSPENDED→REGISTERED reactivate path produces a
    /// NF_PROFILE_CHANGED ChangeItem with nfStatus replace op.
    #[test]
    fn test_nrfd_02_reactivate_change_item_shape() {
        use serde_json::json;

        // The reactivate path in handle_nf_update always constructs this fixed ChangeItem.
        let reactivate_changes = vec![ChangeItem {
            op: "replace".to_string(),
            path: "/nfStatus".to_string(),
            value: Some(json!("REGISTERED")),
            orig_value: Some(json!("SUSPENDED")),
        }];

        assert_eq!(reactivate_changes[0].op, "replace");
        assert_eq!(reactivate_changes[0].path, "/nfStatus");
        assert_eq!(reactivate_changes[0].value, Some(json!("REGISTERED")));
        assert_eq!(reactivate_changes[0].orig_value, Some(json!("SUSPENDED")));

        // Verify it serializes correctly into a NF_PROFILE_CHANGED body.
        use nextgcore_nrfd::nnrf_handler::SubscrCond;
        use nextgcore_nrfd::{nrf_nnrf_nfm_build_nf_profile_changed_notify, SubscriptionData};

        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": "nrfd02-reactivate-nf",
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
        }))
        .unwrap();

        let subscription = SubscriptionData {
            id: "nrfd02-reactivate-sub".to_string(),
            req_nf_type: Some("SMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://smf.example.com/nrfd02/notify".to_string(),
            subscr_cond: Some(SubscrCond::nf_type("AMF")),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
            owner: None,
        };

        let request = nrf_nnrf_nfm_build_nf_profile_changed_notify(
            &subscription,
            &profile,
            "http://nrf.example.com",
            reactivate_changes,
        )
        .expect("builder must produce a request");

        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["event"], "NF_PROFILE_CHANGED");
        let pc = body["profileChanges"].as_array().unwrap();
        assert_eq!(pc.len(), 1);
        assert_eq!(pc[0]["op"], "replace");
        assert_eq!(pc[0]["path"], "/nfStatus");
        assert_eq!(pc[0]["newValue"], "REGISTERED");
        assert_eq!(pc[0]["origValue"], "SUSPENDED");
    }

    // -----------------------------------------------------------------
    // nrfd-03: heartBeatTimer negotiation (TS 29.510 Table 6.1.6.2.2-1)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_03_negotiate_heartbeat() {
        // In-range proposal is reused.
        assert_eq!(negotiate_heartbeat(Some(30), 10, 1, 3600), 30);
        // Absent proposal -> preconfigured default.
        assert_eq!(negotiate_heartbeat(None, 10, 1, 3600), 10);
        // Out-of-range (below min / above max) -> overridden to default.
        assert_eq!(negotiate_heartbeat(Some(0), 10, 1, 3600), 10);
        assert_eq!(negotiate_heartbeat(Some(99999), 10, 1, 3600), 10);
        // The supervision timer is armed at 2x the negotiated value.
        let hb = negotiate_heartbeat(None, 10, 1, 3600);
        assert_eq!((hb as u64) * 2, 20);
    }

    /// R32 on #1957 M1: a profile declaring more range patterns than the cap
    /// is refused 400 with `invalidParams` and nothing is stored; at the cap it
    /// registers. REVERT-VERIFIED: with the `refuse_range_patterns` call removed
    /// from NFRegister, the over-cap profile answers 201.
    #[tokio::test]
    async fn a_profile_over_the_range_pattern_cap_is_refused_1879() {
        use serde_json::json;
        let profile = |id: &str, n: usize| {
            let ranges: Vec<serde_json::Value> = (0..n)
                .map(|k| json!({ "pattern": format!("imsi-00101{k:04}[0-9]+") }))
                .collect();
            json!({
                "nfInstanceId": id, "nfType": "UDM", "nfStatus": "REGISTERED",
                "udmInfo": { "supiRanges": ranges },
            })
        };
        let register = |id: &'static str, body: serde_json::Value| async move {
            let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"));
            req.http.set_content(body.to_string());
            req.peer_cert_nf_instance_id = Some(id.into());
            req.peer_cert_nf_types = vec!["UDM".into()];
            handle_nf_register(id, &req).await
        };
        let over = "aaaaaaaa-1879-4000-8000-000000000065";
        let resp = register(
            over,
            profile(
                over,
                nextgcore_nrfd::nnrf_handler::MAX_RANGE_PATTERNS_PER_PROFILE + 1,
            ),
        )
        .await;
        assert_eq!(resp.status, 400, "{:?}", resp.http.content);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["invalidParams"][0]["param"],
            "/udmInfo/supiRanges/64/pattern"
        );
        assert!(nf_manager().get(over).is_none(), "nothing stored");
        let at = "aaaaaaaa-1879-4000-8000-000000000064";
        let resp = register(
            at,
            profile(
                at,
                nextgcore_nrfd::nnrf_handler::MAX_RANGE_PATTERNS_PER_PROFILE,
            ),
        )
        .await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
    }

    #[tokio::test]
    async fn test_nrfd_03_register_returns_negotiated_heartbeat() {
        use serde_json::json;
        let id = "nrfd03-reg-nf-01";
        // Register WITHOUT a heartBeatTimer: the 201 body must carry the
        // NRF default and a supervision timer must be armed.
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"));
        req.http.set_content(
            json!({"nfInstanceId": id, "nfType": "SMF", "nfStatus": "REGISTERED"}).to_string(),
        );
        req.peer_cert_nf_instance_id = Some(id.into());
        req.peer_cert_nf_types = vec!["SMF".into()];
        let resp = handle_nf_register(id, &req).await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["heartBeatTimer"], NRF_HEARTBEAT_DEFAULT);
        assert!(
            HEARTBEAT_TIMERS.lock().unwrap().contains_key(id),
            "registration must arm the supervision timer from the negotiated value"
        );

        // An out-of-range proposal is overridden to the default in the
        // stored AND returned profile.
        let id2 = "nrfd03-reg-nf-02";
        let mut req2 = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id2}"));
        req2.http.set_content(
            json!({"nfInstanceId": id2, "nfType": "SMF", "nfStatus": "REGISTERED",
                   "heartBeatTimer": 99999})
            .to_string(),
        );
        req2.peer_cert_nf_instance_id = Some(id2.into());
        req2.peer_cert_nf_types = vec!["SMF".into()];
        let resp2 = handle_nf_register(id2, &req2).await;
        let body2: serde_json::Value =
            serde_json::from_str(resp2.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body2["heartBeatTimer"], NRF_HEARTBEAT_DEFAULT);

        nf_manager().deregister(id).ok();
        nf_manager().deregister(id2).ok();
        disarm_heartbeat_timer(id);
        disarm_heartbeat_timer(id2);
    }

    // -----------------------------------------------------------------
    // nrfd-04: conditional AccessTokenReq IEs (TS 29.510 Table 6.3.5.2.2-1)
    // -----------------------------------------------------------------

    /// #1753: the #1751 attack. A provisioned NF registers a profile whose nfType
    /// is outside the TS 29.510 enum (`EES`), offering a service only to itself,
    /// and asks for a token with `targetNfType: EES`. NFRegister still accepts
    /// the profile (NFType is extensible, TS 29.501 §5.3.12), but no token whose
    /// `aud` is `EES` is issued: 400 `invalid_request`. A pinned instance gets a
    /// token whose `aud` is that instance, and a real type is served as before.
    ///
    /// REVERT-VERIFIED: with the #1753 check removed, the `EES` request is 200
    /// with `aud: "EES"`, and the first assertion names it.
    /// R26 on #1922: the real token endpoint, end to end. A PCF names the slice
    /// of a permissive UDR in `requesterSnssaiList`. While that UDR is the only
    /// one registered, the K-read scope is granted (the control: no stray UDR
    /// is refusing it). Once a standard UDR is registered too, SUSPENDED and on
    /// another slice, it still accepts the aud=UDR token, so the scope is
    /// withheld.
    ///
    /// REVERT-VERIFIED: with the handler passing `&producers` instead of
    /// `&acceptors` to `authorize_access_token_for` (the pre-R26 call), the
    /// second request is granted the K-read scope and the second assertion fails.
    /// **#1964.** A type-targeted token that carries a resource scope is pinned
    /// to the producers the scope was evaluated over: its `aud` is their NF
    /// instance IDs, so a producer that registers later (or a legitimate one
    /// while only a rogue was registered at mint time) does not accept it. A
    /// token with only the service scope keeps `aud` the NF type.
    ///
    /// REVERT-VERIFIED: with `pin_audience_to_acceptors` returning early always,
    /// the resource-scoped token's `aud` is "UDR" and the first assertion fails.
    #[tokio::test]
    async fn a_resource_scoped_token_is_pinned_to_its_evaluated_producers_1964() {
        use serde_json::json;
        // An NF type no other test registers, so the acceptor set is exactly the
        // producer registered here.
        const READ: &str = "nnssaaf-nssaa:test-1964";
        let mgr = nf_manager();
        let udm_id = "19640000-0000-4000-8000-0000000000d1";
        let udr_id = "19640000-0000-4000-8000-0000000000a1"; // the NSSAAF
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": udm_id, "nfType": "UDM", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": udr_id, "nfType": "NSSAAF", "nfStatus": "REGISTERED",
                "nfServices": [{
                    "serviceInstanceId": "nssaaf-1964", "serviceName": "nnssaaf-nssaa",
                    "allowedNfTypes": ["UDM"],
                    "allowedOperationsPerNfType": { "UDM": ["nnssaaf-nssaa", READ] }
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        let policy = policy_without_client_auth();
        let ask = |scope: &str| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(
                json!({
                    "grant_type": "client_credentials", "nfInstanceId": udm_id,
                    "nfType": "UDM", "targetNfType": "NSSAAF", "scope": scope,
                })
                .to_string(),
            );
            r
        };
        let token_claims = |resp: &SbiResponse| -> serde_json::Value {
            use base64::Engine;
            assert_eq!(resp.status, 200, "{:?}", resp.http.content);
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let token = body["access_token"].as_str().expect("access_token");
            let payload = token.split('.').nth(1).expect("payload");
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .expect("base64url"),
            )
            .expect("claims JSON")
        };

        let pinned = token_claims(
            &handle_access_token_request_with_policy(
                &ask(&format!("nnssaaf-nssaa {READ}")),
                &policy,
            )
            .await,
        );
        assert!(
            pinned["scope"].as_str().unwrap_or_default().contains(READ),
            "control: the resource scope is granted ({})",
            pinned["scope"]
        );
        assert_eq!(
            pinned["aud"],
            json!([udr_id]),
            "a resource-scoped token is pinned to the producer it was evaluated over"
        );

        let service_only = token_claims(
            &handle_access_token_request_with_policy(&ask("nnssaaf-nssaa"), &policy).await,
        );
        assert_eq!(
            service_only["aud"],
            json!("NSSAAF"),
            "a service-scope token keeps the NF-type audience"
        );

        for id in [udm_id, udr_id] {
            mgr.deregister(id).ok();
        }
    }

    #[tokio::test]
    async fn the_token_endpoint_withholds_k_read_when_any_udr_would_refuse_it_1828() {
        use serde_json::json;
        const READ: &str = "nudr-dr:subscription-data:authentication-subscription:read";
        let mgr = nf_manager();
        let pcf_id = "18280000-0000-4000-8000-0000000000f1";
        let permissive_id = "18280000-0000-4000-8000-0000000000a1";
        let standard_id = "18280000-0000-4000-8000-0000000000a2";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": pcf_id, "nfType": "PCF", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        let udr = |id: &str, pcf_scopes: serde_json::Value, sst: u64, status: &str| {
            NfProfile::from_json(&json!({
                "nfInstanceId": id, "nfType": "UDR", "nfStatus": status,
                "sNssais": [{"sst": sst, "sd": "182800"}],
                "nfServices": [{
                    "serviceInstanceId": "udr-dr", "serviceName": "nudr-dr",
                    "allowedNfTypes": ["UDM", "PCF"],
                    "allowedOperationsPerNfType": {
                        "UDM": ["nudr-dr", READ],
                        "PCF": pcf_scopes
                    }
                }],
            }))
            .unwrap()
        };
        mgr.register(udr(
            permissive_id,
            json!(["nudr-dr", READ]),
            99,
            "REGISTERED",
        ))
        .unwrap();

        let policy = policy_without_client_auth();
        let ask = || {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(
                json!({
                    "grant_type": "client_credentials", "nfInstanceId": pcf_id,
                    "nfType": "PCF", "targetNfType": "UDR",
                    "scope": format!("nudr-dr {READ}"),
                    "requesterSnssaiList": [{"sst": 99, "sd": "182800"}],
                })
                .to_string(),
            );
            r
        };
        let granted_scope = |resp: &SbiResponse| -> String {
            assert_eq!(resp.status, 200, "{:?}", resp.http.content);
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            body["scope"].as_str().unwrap_or_default().to_string()
        };

        let alone = granted_scope(&handle_access_token_request_with_policy(&ask(), &policy).await);
        assert!(
            alone.split(' ').any(|s| s == READ),
            "control: the permissive UDR alone grants it ({alone:?})"
        );

        // SUSPENDED (missed heartbeats) and on another slice: out of the
        // operative, requester-filtered set, yet it accepts the token once it
        // resumes.
        mgr.register(udr(standard_id, json!(["nudr-dr"]), 1, "SUSPENDED"))
            .unwrap();
        let both = granted_scope(&handle_access_token_request_with_policy(&ask(), &policy).await);
        assert!(
            !both.split(' ').any(|s| s == READ),
            "the suspended standard UDR accepts the aud=UDR token too, whatever slice the \
             PCF named, so no K-read scope ({both:?})"
        );
        assert!(both.split(' ').any(|s| s == "nudr-dr"), "{both:?}");

        for id in [pcf_id, permissive_id, standard_id] {
            mgr.deregister(id).ok();
        }
    }

    #[tokio::test]
    async fn no_token_is_issued_for_a_target_type_outside_ts29510_1753() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfd1753-consumer";
        let rogue_id = "1753aaaa-0000-4000-8000-000000000001";
        let real_id = "1753aaaa-0000-4000-8000-000000000002";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFD1753C", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        // NFRegister itself accepts the extensible value.
        let profile = |id: &str, nf_type: &str| {
            json!({
                "nfInstanceId": id, "nfType": nf_type, "nfStatus": "REGISTERED",
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd1753-svc",
                                "allowedNfTypes": ["NRFD1753C"]}],
            })
        };
        let mut put = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{rogue_id}"));
        put.http.set_content(profile(rogue_id, "EES").to_string());
        put.peer_cert_nf_instance_id = Some(rogue_id.into());
        put.peer_cert_nf_types = vec!["EES".into()];
        let resp = handle_nf_register(rogue_id, &put).await;
        assert_eq!(
            resp.status, 201,
            "an unknown nfType still registers: {:?}",
            resp.http.content
        );
        // Control producer of a TS 29.510 type no other test registers.
        mgr.register(NfProfile::from_json(&profile(real_id, "MRFP")).unwrap())
            .unwrap();

        let policy = policy_without_client_auth();
        let ask = |target: serde_json::Value| {
            let mut body = json!({
                "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                "nfType": "NRFD1753C", "scope": "nrfd1753-svc"
            });
            body.as_object_mut()
                .unwrap()
                .extend(target.as_object().unwrap().clone());
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(body.to_string());
            r
        };
        let claims = |resp: &SbiResponse| -> serde_json::Value {
            use base64::Engine;
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let token = body["access_token"].as_str().unwrap().to_string();
            let payload = token.split('.').nth(1).unwrap().to_string();
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .unwrap(),
            )
            .unwrap()
        };

        for target in ["EES", "ees"] {
            let resp = handle_access_token_request_with_policy(
                &ask(json!({"targetNfType": target})),
                &policy,
            )
            .await;
            assert_eq!(resp.status, 400, "{target}: {:?}", resp.http.content);
            let err: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(err["error"], "invalid_request", "{err}");
            assert!(
                err["error_description"]
                    .as_str()
                    .is_some_and(|d| d.contains("is not a TS 29.510 NFType")),
                "{err}"
            );
        }

        // The same rogue profile pinned by instance: aud names that instance only.
        let resp = handle_access_token_request_with_policy(
            &ask(json!({"targetNfInstanceId": rogue_id})),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        assert_eq!(claims(&resp)["aud"], json!([rogue_id]));

        // Control: a TS 29.510 type is served, aud = the type.
        let resp =
            handle_access_token_request_with_policy(&ask(json!({"targetNfType": "MRFP"})), &policy)
                .await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        assert_eq!(claims(&resp)["aud"], "MRFP");

        for id in [consumer_id, rogue_id, real_id] {
            mgr.deregister(id).ok();
        }
    }

    /// #1753: the list is the vendored enum, exactly. Pinned against the
    /// TS29510_Nnrf_NFManagement.yaml `NFType` values (29510-k00), with this
    /// tree's non-3GPP spellings as controls.
    #[test]
    fn the_ts29510_nf_type_list_is_the_vendored_enum_1753() {
        assert_eq!(TS29510_NF_TYPES.len(), 68);
        let mut seen = std::collections::HashSet::new();
        assert!(
            TS29510_NF_TYPES.iter().all(|t| seen.insert(*t)),
            "duplicates"
        );
        for t in [
            "MB_SMF", "mb_smf", "5G_EIR", "NRF", "SENF", "ADM", "AF", "EASDF",
        ] {
            assert!(is_ts29510_nf_type(t), "{t}");
        }
        for t in ["EES", "MBSMF", "SMSF_5G", "", "NRFD04P"] {
            assert!(!is_ts29510_nf_type(t), "{t}");
        }
    }

    #[tokio::test]
    async fn test_nrfd_04_target_instance_and_requester_snssai() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfd04-consumer";
        let producer_id = "nrfd04-producer";
        // Unique NF types so no other test's producers pollute the decision.
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFD04C", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "RH", "nfStatus": "REGISTERED",
                "sNssais": [{"sst": 1, "sd": "010203"}],
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd04-svc"}],
            }))
            .unwrap(),
        )
        .unwrap();

        let token_req = |body: serde_json::Value| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(body.to_string());
            r
        };
        // This test's subject is target resolution and scope, not authentication,
        // so it runs with the documented opt-out. Authentication itself is covered
        // by the issue #64 tests further down.
        let policy = policy_without_client_auth();

        // (a) Only targetNfInstanceId (no targetNfType) -> succeeds.
        let resp = handle_access_token_request_with_policy(
            &token_req(json!({
                "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                "nfType": "NRFD04C", "targetNfInstanceId": producer_id, "scope": "nrfd04-svc"
            })),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "instance-scoped token: {:?}",
            resp.http.content
        );

        // (b) Neither targetNfType nor targetNfInstanceId -> invalid_request.
        let resp = handle_access_token_request_with_policy(
            &token_req(json!({
                "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                "nfType": "NRFD04C", "scope": "nrfd04-svc"
            })),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 400);
        let err: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(err["error"], "invalid_request");

        // (c) requesterSnssaiList that no producer serves -> invalid_scope.
        let resp = handle_access_token_request_with_policy(
            &token_req(json!({
                "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                "nfType": "NRFD04C", "targetNfType": "RH", "scope": "nrfd04-svc",
                "requesterSnssaiList": [{"sst": 9}]
            })),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 400);
        let err: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(err["error"], "invalid_scope");

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
    }

    /// Issue #1391, on the real token handler and real registry: the three
    /// states a producer of the target type can be in, in the order a startup
    /// race walks through them. Before the fix step (1) returned a token, which
    /// then outlived the restrictive `allowedNfTypes` of step (2).
    #[tokio::test]
    async fn test_1391_token_fails_closed_until_a_producer_authorizes_it() {
        use serde_json::json;
        let mgr = nf_manager();
        // Unique ids and NF types: the registry is process-global.
        let consumer_id = "nrfd1391-consumer";
        let producer_id = "nrfd1391-producer";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFD1391C", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        let producer = |allowed: serde_json::Value| {
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "EIF", "nfStatus": "REGISTERED",
                "allowedNfTypes": allowed,
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd1391-svc"}],
            }))
            .unwrap()
        };
        let mut req = SbiRequest::post("/nnrf-oauth2/v1/access-token");
        req.http.set_content(
            json!({
                "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                "nfType": "NRFD1391C", "targetNfType": "EIF", "scope": "nrfd1391-svc"
            })
            .to_string(),
        );
        // Authentication is covered by the issue #64 tests; this one is about
        // the authorization decision only.
        let policy = policy_without_client_auth();
        let body = |resp: &SbiResponse| -> serde_json::Value {
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap()
        };

        // (1) No producer of the target type registered -> invalid_scope, no token.
        let resp = handle_access_token_request_with_policy(&req, &policy).await;
        let b = body(&resp);
        assert_eq!(resp.status, 400, "no producer: {b}");
        assert_eq!(b["error"], "invalid_scope", "no producer: {b}");
        assert!(b.get("access_token").is_none(), "no producer: {b}");

        // (2) The producer registers barring the consumer's type -> unauthorized_client.
        mgr.register(producer(json!(["AMF"]))).unwrap();
        let resp = handle_access_token_request_with_policy(&req, &policy).await;
        let b = body(&resp);
        assert_eq!(resp.status, 400, "barred: {b}");
        assert_eq!(b["error"], "unauthorized_client", "barred: {b}");
        assert!(b.get("access_token").is_none(), "barred: {b}");

        // (3) The producer allows the consumer's type -> a token for that scope.
        mgr.deregister(producer_id).ok();
        mgr.register(producer(json!(["AMF", "NRFD1391C"]))).unwrap();
        let resp = handle_access_token_request_with_policy(&req, &policy).await;
        let b = body(&resp);
        assert_eq!(resp.status, 200, "allowed: {b}");
        assert_eq!(b["scope"], "nrfd1391-svc", "allowed: {b}");
        assert_eq!(
            b["access_token"].as_str().unwrap().split('.').count(),
            3,
            "allowed: {b}"
        );

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
    }

    /// Issue #1391, second route: an unregistered `targetNfInstanceId` with no
    /// `targetNfType` used to fall through to a type filter on the empty string,
    /// match no producer, and reach the conservative grant. It is refused
    /// `invalid_scope` with no token, and so is the same id alongside a
    /// `targetNfType` that does have a permitting producer: pinning an instance
    /// that does not exist must not widen to "any producer of the type".
    #[tokio::test]
    async fn test_1391_unregistered_target_instance_is_invalid_scope() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfd1391b-consumer";
        let producer_id = "nrfd1391b-producer";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFD1391BC", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "AIOTF", "nfStatus": "REGISTERED",
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd1391b-svc"}],
            }))
            .unwrap(),
        )
        .unwrap();
        let policy = policy_without_client_auth();
        let ask = |body: serde_json::Value| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(body.to_string());
            r
        };
        let absent = "00000000-1391-4000-8000-000000000000";

        for body in [
            json!({"grant_type": "client_credentials", "nfInstanceId": consumer_id,
                   "nfType": "NRFD1391BC", "targetNfInstanceId": absent,
                   "scope": "nrfd1391b-svc"}),
            json!({"grant_type": "client_credentials", "nfInstanceId": consumer_id,
                   "nfType": "NRFD1391BC", "targetNfInstanceId": absent,
                   "targetNfType": "AIOTF", "scope": "nrfd1391b-svc"}),
        ] {
            let resp = handle_access_token_request_with_policy(&ask(body.clone()), &policy).await;
            let b: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(resp.status, 400, "{body} -> {b}");
            assert_eq!(b["error"], "invalid_scope", "{body} -> {b}");
            assert!(b.get("access_token").is_none(), "{body} -> {b}");
        }

        // Control: the same producer pinned by its REAL id is granted, so the
        // refusals above are about the absent instance and nothing else.
        let resp = handle_access_token_request_with_policy(
            &ask(
                json!({"grant_type": "client_credentials", "nfInstanceId": consumer_id,
                        "nfType": "NRFD1391BC", "targetNfInstanceId": producer_id,
                        "scope": "nrfd1391b-svc"}),
            ),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
    }

    /// Issue #1391 review: two more ways a producer could vouch for a scope it
    /// should not. (a) A pinned instance of a DIFFERENT type than the explicit
    /// `targetNfType` is `invalid_request` (the selectors contradict). (b) A
    /// SUSPENDED producer is "not operative" (TS 29.510 Table 6.1.6.3.7-1), so it
    /// authorizes nothing, pinned or by type; REGISTERED, UNDISCOVERABLE and
    /// CANARY_RELEASE are operative and are granted.
    #[tokio::test]
    async fn test_1391_mismatched_or_suspended_producer_does_not_authorize() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfd1391c-consumer";
        let producer_id = "nrfd1391c-producer";
        let other_id = "nrfd1391c-other";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFD1391CC", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        let producer = |status: &str| {
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "ADM", "nfStatus": status,
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd1391c-svc"}],
            }))
            .unwrap()
        };
        mgr.register(producer("REGISTERED")).unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": other_id, "nfType": "NRFD1391CO", "nfStatus": "REGISTERED",
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfd1391c-svc"}],
            }))
            .unwrap(),
        )
        .unwrap();
        let policy = policy_without_client_auth();
        let ask = |body: serde_json::Value| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(body.to_string());
            r
        };
        let base = json!({"grant_type": "client_credentials", "nfInstanceId": consumer_id,
                          "nfType": "NRFD1391CC", "scope": "nrfd1391c-svc"});
        let with = |extra: serde_json::Value| {
            let mut b = base.clone();
            b.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            b
        };
        let call = |body: serde_json::Value| {
            let req = ask(body);
            let policy = &policy;
            async move {
                let resp = handle_access_token_request_with_policy(&req, policy).await;
                let b: serde_json::Value =
                    serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
                (resp.status, b)
            }
        };

        // (a) Pinned instance is an NRFD1391CO, the request says ADM.
        let (st, b) = call(with(
            json!({"targetNfInstanceId": other_id, "targetNfType": "ADM"}),
        ))
        .await;
        assert_eq!(
            (st, b["error"].as_str()),
            (400, Some("invalid_request")),
            "{b}"
        );
        assert!(b.get("access_token").is_none(), "{b}");

        // (b) The only ADM producer is SUSPENDED: by type and pinned.
        mgr.deregister(producer_id).ok();
        mgr.register(producer("SUSPENDED")).unwrap();
        for extra in [
            json!({"targetNfType": "ADM"}),
            json!({"targetNfInstanceId": producer_id}),
        ] {
            let (st, b) = call(with(extra.clone())).await;
            assert_eq!(
                (st, b["error"].as_str()),
                (400, Some("invalid_scope")),
                "{extra} -> {b}"
            );
            assert!(b.get("access_token").is_none(), "{extra} -> {b}");
        }

        // Control: every OPERATIVE status (TS 29.510 Table 6.1.6.3.7-1) is
        // granted in both shapes. UNDISCOVERABLE is operative and still serves
        // consumers already bound to it, so their token refresh must work.
        for status in ["REGISTERED", "UNDISCOVERABLE", "CANARY_RELEASE"] {
            mgr.deregister(producer_id).ok();
            mgr.register(producer(status)).unwrap();
            for extra in [
                json!({"targetNfType": "ADM"}),
                json!({"targetNfInstanceId": producer_id}),
            ] {
                let (st, b) = call(with(extra.clone())).await;
                assert_eq!(st, 200, "{status} {extra} -> {b}");
            }
        }

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
        mgr.deregister(other_id).ok();
    }

    // -----------------------------------------------------------------
    // nrfd-05: CCA client-authentication binding (TS 29.510 §6.7.5)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_05_verify_cca_binding() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use serde_json::json;

        let now = 1_000_000u64;
        // Encode arbitrary CCA claims into a placeholder-signed JWT (signature
        // verification is FLAGGED; this function checks the claim binding + iat/aud).
        let encode_cca = |claims: serde_json::Value| -> String {
            let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
            let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
            format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(b"sig"))
        };
        // Conformant CCA defaults: iat=now, aud="NRF" (the NRF's own NF type).
        let cca = |sub: &str, iss: Option<&str>, exp: Option<u64>| -> String {
            let mut claims = json!({ "sub": sub, "iat": now, "aud": "NRF" });
            if let Some(i) = iss {
                claims["iss"] = json!(i);
            }
            if let Some(e) = exp {
                claims["exp"] = json!(e);
            }
            encode_cca(claims)
        };

        // Matching subject + issuer, not expired, iat present, aud NRF -> Ok.
        assert!(
            verify_cca_binding(&cca("nf-1", Some("nf-1"), Some(now + 100)), "nf-1", now).is_ok()
        );
        // Subject mismatch -> invalid_client.
        assert_eq!(
            verify_cca_binding(&cca("nf-2", None, None), "nf-1", now)
                .unwrap_err()
                .0,
            "invalid_client"
        );
        // Expired -> invalid_client.
        assert_eq!(
            verify_cca_binding(&cca("nf-1", None, Some(now - 1)), "nf-1", now)
                .unwrap_err()
                .0,
            "invalid_client"
        );
        // Malformed (not a 3-part JWT) -> invalid_client.
        assert_eq!(
            verify_cca_binding("not-a-jwt", "nf-1", now).unwrap_err().0,
            "invalid_client"
        );
        // TS 33.501 §13.3.8.3 hardening: missing iat -> invalid_client.
        assert_eq!(
            verify_cca_binding(
                &encode_cca(json!({ "sub": "nf-1", "aud": "NRF", "exp": now + 100 })),
                "nf-1",
                now
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );
        // Future-dated iat (beyond skew) -> invalid_client.
        assert_eq!(
            verify_cca_binding(
                &encode_cca(json!({ "sub": "nf-1", "aud": "NRF", "iat": now + 10_000 })),
                "nf-1",
                now
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );
        // Audience not the NRF -> invalid_client.
        assert_eq!(
            verify_cca_binding(
                &encode_cca(json!({ "sub": "nf-1", "aud": "UDM", "iat": now })),
                "nf-1",
                now
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );
        // aud as an array containing NRF -> Ok.
        assert!(verify_cca_binding(
            &encode_cca(json!({ "sub": "nf-1", "aud": ["UDM", "NRF"], "iat": now })),
            "nf-1",
            now
        )
        .is_ok());
    }

    // -----------------------------------------------------------------
    // I1: CCA ES256 JWS signature verification (TS 33.501 §13.3.8.3)
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_i1_verify_cca_signature() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        // Deterministic P-256 signer (fixed scalar, well below the group order).
        let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("valid P-256 scalar");
        let vk = sk.verifying_key().to_owned();

        // Produce a real ES256 JWS over base64url(header).base64url(payload).
        let sign = |header_json: &[u8], payload_json: &[u8]| -> String {
            let h = URL_SAFE_NO_PAD.encode(header_json);
            let p = URL_SAFE_NO_PAD.encode(payload_json);
            let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
            format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
        };

        let header = br#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = br#"{"sub":"nf-1","iss":"nf-1","aud":"NRF","iat":1000000}"#;

        // A correctly-signed CCA verifies against the matching public key.
        let cca = sign(header, payload);
        assert!(verify_cca_signature(&cca, &vk).is_ok());

        let parts: Vec<&str> = cca.split('.').collect();

        // Tampered payload (forged claims, original signature) -> rejected: this
        // is exactly the forged-CCA the audit flagged as accepted.
        let forged_payload = URL_SAFE_NO_PAD
            .encode(br#"{"sub":"attacker","iss":"attacker","aud":"NRF","iat":1000000}"#);
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert_eq!(
            verify_cca_signature(&forged, &vk).unwrap_err().0,
            "invalid_client"
        );

        // Valid signature but WRONG (untrusted) key -> rejected.
        let other = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        assert_eq!(
            verify_cca_signature(&cca, other.verifying_key())
                .unwrap_err()
                .0,
            "invalid_client"
        );

        // alg=none downgrade -> rejected before any crypto (algorithm-substitution).
        let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let none_jwt = format!("{}.{}.{}", none_header, parts[1], parts[2]);
        assert_eq!(
            verify_cca_signature(&none_jwt, &vk).unwrap_err().0,
            "invalid_client"
        );

        // Malformed signature bytes (wrong length) -> rejected.
        let bad_sig = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode(b"short")
        );
        assert_eq!(
            verify_cca_signature(&bad_sig, &vk).unwrap_err().0,
            "invalid_client"
        );

        // Not a well-formed 3-part JWT -> rejected.
        assert_eq!(
            verify_cca_signature("a.b", &vk).unwrap_err().0,
            "invalid_client"
        );
    }

    #[test]
    fn test_nrfd_i1_from_yaml_cca_signature_config() {
        // RFC 7515 Appendix A.3.1 P-256 public key — a valid EC/P-256 JWK.
        let yaml_str = "nrf:\n  sbi:\n    oauth2:\n      cca_verify_signature: true\n      \
             cca_trusted_keys:\n        - nfInstanceId: nf-1\n          jwk:\n            \
             kty: EC\n            crv: P-256\n            \
             x: f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\n            \
             y: x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\n";
        let yaml: NrfYaml = serde_yaml::from_str(yaml_str).expect("parse yaml");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(policy.cca_verify_signature);
        assert!(policy.cca_trusted_keys.contains_key("nf-1"));

        // A malformed JWK entry is dropped, not fatal — the issuer then has no
        // trusted key and its CCA is rejected at runtime (fail-closed).
        let bad = "nrf:\n  sbi:\n    oauth2:\n      cca_verify_signature: true\n      \
             cca_trusted_keys:\n        - nfInstanceId: nf-2\n          jwk:\n            \
             kty: EC\n            crv: P-256\n            x: not-valid\n            y: not-valid\n";
        let yaml2: NrfYaml = serde_yaml::from_str(bad).expect("parse yaml");
        let policy2 = NrfPolicy::from_yaml(&yaml2);
        assert!(policy2.cca_verify_signature);
        assert!(!policy2.cca_trusted_keys.contains_key("nf-2"));

        // Issue #64 gap 2: signature verification defaults ON, with an EMPTY trust
        // store — so a CCA from an unknown issuer is rejected rather than accepted
        // unverified. The two together are what make the default fail-closed.
        let def = NrfPolicy::default();
        assert!(def.cca_verify_signature);
        assert!(def.cca_trusted_keys.is_empty());

        // An explicitly-disabled knob is honoured (the documented opt-out).
        let off: NrfYaml =
            serde_yaml::from_str("nrf:\n  sbi:\n    oauth2:\n      cca_verify_signature: false\n")
                .expect("parse yaml");
        assert!(!NrfPolicy::from_yaml(&off).cca_verify_signature);
    }

    // -----------------------------------------------------------------
    // I2: token-requester transport auth (mTLS/CCA binding) — TS 33.501
    // §13.3.1/§13.4.1, TS 33.310 (NF Instance ID in cert URI SAN),
    // Envoy XFCC / RFC 9440 conveyance trust model.
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_i2_xfcc_uri_extraction() {
        // #1990: one entry, Envoy's grammar. Quoted values may hold `,` `;` `=`
        // and escaped quotes; the elements are lower-cased keys.
        let e = parse_xfcc_single_entry(
            r#"By=spiffe://c/ns/5gc/sa/nrf;Hash=abcd;Subject="CN=SMF,O=Op; \"x\"";URI=urn:uuid:smf-1"#,
        )
        .expect("one entry");
        assert_eq!(e["hash"], "abcd");
        assert_eq!(e["subject"], r#"CN=SMF,O=Op; "x""#);
        assert_eq!(e["uri"], "urn:uuid:smf-1");

        // R30 MAJOR 2: an escaped quote inside a quoted Subject does not close it,
        // so a smuggled `;URI=` stays inside the Subject value.
        let e =
            parse_xfcc_single_entry(r#"Subject="CN=evil\";URI=urn:uuid:victim";URI=urn:uuid:real"#)
                .expect("one entry");
        assert_eq!(e["uri"], "urn:uuid:real");
        assert_eq!(e["subject"], r#"CN=evil";URI=urn:uuid:victim"#);

        // Ambiguous: refused, never guessed at.
        for bad in [
            r#"Subject="CN=open;URI=urn:uuid:victim"#, // unterminated quote
            r#"Subject=CN"x";URI=urn:uuid:a"#,         // a quote inside a bare value
            r#"Subject="x"y;URI=urn:uuid:a"#,          // text after a closing quote
            r#"URI=urn:uuid:a;URI=urn:uuid:b"#,        // a key twice
            r#"URI=urn:uuid:a;bare"#,                  // an element with no '='
        ] {
            assert!(parse_xfcc_single_entry(bad).is_none(), "{bad}");
        }
        // R30: more than one entry (Envoy APPEND_FORWARD prepends whatever the
        // client sent): refused.
        assert!(
            parse_xfcc_single_entry("URI=urn:uuid:leaf,By=x;URI=urn:uuid:intermediate").is_none()
        );

        // Extraction requires a declared trusted terminator (issue #64 gap 2);
        // see `xfcc_header_is_ignored_unless_trusted` for the default posture.
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        // The identity is the forwarded certificate's own URI SAN, urn:uuid:
        // stripped; a non-URN URI SAN binds on the exact value.
        let mut req = SbiRequest::post("/nnrf-oauth2/v1/access-token");
        req.http
            .set_header("x-forwarded-client-cert", test_xfcc("amf-9", &[]));
        from_test_terminator(&mut req);
        assert_eq!(
            extract_transport_client_nf_instance_id(&req, &trusting).as_deref(),
            Some("amf-9")
        );
        let mut req2 = SbiRequest::post("/x");
        req2.http.set_header(
            "x-forwarded-client-cert",
            test_xfcc("https://amf.example/nf/amf-9", &[]),
        );
        from_test_terminator(&mut req2);
        assert_eq!(
            extract_transport_client_nf_instance_id(&req2, &trusting).as_deref(),
            Some("https://amf.example/nf/amf-9")
        );
        // No XFCC header -> no transport identity.
        let bare = SbiRequest::post("/x");
        assert!(extract_transport_client_nf_instance_id(&bare, &trusting).is_none());
    }

    #[test]
    fn test_nrfd_i2_verify_transport_binding() {
        // Matching cert identity and request nfInstanceId -> Ok.
        assert!(verify_transport_binding("nf-1", "nf-1").is_ok());
        // Mismatch -> invalid_client (a cert for nf-A cannot mint tokens for nf-B).
        assert_eq!(
            verify_transport_binding("nf-A", "nf-B").unwrap_err().0,
            "invalid_client"
        );
    }

    #[test]
    fn test_nrfd_i2_enforce_client_authentication() {
        // Issue #64 gap 1: the DEFAULT requires authentication. Satisfied by a
        // verified CCA OR an mTLS identity; neither proven -> invalid_client.
        let def = NrfPolicy::default();
        assert!(def.require_client_auth, "the secure posture is the default");
        assert!(enforce_client_authentication(&def, true, false).is_ok());
        assert!(enforce_client_authentication(&def, false, true).is_ok());
        assert_eq!(
            enforce_client_authentication(&def, false, false)
                .unwrap_err()
                .0,
            "invalid_client"
        );

        // The documented escape hatch: explicitly opting out lets an
        // unauthenticated request through again (matched sim / non-TLS dev).
        let opted_out = NrfPolicy {
            require_client_auth: false,
            ..NrfPolicy::default()
        };
        assert!(enforce_client_authentication(&opted_out, false, false).is_ok());

        // require_client_cert_binding ON: an mTLS identity is MANDATORY — a CCA
        // alone does not satisfy it.
        let mtls = NrfPolicy {
            require_client_cert_binding: true,
            ..NrfPolicy::default()
        };
        assert!(enforce_client_authentication(&mtls, false, true).is_ok());
        assert_eq!(
            enforce_client_authentication(&mtls, true, false)
                .unwrap_err()
                .0,
            "invalid_client"
        );
    }

    #[test]
    fn test_nrfd_i2_from_yaml_and_env_overrides() {
        // yaml knobs fold into the policy.
        let yaml: NrfYaml = serde_yaml::from_str(
            "nrf:\n  sbi:\n    oauth2:\n      require_client_auth: true\n      \
             require_client_cert_binding: true\n",
        )
        .expect("parse yaml");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(policy.require_client_auth);
        assert!(policy.require_client_cert_binding);

        // Issue #64 gaps 1+2: authentication is required by default and the CCA
        // signature is verified by default; mandating mTLS *specifically*, and
        // trusting a forwarded-cert header, both stay opt-in.
        let def = NrfPolicy::default();
        assert!(def.require_client_auth);
        assert!(def.cca_verify_signature);
        assert!(!def.require_client_cert_binding);
        assert!(!def.trust_forwarded_client_cert);

        // An `oauth2:` section that does NOT mention a knob must leave its default
        // alone. This is the whole reason `from_yaml` stopped using
        // `unwrap_or(false)`: nrf-oauth2.yaml sets only `require: true`, so the
        // old fold silently turned client authentication back OFF in exactly the
        // deployment that had asked for OAuth2.
        let partial: NrfYaml =
            serde_yaml::from_str("nrf:\n  sbi:\n    oauth2:\n      require: true\n")
                .expect("parse yaml");
        let folded = NrfPolicy::from_yaml(&partial);
        assert!(
            folded.require_client_auth,
            "an unmentioned knob must keep its secure default"
        );
        assert!(folded.cca_verify_signature);

        // Env override forces an opt-in knob ON without a code edit; an
        // absent/other value leaves it unchanged. Serialized because it mutates
        // process env.
        let mut p = NrfPolicy::default();
        std::env::set_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING", "1");
        p.apply_env_overrides();
        assert!(p.require_client_cert_binding);
        std::env::remove_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_CERT_BINDING");

        // #1990 (R30): the trusted-terminator variable turns the knob on under
        // dev only. Under production a header any client can send is not trusted
        // on an environment variable's say-so.
        //
        // REVERT-VERIFIED: with the production check removed, the production
        // assertion fails.
        std::env::set_var("NRF_SBI_OAUTH2_TRUST_FORWARDED_CLIENT_CERT", "1");
        let mut t = NrfPolicy::default();
        t.apply_env_overrides_under(nextgcore_sbi::security::SbiProfile::Dev);
        assert!(
            t.trust_forwarded_client_cert,
            "dev: the variable turns it on"
        );
        let mut prod = NrfPolicy::default();
        prod.apply_env_overrides_under(nextgcore_sbi::security::SbiProfile::Production);
        assert!(
            !prod.trust_forwarded_client_cert,
            "production: the variable is ignored"
        );
        std::env::remove_var("NRF_SBI_OAUTH2_TRUST_FORWARDED_CLIENT_CERT");

        // A tightening env override never turns a knob back off with a falsy value.
        let mut on = NrfPolicy {
            require_client_auth: true,
            ..NrfPolicy::default()
        };
        std::env::set_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH", "0");
        on.apply_env_overrides();
        assert!(on.require_client_auth);
        std::env::remove_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH");

        // The escape hatch is the ONE loosening override, and it wins over the
        // tightening one so a host operator can always get back to a working
        // dev posture without editing config.
        let mut hatch = NrfPolicy::default();
        std::env::set_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH", "1");
        std::env::set_var("NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED", "1");
        hatch.apply_env_overrides();
        assert!(
            !hatch.require_client_auth,
            "NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED is applied last and wins"
        );
        std::env::remove_var("NRF_SBI_OAUTH2_ALLOW_UNAUTHENTICATED");
        std::env::remove_var("NRF_SBI_OAUTH2_REQUIRE_CLIENT_AUTH");
    }

    /// Strict-peer (real handler) test of the mTLS/CCA binding at the live token
    /// endpoint. The transport-binding mismatch check runs unconditionally (no
    /// flag needed): a forged XFCC identity is rejected even under the default
    /// (OFF) policy — the falsifiable core of I2.
    #[tokio::test]
    async fn test_nrfd_i2_token_endpoint_mtls_binding() {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = "nrfdi2-consumer";
        let producer_id = "nrfdi2-producer";
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": "NRFDI2C", "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": "SENF", "nfStatus": "REGISTERED",
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "nrfdi2-svc"}],
            }))
            .unwrap(),
        )
        .unwrap();

        let token_req = |xfcc: Option<&str>| {
            let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            r.http.set_content(
                json!({
                    "grant_type": "client_credentials", "nfInstanceId": consumer_id,
                    "nfType": "NRFDI2C", "targetNfType": "SENF", "scope": "nrfdi2-svc"
                })
                .to_string(),
            );
            if let Some(x) = xfcc {
                r.http.set_header("x-forwarded-client-cert", x);
                from_test_terminator(&mut r);
            }
            r
        };

        // A deployment that HAS declared a trusted TLS terminator, so the
        // forwarded-cert header carries a real identity (issue #64 gap 2).
        let policy = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };

        // (a) A forged/mismatched mTLS identity is rejected with invalid_client.
        // The binding check is unconditional: a cert for one NF can never mint a
        // token for another, whatever the policy flags say.
        let resp = handle_access_token_request_with_policy(
            &token_req(Some(&test_xfcc("some-other-nf", &[]))),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 400, "mismatched cert must be rejected");
        let err: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(err["error"], "invalid_client");

        // (b) A matching mTLS identity binds cleanly -> token issued (200).
        let resp = handle_access_token_request_with_policy(
            &token_req(Some(&test_xfcc(consumer_id, &[]))),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "bound cert must pass: {:?}",
            resp.http.content
        );

        // (c) No identity at all -> rejected, because authentication is now
        // required by default (issue #64 gap 1). This assertion INVERTED with the
        // posture change: it used to assert 200.
        let resp = handle_access_token_request_with_policy(&token_req(None), &policy).await;
        assert_eq!(
            resp.status, 400,
            "an unauthenticated request must be refused under the default policy"
        );

        // (d) The same request succeeds only when an operator explicitly opts out.
        let opted_out = NrfPolicy {
            require_client_auth: false,
            ..policy
        };
        let resp = handle_access_token_request_with_policy(&token_req(None), &opted_out).await;
        assert_eq!(
            resp.status, 200,
            "explicit opt-out restores the legacy path: {:?}",
            resp.http.content
        );

        mgr.deregister(consumer_id).ok();
        mgr.deregister(producer_id).ok();
    }

    // -----------------------------------------------------------------
    // Issue #64 gaps 1+2: the token endpoint authenticates the consumer, and
    // the evidence it accepts is unforgeable
    // (TS 33.501 §13.3.1, §13.3.8.3, §13.4.1.1)
    // -----------------------------------------------------------------

    /// Register a throwaway consumer/producer pair under NF types unique to the
    /// caller, so no other test's registrations affect the authorization decision.
    fn register_pair(tag: &str) -> (String, String, String, String) {
        use serde_json::json;
        let mgr = nf_manager();
        let consumer_id = format!("{tag}-consumer");
        let producer_id = format!("{tag}-producer");
        let consumer_type = format!("{}C", tag.to_uppercase());
        let producer_type = format!("{}P", tag.to_uppercase());
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": consumer_id, "nfType": consumer_type,
                "nfStatus": "REGISTERED",
            }))
            .unwrap(),
        )
        .unwrap();
        mgr.register(
            NfProfile::from_json(&json!({
                "nfInstanceId": producer_id, "nfType": producer_type,
                "nfStatus": "REGISTERED",
                "nfServices": [{"serviceInstanceId": "s0", "serviceName": "svc"}],
            }))
            .unwrap(),
        )
        .unwrap();
        (consumer_id, producer_id, consumer_type, producer_type)
    }

    /// Build a token request for a pair from [`register_pair`], optionally
    /// carrying a CCA and/or a forwarded-client-cert header. The producer is
    /// pinned by instance (#1753): its per-test NF type keeps it out of every other
    /// test's producer set, and is outside the TS 29.510 enum, so a request by type
    /// would be refused before authentication is what decides.
    fn auth_token_req(
        consumer_id: &str,
        consumer_type: &str,
        producer_id: &str,
        cca: Option<&str>,
        xfcc: Option<&str>,
    ) -> SbiRequest {
        use serde_json::json;
        let mut body = json!({
            "grant_type": "client_credentials",
            "nfInstanceId": consumer_id,
            "nfType": consumer_type,
            "targetNfInstanceId": producer_id,
            "scope": "svc",
        });
        if let Some(c) = cca {
            body["cca"] = json!(c);
        }
        let mut r = SbiRequest::post("/nnrf-oauth2/v1/access-token");
        r.http.set_content(body.to_string());
        if let Some(x) = xfcc {
            r.http.set_header("x-forwarded-client-cert", x);
            from_test_terminator(&mut r);
        }
        r
    }

    fn error_of(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap()
    }

    /// **Issue #187, criteria 1 + 3.** The overlay's whole reason for opting out
    /// of client authentication was that no trust store could be provisioned.
    /// This asserts the provisioning route that replaces the opt-out works, in
    /// BOTH directions, against the real token endpoint:
    ///
    /// * POSITIVE — a consumer whose CCA is signed with a key published into
    ///   `cca_trusted_keys_dir` gets a 200 and a token whose `sub` is its pinned
    ///   `nfInstanceId`. A negative-only test would be satisfied by a code path
    ///   that never issues a token to anyone, so this half is the load-bearing
    ///   one for criterion 1.
    /// * NEGATIVE — a consumer signing with a key that is NOT in the store is
    ///   refused `invalid_client`, and the reason names the missing trusted key
    ///   rather than being a generic 401 (criterion 3 is explicit about this:
    ///   the failure has to be diagnosable).
    ///
    /// Revert-verified: deleting the `load_cca_trusted_keys_dir` call from
    /// `NrfPolicy::from_yaml` fails the POSITIVE half (the trusted key is never
    /// loaded, so the signed CCA is refused); making the directory loader ignore
    /// the file stem fails it the same way.
    #[tokio::test]
    async fn a_cca_signed_by_a_directory_published_key_is_accepted_and_an_unpublished_one_is_not() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd187dir");

        // The consumer generates its own key and publishes the PUBLIC half, as
        // `init_cca_client_credentials` does at NF startup. Nothing private is
        // shared with the NRF, and nothing is committed.
        let dir = std::env::temp_dir().join(format!("nrfd187-jwks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let trusted = nextgcore_sbi::oauth::generate_es256_key();
        nextgcore_sbi::oauth::publish_cca_public_jwk(&trusted, &consumer_id, &dir)
            .expect("publish the consumer's public JWK");

        // The NRF loads its trust store from that directory, via real YAML — so
        // this also proves the new key is READ and not merely declared.
        let yaml: NrfYaml = serde_yaml::from_str(&format!(
            "nrf:\n  sbi:\n    oauth2:\n      require_client_auth: true\n      \
             cca_trusted_keys_dir: {}\n",
            dir.display()
        ))
        .expect("parse");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(
            policy.cca_trusted_keys.contains_key(&consumer_id),
            "cca_trusted_keys_dir must load {consumer_id}.jwk, keyed by the file stem; \
             without it the docker overlay still has no way to provision a trust store"
        );
        assert!(policy.require_client_auth);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // POSITIVE: signed with the published key -> authenticated, token issued.
        let good = nextgcore_sbi::oauth::mint_cca(&trusted, &consumer_id, "NRF", now, 60, &[]);
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&good), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "a CCA signed with a directory-published trusted key must be accepted: {:?}",
            resp.http.content
        );
        let issued: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let token = issued["access_token"].as_str().expect("access_token");
        // The token's subject must be the AUTHENTICATED identity, i.e. the
        // pinned nfInstanceId the CCA proved (TS 33.501 §13.4.1.1).
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).expect("JWT payload"))
                .expect("base64url"),
        )
        .expect("claims");
        assert_eq!(
            claims["sub"], consumer_id,
            "the issued token's subject must be the authenticated nfInstanceId"
        );

        // NEGATIVE: a DIFFERENT key, never published, for the same NF. This is
        // criterion 3 — and the message must name the cause, because a generic
        // 401 leaves an operator with no way to tell a missing trust-store entry
        // from a network fault.
        let untrusted = nextgcore_sbi::oauth::generate_es256_key();
        let forged = nextgcore_sbi::oauth::mint_cca(&untrusted, &consumer_id, "NRF", now, 60, &[]);
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&forged), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "a CCA signed with a key the NRF does not trust must be refused"
        );
        let err = error_of(&resp);
        assert_eq!(err["error"], "invalid_client");
        let desc = err["error_description"].as_str().unwrap_or_default();
        assert!(
            desc.contains("signature"),
            "the refusal must say the SIGNATURE did not verify so an operator can act on it; \
             got {desc:?}"
        );

        // And an NF with no published key at all is refused for the other
        // fail-closed reason: no trusted key exists to verify against.
        let (other_id, other_producer, otype, _optype) = register_pair("nrfd187nokey");
        let other_cca = nextgcore_sbi::oauth::mint_cca(&untrusted, &other_id, "NRF", now, 60, &[]);
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&other_id, &otype, &other_producer, Some(&other_cca), None),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 400);
        let desc = error_of(&resp)["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            desc.contains("no trusted"),
            "an NF absent from the trust store must be told exactly that; got {desc:?}"
        );

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
        mgr.deregister(&other_id).ok();
        mgr.deregister(&other_producer).ok();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Issue #187.** A key published AFTER the NRF started is still trusted.
    ///
    /// This is not a nicety, it is the overlay's actual startup order: every NF
    /// `depends_on` the NRF, and each publishes its own public JWK when it boots,
    /// so at the NRF's startup read the directory is empty. A startup-only load
    /// would trust nobody and the overlay would fail exactly as it does today.
    ///
    /// The fail-closed posture is unchanged and asserted here too: an NF with no
    /// file on disk is still refused.
    ///
    /// Revert-verified: deleting the `lazy_trusted_key` arm from
    /// `authenticate_token_client` makes the late-publish half fail with
    /// "no trusted ES256 key configured".
    #[tokio::test]
    async fn a_key_published_after_the_nrf_started_is_still_trusted() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd187late");
        let dir = std::env::temp_dir().join(format!("nrfd187-late-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        // The NRF reads an EMPTY directory at startup, as it really would.
        let yaml: NrfYaml = serde_yaml::from_str(&format!(
            "nrf:\n  sbi:\n    oauth2:\n      require_client_auth: true\n      \
             cca_trusted_keys_dir: {}\n",
            dir.display()
        ))
        .expect("parse");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(
            policy.cca_trusted_keys.is_empty(),
            "the directory was empty at startup, which is the real ordering"
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &consumer_id, "NRF", now, 60, &[]);

        // Before the NF published: refused, fail-closed.
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "with nothing on disk the NRF must still refuse -- the on-miss read must not \
             become a way to pass without a key"
        );

        // The NF starts and publishes. No NRF restart.
        nextgcore_sbi::oauth::publish_cca_public_jwk(&key, &consumer_id, &dir).expect("publish");

        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "a key published after startup must be picked up, or every NF that boots after \
             the NRF is permanently untrusted: {:?}",
            resp.http.content
        );

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Issue #187, criterion 5.** With `oauth2.require: true` the NRF requests
    /// tokens from ITSELF for its outbound status notifications, and is not
    /// exempt from its own policy. Two things it needs and previously lacked: a
    /// CCA key the NRF trusts for its own ID, and a REGISTRATION — the token
    /// endpoint refuses a requester its registry does not know.
    ///
    /// Revert-verified: removing the `register_self_with_own_registry()` call
    /// makes this fail with "is not registered with this NRF", which is exactly
    /// the lockout an overlay run would have hit.
    #[tokio::test]
    async fn the_nrf_can_obtain_a_token_from_its_own_endpoint_under_its_own_policy() {
        // A producer for the NRF to ask about, so authorization has a target.
        let (_c, producer_id, _ct, _ptype) = register_pair("nrfd187self");

        // The NRF registers itself, exactly as startup does. Its entry is shared with
        // every other test of this process (#1644 review M1).
        let _self_entry = self_entry_test_lock().lock().await;
        register_self_with_own_registry();
        let self_id = nrf_instance_id().to_string();
        assert!(
            nf_manager().get(&self_id).is_some(),
            "the NRF must be in its own registry or its own token request is invalid_client"
        );

        // Its own CCA key, published into its own trust store — the same
        // provisioning path as any consumer's, with no NRF special case.
        let dir = std::env::temp_dir().join(format!("nrfd187-self-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = nextgcore_sbi::oauth::generate_es256_key();
        nextgcore_sbi::oauth::publish_cca_public_jwk(&key, &self_id, &dir).expect("publish");

        let yaml: NrfYaml = serde_yaml::from_str(&format!(
            "nrf:\n  sbi:\n    oauth2:\n      require_client_auth: true\n      \
             cca_trusted_keys_dir: {}\n",
            dir.display()
        ))
        .expect("parse");
        let policy = NrfPolicy::from_yaml(&yaml);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &self_id, "NRF", now, 60, &[]);
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&self_id, "NRF", &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "the NRF must be able to authenticate to its own token endpoint: {:?}",
            resp.http.content
        );

        nf_manager().deregister(&producer_id).ok();
        nf_manager().deregister(&self_id).ok();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Issue #64 acceptance criterion 1.** With DEFAULT configuration, a token
    /// request from a consumer that presents no verifiable client identity is
    /// rejected with `invalid_client`.
    ///
    /// This is the whole of gap 1: before the fix the endpoint minted a valid,
    /// NRF-signed access token for any `nfInstanceId` that happened to be in the
    /// registry, with no evidence at all that the caller was that NF.
    ///
    /// Revert-verified: restoring `require_client_auth: false` in
    /// `NrfPolicy::default` fails this.
    #[tokio::test]
    async fn default_policy_rejects_unauthenticated_token_request() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd64a");
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, None, None),
            &NrfPolicy::default(),
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "the default policy must not mint a token for an unauthenticated caller: {:?}",
            resp.http.content
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #64 gap 2.** A claim-valid but UNSIGNED CCA does not authenticate
    /// anything.
    ///
    /// This is why gaps 1 and 2 could not ship separately. `verify_cca_binding`
    /// only checks that the assertion's own claims agree with the request body —
    /// and both are chosen by whoever sent them. Before the fix,
    /// `cca_verify_signature` defaulted OFF and a present `cca` field satisfied
    /// `require_client_auth`, so turning gap 1's knob on would have demanded
    /// evidence of identity and then accepted a forgery: an attacker mints an
    /// assertion naming any registered NF and is authenticated as it.
    ///
    /// Revert-verified: making `authenticate_token_client` set `auth.identity`
    /// for a merely claim-checked CCA, or defaulting `cca_verify_signature` back
    /// to false, fails this.
    #[tokio::test]
    async fn unsigned_cca_does_not_authenticate() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd64b");

        // A CCA whose CLAIMS are all correct, with a garbage signature.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": consumer_id, "iss": consumer_id, "aud": "NRF",
                "iat": now, "exp": now + 60,
            })
            .to_string()
            .as_bytes(),
        );
        let forged = format!("{header}.{claims}.{}", URL_SAFE_NO_PAD.encode([0u8; 64]));

        // The claim binding passes -- which is exactly the trap.
        assert!(verify_cca_binding(&forged, &consumer_id, now).is_ok());

        // The consumer DOES have a trusted key registered, so the fail-closed
        // "no trusted key for this issuer" branch cannot be what rejects this.
        // Only signature verification can, which is the property under test.
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(consumer_id.clone(), *key.verifying_key());
        let policy = NrfPolicy {
            cca_trusted_keys: trusted.clone(),
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&forged), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "an unsigned CCA must not authenticate: {:?}",
            resp.http.content
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        // And with signature verification explicitly OFF -- the pre-fix default --
        // the forged assertion must STILL not authenticate the caller. This is the
        // combination that made gaps 1 and 2 inseparable: enforcement on, evidence
        // unchecked, so a forgery satisfies the requirement.
        let unchecked = NrfPolicy {
            cca_verify_signature: false,
            cca_trusted_keys: trusted,
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&forged), None),
            &unchecked,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "an unverified CCA must not satisfy require_client_auth: {:?}",
            resp.http.content
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #64 gap 2.** The `x-forwarded-client-cert` header confers no
    /// identity unless the operator declared a trusted TLS terminator.
    ///
    /// The header is an ordinary request header. Nothing in this repo sets or
    /// strips it (`grep -rn forwarded-client-cert docker/ deploy/ k8s/ configs/`
    /// finds nothing) and no SCP fronts the NRF token endpoint, so trusting it
    /// unconditionally let any client that could reach the NRF assert any
    /// identity by setting it — and `require_client_cert_binding` would then have
    /// confirmed the forgery instead of catching it.
    ///
    /// Revert-verified: removing the `trust_forwarded_client_cert` gate from
    /// `extract_transport_client_nf_instance_id` fails this.
    #[tokio::test]
    async fn xfcc_header_is_ignored_unless_trusted() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd64c");
        let xfcc = test_xfcc(&consumer_id, &[]);

        // Default policy: the header is not evidence, so the request is
        // unauthenticated and refused.
        let req = plaintext(auth_token_req(
            &consumer_id,
            &ctype,
            &producer_id,
            None,
            Some(&xfcc),
        ));
        assert!(
            extract_transport_client_nf_instance_id(&req, &NrfPolicy::default()).is_none(),
            "an untrusted forwarded-cert header must confer no identity"
        );
        let resp = handle_access_token_request_with_policy(&req, &NrfPolicy::default()).await;
        assert_eq!(
            resp.status, 400,
            "a self-set forwarded-cert header must not authenticate: {:?}",
            resp.http.content
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        // Declare a trusted terminator and the SAME header now authenticates.
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, None, Some(&xfcc)),
            &trusting,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "behind a declared terminator the header is the identity: {:?}",
            resp.http.content
        );

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #64 acceptance criterion 2.** A CCA whose subject does not match
    /// the requester is rejected, and so is a mismatched certificate identity.
    #[tokio::test]
    async fn subject_mismatch_is_rejected() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd64d");
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // A CCA correctly signed by SOMEONE ELSE's key, asserting their identity,
        // replayed on a request that claims to be our consumer.
        let other_cca = nextgcore_sbi::oauth::mint_cca(&key, "a-different-nf", "NRF", now, 60, &[]);
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(consumer_id.clone(), *key.verifying_key());
        let policy = NrfPolicy {
            cca_trusted_keys: trusted,
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&other_cca), None),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 400, "CCA subject mismatch must be rejected");
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        // A certificate identity for a different NF, behind a trusted terminator.
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(
                &consumer_id,
                &ctype,
                &producer_id,
                None,
                Some(&test_xfcc("a-different-nf", &[])),
            ),
            &policy,
        )
        .await;
        assert_eq!(resp.status, 400, "cert identity mismatch must be rejected");
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #64 gaps 1+2, the positive path.** A CCA minted by
    /// [`nextgcore_sbi::oauth::mint_cca`] and signed with a key the NRF trusts for
    /// that issuer authenticates the consumer, and the token's `sub` is the
    /// AUTHENTICATED identity (TS 33.501 §13.4.1.1).
    ///
    /// This is the end-to-end proof that the secure default is usable rather than
    /// merely strict: it exercises the exact assertion an `OAuth2Client` sends.
    #[tokio::test]
    async fn signed_cca_authenticates_and_binds_the_token_subject() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd64e");

        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &consumer_id, "NRF", now, 60, &[]);

        // The NRF trusts this issuer's public key -- the operator-provisioned half.
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(consumer_id.clone(), *key.verifying_key());
        let policy = NrfPolicy {
            cca_trusted_keys: trusted,
            ..NrfPolicy::default()
        };

        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "a signed CCA from a trusted key must authenticate: {:?}",
            resp.http.content
        );

        let body: serde_json::Value = serde_json::from_str(resp.http.content.as_deref().unwrap())
            .expect("token response is JSON");
        let token = body["access_token"].as_str().expect("access_token");
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).expect("payload"))
                .expect("base64url"),
        )
        .expect("claims are JSON");
        assert_eq!(
            claims["sub"], consumer_id,
            "the subject must be the authenticated identity"
        );

        // An assertion signed by an UNTRUSTED key is refused fail-closed, even
        // though its claims are identical.
        let rogue = nextgcore_sbi::oauth::generate_es256_key();
        let rogue_cca = nextgcore_sbi::oauth::mint_cca(&rogue, &consumer_id, "NRF", now, 60, &[]);
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&rogue_cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "a CCA signed by an untrusted key must be refused"
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// Issue #64 gaps 1+2, the WIRE contract between the two crates: a CCA minted
    /// by `nextgcore-sbi`, encoded into the form body it actually sends, must
    /// survive nrfd's own parser and still verify.
    ///
    /// Worth its own test because the two halves live in different crates and
    /// neither one alone can prove the round trip. A form body is
    /// percent-encoded and `decode_form_value` maps `+` to space; a JWT is
    /// base64url plus `.` separators, which `encode_form_value` leaves untouched — but
    /// that is a property of two functions agreeing, not something either
    /// guarantees on its own. If it ever stops holding, every NF silently fails
    /// authentication.
    #[test]
    fn a_minted_cca_survives_the_form_body_round_trip() {
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = 1_700_000_000u64;
        let cca = nextgcore_sbi::oauth::mint_cca(&key, "amf-1", "NRF", now, 60, &[]);

        // Encode exactly as OAuth2Client::request_token does.
        let mut req = nextgcore_sbi::oauth::AccessTokenRequest::new(
            "amf-1",
            NfType::Amf,
            NfType::Udm,
            "nudm-sdm",
        );
        req.cca = Some(cca.clone());
        let body = req.to_form_body();

        // ...and decode with the NRF's own parser.
        let parsed = parse_token_request(&body);
        assert_eq!(parsed.nf_instance_id, "amf-1");
        assert_eq!(
            parsed.cca, cca,
            "the CCA must arrive byte-identical, or its signature cannot verify"
        );
        // The assertion the NRF reconstructed still passes both NRF-side checks.
        verify_cca_binding(&parsed.cca, "amf-1", now).expect("binding holds after the round trip");
        verify_cca_signature(&parsed.cca, key.verifying_key())
            .expect("signature holds after the round trip");
    }

    /// **#1633 review m1.** Every identity check of the token endpoint compares
    /// NF Instance IDs as the registry keys them: a UUID case-insensitively (TS
    /// 29.510 §5.2.2.2.2), any other ID exactly. Over the real handler, for each
    /// proof:
    /// - mTLS (`verify_transport_binding`): a certificate naming the UUID in
    ///   upper case authenticates the lower-case request;
    /// - a trust-store CCA (`verify_cca_binding` sub/iss, the key lookup): an
    ///   upper-case `sub`/`iss` authenticates the lower-case request, and an
    ///   upper-case request finds the key of the lower-case NF;
    /// - an x5c CCA (`resolve_cca_verifying_key`): a leaf naming the UUID in
    ///   upper case binds the lower-case assertion.
    ///
    /// Each token's `sub` is the canonical (lower-case) ID. A non-UUID ID that
    /// differs only in case is refused, `invalid_client`, by every proof.
    #[tokio::test]
    async fn token_endpoint_identity_checks_fold_only_uuid_case_1633() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use serde_json::json;

        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd1633m1");
        let lower = "1633c0de-0000-4000-8000-0000000000a1";
        let upper = lower.to_ascii_uppercase();
        let legacy = "nrfd1633m1-legacy";
        let legacy_upper = legacy.to_ascii_uppercase();
        for id in [lower, legacy] {
            nf_manager()
                .register(
                    NfProfile::from_json(&json!({
                        "nfInstanceId": id, "nfType": ctype, "nfStatus": "REGISTERED",
                    }))
                    .unwrap(),
                )
                .unwrap();
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sub_of = |resp: &SbiResponse| -> String {
            assert_eq!(resp.status, 200, "{:?}", resp.http.content);
            let token = error_of(resp)["access_token"]
                .as_str()
                .expect("access_token")
                .to_string();
            let claims: serde_json::Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(token.split('.').nth(1).expect("payload"))
                    .expect("base64url"),
            )
            .expect("claims");
            claims["sub"].as_str().expect("sub").to_string()
        };
        let refused = |resp: &SbiResponse, what: &str| {
            assert_eq!(resp.status, 400, "{what}: {:?}", resp.http.content);
            assert_eq!(error_of(resp)["error"], "invalid_client", "{what}");
        };
        let req = |id: &str, cca: Option<&str>, xfcc: Option<&str>| {
            auth_token_req(id, &ctype, &producer_id, cca, xfcc)
        };

        // mTLS, through a declared terminator.
        let fwd = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &req(lower, None, Some(&test_xfcc(&upper, &[]))),
            &fwd,
        )
        .await;
        assert_eq!(sub_of(&resp), lower, "mTLS, upper-case certificate");
        let resp = handle_access_token_request_with_policy(
            &req(legacy, None, Some(&test_xfcc(&legacy_upper, &[]))),
            &fwd,
        )
        .await;
        refused(&resp, "mTLS, non-UUID differing in case");

        // A CCA verified against the trust store.
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let trusted: std::collections::HashMap<_, _> = [lower, legacy]
            .into_iter()
            .map(|id| (id.to_string(), *key.verifying_key()))
            .collect();
        let store = NrfPolicy {
            cca_trusted_keys: trusted,
            ..NrfPolicy::default()
        };
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &upper, "NRF", now, 60, &[]);
        let resp =
            handle_access_token_request_with_policy(&req(lower, Some(&cca), None), &store).await;
        assert_eq!(sub_of(&resp), lower, "trust store, upper-case sub/iss");
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &upper, "NRF", now, 60, &[]);
        let resp =
            handle_access_token_request_with_policy(&req(&upper, Some(&cca), None), &store).await;
        assert_eq!(sub_of(&resp), lower, "trust store, upper-case request");
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &legacy_upper, "NRF", now, 60, &[]);
        let resp =
            handle_access_token_request_with_policy(&req(legacy, Some(&cca), None), &store).await;
        refused(&resp, "trust store, non-UUID sub differing in case");

        // A CCA carrying its x5c certificate.
        let (ca_der, ca, ca_key) = cca_test_ca();
        let anchored = NrfPolicy {
            cca_trust_anchors: vec![ca_der],
            ..NrfPolicy::default()
        };
        let leaf = cca_test_leaf(&key, &upper, &ca, &ca_key);
        let cca = nextgcore_sbi::oauth::mint_cca(&key, lower, "NRF", now, 60, &[leaf]);
        let resp =
            handle_access_token_request_with_policy(&req(lower, Some(&cca), None), &anchored).await;
        assert_eq!(sub_of(&resp), lower, "x5c, upper-case certificate");
        let leaf = cca_test_leaf(&key, &legacy_upper, &ca, &ca_key);
        let cca = nextgcore_sbi::oauth::mint_cca(&key, legacy, "NRF", now, 60, &[leaf]);
        let resp =
            handle_access_token_request_with_policy(&req(legacy, Some(&cca), None), &anchored)
                .await;
        refused(&resp, "x5c, non-UUID certificate differing in case");

        for id in [lower, legacy, &consumer_id, &producer_id] {
            nf_manager().deregister(id).ok();
        }
    }

    /// **#1657 review m1.** With client authentication off and no proof, the
    /// token `sub` is the asserted ID in the registry's spelling, as a proven
    /// one is: an upper-case UUID request gets the lower-case `sub`.
    #[tokio::test]
    async fn an_unproven_token_subject_is_canonical_1633() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd1633m3");
        let lower = "1633f0f0-0000-4000-8000-0000000000f6";
        let upper = lower.to_ascii_uppercase();
        nf_manager()
            .register(
                NfProfile::from_json(&serde_json::json!({
                    "nfInstanceId": lower, "nfType": ctype, "nfStatus": "REGISTERED",
                }))
                .unwrap(),
            )
            .unwrap();
        let open = NrfPolicy {
            require_client_auth: false,
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&upper, &ctype, &producer_id, None, None),
            &open,
        )
        .await;
        assert_eq!(resp.status, 200, "{:?}", resp.http.content);
        let token = error_of(&resp)["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).expect("payload"))
                .expect("base64url"),
        )
        .expect("claims");
        for id in [lower, &consumer_id, &producer_id] {
            nf_manager().deregister(id).ok();
        }
        assert_eq!(claims["sub"], lower);
    }

    /// #1684, the NRF's half: its trust-store loader (`TrustedKeySet::read_dir`),
    /// reading the directory over and over while an NF republishes its key there,
    /// finds that NF's key on every pass, and never takes the publisher's temporary
    /// file for an entry.
    ///
    /// REVERT-VERIFIED: with `publish_cca_public_jwk` writing in place
    /// (`std::fs::write`), a pass misses the key.
    #[test]
    fn the_trust_store_loader_always_finds_a_key_being_republished_1684() {
        let dir = std::env::temp_dir().join(format!(
            "nrfd1684-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let id = "16841684-0000-4000-8000-000000000001";
        let key = nextgcore_sbi::oauth::generate_es256_key();
        nextgcore_sbi::oauth::publish_cca_public_jwk(&key, id, &dir).expect("publish");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let (dir, stop, key) = (dir.clone(), std::sync::Arc::clone(&stop), key.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    nextgcore_sbi::oauth::publish_cca_public_jwk(&key, id, &dir)
                        .expect("republish");
                }
            })
        };
        for pass in 0..500 {
            let found = TrustedKeySet::read_dir(&dir, None).expect("readable");
            assert_eq!(found.keys.len(), 1, "pass {pass}: exactly the one entry");
            assert_eq!(
                found.keys.get(id),
                Some(key.verifying_key()),
                "pass {pass}: the key is found"
            );
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().expect("writer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **#1657 review m2.** Two trust-store entries that spell one UUID in
    /// different case and hold DIFFERENT keys are trusted neither, in the inline
    /// list, in `cca_trusted_keys_dir` at load, and in the on-disk lookup of a
    /// key published after start: keeping one would let the order (or the
    /// request's case) pick the key that verifies the NF. The same key twice is
    /// kept.
    #[test]
    fn case_variant_trusted_keys_with_different_keys_are_trusted_neither_1633() {
        let now = 1_700_000_000u64;
        let base = std::env::temp_dir().join(format!("nrfd1633-m2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let a = nextgcore_sbi::oauth::generate_es256_key();
        let b = nextgcore_sbi::oauth::generate_es256_key();
        let jwk_of = |key: &p256::ecdsa::SigningKey| -> String {
            let d = base.join(format!("jwk-{}", rand_suffix_1633(key)));
            let path = nextgcore_sbi::oauth::publish_cca_public_jwk(key, "x", &d).expect("jwk");
            std::fs::read_to_string(path).expect("read jwk")
        };
        let (ja, jb) = (jwk_of(&a), jwk_of(&b));
        let id = "1633a1a1-0000-4000-8000-0000000000a7";
        let up = id.to_ascii_uppercase();
        let inline = |entries: &[(&str, &str)]| -> NrfPolicy {
            let mut yaml = "nrf:\n  sbi:\n    oauth2:\n      cca_trusted_keys:\n".to_string();
            for (nf, jwk) in entries {
                yaml.push_str(&format!(
                    "        - nfInstanceId: {nf}\n          jwk: {jwk}\n"
                ));
            }
            NrfPolicy::from_yaml(&serde_yaml::from_str::<NrfYaml>(&yaml).expect("yaml"))
        };
        assert!(
            !inline(&[(&up, &ja), (id, &jb)])
                .cca_trusted_keys
                .contains_key(id),
            "inline: different keys, neither trusted"
        );
        assert!(
            !inline(&[(&up, &ja), (id, &jb), (&up, &ja)])
                .cca_trusted_keys
                .contains_key(id),
            "inline: a third entry does not reinstate a conflicted NF"
        );
        assert_eq!(
            inline(&[(&up, &ja), (id, &ja)]).cca_trusted_keys.get(id),
            Some(a.verifying_key()),
            "inline: the same key twice is kept"
        );

        let dir_policy = |dir: &std::path::Path| -> NrfPolicy {
            let yaml = format!(
                "nrf:\n  sbi:\n    oauth2:\n      cca_trusted_keys_dir: {}\n",
                dir.display()
            );
            NrfPolicy::from_yaml(&serde_yaml::from_str::<NrfYaml>(&yaml).expect("yaml"))
        };
        let differ = base.join("differ");
        nextgcore_sbi::oauth::publish_cca_public_jwk(&a, &up, &differ).expect("publish");
        nextgcore_sbi::oauth::publish_cca_public_jwk(&b, id, &differ).expect("publish");
        assert!(
            !dir_policy(&differ).cca_trusted_keys.contains_key(id),
            "dir: different keys, neither trusted"
        );
        let same = base.join("same");
        nextgcore_sbi::oauth::publish_cca_public_jwk(&a, &up, &same).expect("publish");
        nextgcore_sbi::oauth::publish_cca_public_jwk(&a, id, &same).expect("publish");
        assert_eq!(
            dir_policy(&same).cca_trusted_keys.get(id),
            Some(a.verifying_key()),
            "dir: the same key twice is kept"
        );

        // Published after start: the startup map is empty.
        let late = base.join("late");
        std::fs::create_dir_all(&late).expect("dir");
        let policy = dir_policy(&late);
        nextgcore_sbi::oauth::publish_cca_public_jwk(&a, &up, &late).expect("publish");
        nextgcore_sbi::oauth::publish_cca_public_jwk(&b, id, &late).expect("publish");
        let cca = nextgcore_sbi::oauth::mint_cca(&a, &up, "NRF", now, 60, &[]);
        let refused = resolve_cca_verifying_key(&policy, &cca, &up, now);
        nextgcore_sbi::oauth::publish_cca_public_jwk(&a, id, &late).expect("republish");
        let accepted = resolve_cca_verifying_key(&policy, &cca, &up, now);
        let _ = std::fs::remove_dir_all(&base);
        assert!(refused.is_err(), "late: different keys, neither trusted");
        assert_eq!(
            accepted.ok(),
            Some(*a.verifying_key()),
            "late: the same key is used"
        );
    }

    /// **#1678 review M1.** The trust-neither rule holds for the CCA outcome
    /// itself, through `resolve_cca_verifying_key`, on every path R1 probed:
    /// 1. `UPPER.jwk` holds key a and `lower.jwk` key b at load: a CCA signed by
    ///    either, in either spelling, is refused (the on-disk lookup used to
    ///    accept the lower-case one's key);
    /// 2. two non-canonical spellings published after start, with different
    ///    keys and no canonical file: each spelling's own key is refused (each
    ///    used to verify);
    /// 3. an inline key for the NF plus a conflict in the directory: refused
    ///    (the inline key used to stay in force);
    /// 4. a conflict recorded at load stands when the stale files are removed
    ///    and a canonical one published later.
    ///
    /// The conflict is reported once per NF, an ERROR and the
    /// `nrf_cca_trusted_key_conflicts_total` counter.
    #[test]
    fn a_conflicted_nf_is_refused_on_every_lookup_path_1633() {
        let now = 1_700_000_000u64;
        let base = std::env::temp_dir().join(format!("nrfd1678-m1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let a = nextgcore_sbi::oauth::generate_es256_key();
        let b = nextgcore_sbi::oauth::generate_es256_key();
        let publish = |key: &p256::ecdsa::SigningKey, id: &str, dir: &std::path::Path| {
            nextgcore_sbi::oauth::publish_cca_public_jwk(key, id, dir).expect("publish");
        };
        let dir_policy = |dir: &std::path::Path, inline: &str| -> NrfPolicy {
            let yaml = format!(
                "nrf:\n  sbi:\n    oauth2:\n      cca_trusted_keys_dir: {}\n{inline}",
                dir.display()
            );
            NrfPolicy::from_yaml(&serde_yaml::from_str::<NrfYaml>(&yaml).expect("yaml"))
        };
        let verifies = |policy: &NrfPolicy, key: &p256::ecdsa::SigningKey, id: &str| {
            let cca = nextgcore_sbi::oauth::mint_cca(key, id, "NRF", now, 60, &[]);
            resolve_cca_verifying_key(policy, &cca, id, now)
                .ok()
                .is_some_and(|k| k == *key.verifying_key())
        };

        // 1. A conflict present at load.
        let id = "1678a1a1-0000-4000-8000-0000000000b1";
        let up = id.to_ascii_uppercase();
        let load = base.join("load");
        publish(&a, &up, &load);
        publish(&b, id, &load);
        let policy = dir_policy(&load, "");
        for (key, spelled) in [(&a, up.as_str()), (&b, id), (&a, id), (&b, up.as_str())] {
            assert!(
                !verifies(&policy, key, spelled),
                "1: a conflicted NF's CCA ({spelled}) must not verify"
            );
        }
        // 4. ...and it stands after the stale files go and a canonical one
        // is published.
        std::fs::remove_dir_all(&load).expect("rm");
        publish(&a, id, &load);
        assert!(!verifies(&policy, &a, id), "4: a load-time conflict stands");

        // 2. Two non-canonical spellings published after start.
        let id2 = "1678b2b2-0000-4000-8000-0000000000c2";
        let mixed1 = "1678B2B2-0000-4000-8000-0000000000c2";
        let mixed2 = "1678b2b2-0000-4000-8000-0000000000C2";
        let late = base.join("late");
        std::fs::create_dir_all(&late).expect("mkdir");
        let policy = dir_policy(&late, "");
        publish(&a, mixed1, &late);
        publish(&b, mixed2, &late);
        assert!(
            !verifies(&policy, &a, mixed1),
            "2: {mixed1} with its own key"
        );
        assert!(
            !verifies(&policy, &b, mixed2),
            "2: {mixed2} with its own key"
        );
        assert!(!verifies(&policy, &a, id2), "2: the canonical spelling");
        // The same NF with one key under every spelling still verifies.
        publish(&a, mixed2, &late);
        assert!(
            verifies(&policy, &a, mixed2),
            "2: one key, any spelling, verifies"
        );

        // 3. An inline key for the NF, and a conflict in the directory.
        let id3 = "1678c3c3-0000-4000-8000-0000000000d3";
        let both = base.join("both");
        publish(&a, &id3.to_ascii_uppercase(), &both);
        publish(&b, id3, &both);
        let jwk = std::fs::read_to_string(
            nextgcore_sbi::oauth::publish_cca_public_jwk(&a, "x", &base.join("jwk")).expect("jwk"),
        )
        .expect("read jwk");
        let inline = format!(
            "      cca_trusted_keys:\n        - nfInstanceId: {id3}\n          jwk: {jwk}\n"
        );
        let policy = dir_policy(&both, &inline);
        assert!(
            !policy.cca_trusted_keys.contains_key(id3) && !verifies(&policy, &a, id3),
            "3: a directory conflict leaves no inline key in force"
        );
        let _ = std::fs::remove_dir_all(&base);

        // Reported once per NF.
        assert!(
            !report_cca_key_conflict("test", id, id),
            "1's conflict was already reported"
        );
        assert!(report_cca_key_conflict(
            "test",
            "1678d4d4-0000-4000-8000-0000000000e4",
            "x"
        ));
        assert!(nextgcore_nrfd::metrics::render_prometheus()
            .lines()
            .any(|l| l.starts_with("nrf_cca_trusted_key_conflicts_total ") && !l.ends_with(" 0")));
    }

    /// A per-key directory name for [`case_variant_trusted_keys_with_different_keys_are_trusted_neither_1633`].
    fn rand_suffix_1633(key: &p256::ecdsa::SigningKey) -> String {
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .iter()
            .take(6)
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// **#1633 review m1.** A key in `cca_trusted_keys_dir` is keyed by the
    /// canonical ID when the directory is loaded, and a key published after
    /// start is also looked up under the canonical file name, so a UUID in
    /// either case finds it.
    #[test]
    fn directory_trusted_cca_keys_are_found_in_either_uuid_case_1633() {
        let now = 1_700_000_000u64;
        let dir = std::env::temp_dir().join(format!("nrfd1633-jwks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let loaded = "1633e0e0-0000-4000-8000-0000000000d4";
        nextgcore_sbi::oauth::publish_cca_public_jwk(&key, &loaded.to_ascii_uppercase(), &dir)
            .expect("publish");
        let yaml: NrfYaml = serde_yaml::from_str(&format!(
            "nrf:\n  sbi:\n    oauth2:\n      cca_trusted_keys_dir: {}\n",
            dir.display()
        ))
        .expect("parse yaml");
        let policy = NrfPolicy::from_yaml(&yaml);
        assert!(
            policy.cca_trusted_keys.contains_key(loaded),
            "{:?}",
            policy.cca_trusted_keys.keys().collect::<Vec<_>>()
        );

        let late = "1633e0e0-0000-4000-8000-0000000000e5";
        let late_upper = late.to_ascii_uppercase();
        nextgcore_sbi::oauth::publish_cca_public_jwk(&key, late, &dir).expect("publish");
        let cca = nextgcore_sbi::oauth::mint_cca(&key, &late_upper, "NRF", now, 60, &[]);
        let found = resolve_cca_verifying_key(&policy, &cca, &late_upper, now);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(found.ok(), Some(*key.verifying_key()));
    }

    /// **#1633 review m1.** A configured CCA trusted key is stored under the
    /// canonical ID, so a UUID written in upper case in the config is found.
    #[test]
    fn a_trusted_cca_key_is_keyed_canonically_1633() {
        let yaml_str = "nrf:\n  sbi:\n    oauth2:\n      cca_verify_signature: true\n      \
             cca_trusted_keys:\n        - nfInstanceId: 1633C0DE-0000-4000-8000-0000000000B2\n          \
             jwk:\n            kty: EC\n            crv: P-256\n            \
             x: f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\n            \
             y: x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\n        \
             - nfInstanceId: NF-1633\n          jwk:\n            kty: EC\n            \
             crv: P-256\n            x: f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\n            \
             y: x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\n";
        let yaml: NrfYaml = serde_yaml::from_str(yaml_str).expect("parse yaml");
        let policy = NrfPolicy::from_yaml(&yaml);
        let mut keys: Vec<_> = policy.cca_trusted_keys.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["1633c0de-0000-4000-8000-0000000000b2", "NF-1633"]);
    }

    /// Issue #64 gap 2: `authenticate_token_client` returns an identity ONLY for
    /// proven evidence, and records HOW it was proven.
    #[test]
    fn authenticate_token_client_reports_only_proven_identities() {
        let now = 1_700_000_000u64;
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let cca = nextgcore_sbi::oauth::mint_cca(&key, "nf-1", "NRF", now, 60, &[]);
        let mut trusted = std::collections::HashMap::new();
        trusted.insert("nf-1".to_string(), *key.verifying_key());

        // Nothing presented -> nothing proven.
        let bare = SbiRequest::post("/x");
        let auth =
            authenticate_token_client(&NrfPolicy::default(), &bare, "nf-1", "", now).unwrap();
        assert!(!auth.is_authenticated());
        assert!(!auth.via_transport);

        // A verified CCA proves the identity, but NOT via transport -- so it
        // cannot satisfy `require_client_cert_binding`.
        let policy = NrfPolicy {
            cca_trusted_keys: trusted.clone(),
            ..NrfPolicy::default()
        };
        let auth = authenticate_token_client(&policy, &bare, "nf-1", &cca, now).unwrap();
        assert_eq!(auth.identity.as_deref(), Some("nf-1"));
        assert!(
            !auth.via_transport,
            "a CCA is not transport authentication; mandating mTLS must still reject it"
        );
        assert_eq!(
            enforce_client_authentication(
                &NrfPolicy {
                    require_client_cert_binding: true,
                    ..policy.clone()
                },
                auth.is_authenticated(),
                auth.via_transport,
            )
            .unwrap_err()
            .0,
            "invalid_client"
        );

        // With signature verification explicitly off, the assertion is still
        // claim-checked but authenticates nothing -- the honest reading of "we
        // did not check it".
        let unchecked = NrfPolicy {
            cca_verify_signature: false,
            ..NrfPolicy::default()
        };
        let auth = authenticate_token_client(&unchecked, &bare, "nf-1", &cca, now).unwrap();
        assert!(
            !auth.is_authenticated(),
            "an unverified assertion proves nothing"
        );
        // ...and a contradictory one is still refused outright.
        assert!(authenticate_token_client(&unchecked, &bare, "nf-2", &cca, now).is_err());
    }

    // -----------------------------------------------------------------
    // Issue #393: the CCA's `x5c` chain and TS 33.501 §13.3.8.3's final
    // validation step — the NF Instance ID in the CCA must match the one in the
    // certificate that signed it.
    // -----------------------------------------------------------------

    /// A CA for CCA signing certificates. Returned as `(der, rcgen cert, rcgen
    /// key)` so the same CA can issue several leaves — which is what makes the
    /// contrast pair a controlled comparison rather than two unrelated setups.
    fn cca_test_ca() -> (Vec<u8>, rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "nrfd test CCA CA");
        let key = KeyPair::generate().expect("ca key");
        let cert = params.self_signed(&key).expect("ca cert");
        let der = cert.der().to_vec();
        (der, cert, key)
    }

    /// Issue a leaf over `signing_key`, carrying `nf_instance_id` as a
    /// `urn:uuid:` URI SubjectAltName (TS 33.310), signed by `(ca, ca_key)`.
    ///
    /// The leaf certifies the CCA **signing** key, which is what makes the binding
    /// real: `resolve_cca_verifying_key` pulls the key back out of the validated
    /// certificate and the JWS is checked against it.
    fn cca_test_leaf(
        signing_key: &p256::ecdsa::SigningKey,
        nf_instance_id: &str,
        ca: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
    ) -> Vec<u8> {
        use p256::pkcs8::EncodePrivateKey;
        use rcgen::{CertificateParams, KeyPair, SanType};

        let pkcs8 = signing_key
            .to_pkcs8_der()
            .expect("cca key to pkcs8")
            .as_bytes()
            .to_vec();
        let subject_key = KeyPair::try_from(pkcs8.as_slice()).expect("import the cca key");

        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::URI(
            format!("urn:uuid:{nf_instance_id}")
                .try_into()
                .expect("ia5 uri"),
        )];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, nf_instance_id);
        let t = time::OffsetDateTime::now_utc();
        params.not_before = t - time::Duration::hours(1);
        params.not_after = t + time::Duration::days(30);
        params
            .signed_by(&subject_key, ca, ca_key)
            .expect("leaf cert")
            .der()
            .to_vec()
    }

    /// **Issue #393, the contrast pair — criterion 2.** TS 33.501 §13.3.8.3's
    /// final bullet, asserted in both directions:
    ///
    /// > It verifies that the NF instance ID of the NFc in the CCA matches the NF
    /// > instance ID in the public key certificate used for signing the CCA.
    ///
    /// Both halves use the SAME CA, the SAME signing key, the SAME claims and the
    /// same code path. The ONLY difference is the URI SubjectAltName of the leaf
    /// certificate. So a pass cannot come from the chain failing for an unrelated
    /// reason, and the refusal is attributable to the binding and nothing else.
    ///
    /// Note the negative half is the *interesting* one: its CCA is signed by a key
    /// whose certificate validates perfectly to the configured CA. Before this
    /// issue there was no check that could tell the two apart.
    ///
    /// Revert-verified: deleting the `verified.nf_instance_id != nf_instance_id`
    /// arm from `resolve_cca_verifying_key` makes the negative half fail — it
    /// returns 200 where 400 is asserted.
    #[tokio::test]
    async fn a_cca_whose_certificate_names_another_nf_is_refused_and_its_own_is_accepted() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd393bind");
        let (ca_der, ca, ca_key) = cca_test_ca();

        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let policy = NrfPolicy {
            cca_trust_anchors: vec![ca_der],
            ..NrfPolicy::default()
        };

        // POSITIVE: the leaf's URI SAN IS this consumer's instance ID.
        let own_leaf = cca_test_leaf(&key, &consumer_id, &ca, &ca_key);
        let good = nextgcore_sbi::oauth::mint_cca(
            &key,
            &consumer_id,
            "NRF",
            now,
            60,
            std::slice::from_ref(&own_leaf),
        );
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&good), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "a CCA whose x5c certificate binds to the asserted nfInstanceId must authenticate, \
             with NO entry in cca_trusted_keys -- the certificate is the binding: {:?}",
            resp.http.content
        );
        assert!(
            policy.cca_trusted_keys.is_empty(),
            "the positive half must not be passing via the trust store, or it proves nothing \
             about x5c"
        );

        // NEGATIVE: same CA, same signing key, same claims -- a leaf issued for a
        // DIFFERENT NF. The chain validates; the binding does not.
        let other_leaf = cca_test_leaf(&key, "6b1d7e3c-0000-4000-8000-00000000dead", &ca, &ca_key);
        let impersonating = nextgcore_sbi::oauth::mint_cca(
            &key,
            &consumer_id,
            "NRF",
            now,
            60,
            std::slice::from_ref(&other_leaf),
        );
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(
                &consumer_id,
                &ctype,
                &producer_id,
                Some(&impersonating),
                None,
            ),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "a certificate issued for a DIFFERENT NF must be refused (TS 33.501 §13.3.8.3): {:?}",
            resp.http.content
        );
        let err = error_of(&resp);
        assert_eq!(err["error"], "invalid_client");
        let desc = err["error_description"].as_str().unwrap_or_default();
        // Criterion 2 asks for the reason to NAME the mismatch. Both ids, so an
        // operator can tell a misissued certificate from an impersonation attempt.
        assert!(
            desc.contains("6b1d7e3c-0000-4000-8000-00000000dead") && desc.contains(&consumer_id),
            "the refusal must name BOTH the certificate's id and the asserted one, or the \
             failure is undiagnosable: {desc:?}"
        );

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #393, the anti-downgrade property.** A CCA that carries `x5c`
    /// against an NRF with no `cca_trust_anchors` is refused **even though the
    /// trust store holds a good key for that NF**.
    ///
    /// This is the test that proves the precedence in `resolve_cca_verifying_key`
    /// is a decision table and not an `unwrap_or` chain. If it were a fallback, a
    /// requester could choose which check it faces simply by attaching a
    /// certificate — and attaching a deliberately broken one would be the way to
    /// reach the weaker path.
    ///
    /// Revert-verified: changing the empty-anchors arm to fall through to the
    /// trust store makes this fail with status 200.
    #[tokio::test]
    async fn an_x5c_bearing_cca_is_refused_rather_than_downgraded_to_the_trust_store() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd393down");
        let (_, ca, ca_key) = cca_test_ca();

        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let leaf = cca_test_leaf(&key, &consumer_id, &ca, &ca_key);

        // The trust store WOULD accept this key. The CA is deliberately not
        // configured.
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(consumer_id.clone(), *key.verifying_key());
        let policy = NrfPolicy {
            cca_trusted_keys: trusted,
            cca_trust_anchors: Vec::new(),
            ..NrfPolicy::default()
        };

        // Control: with NO x5c the very same key authenticates via the store, so
        // the refusal below is attributable to x5c and not to a bad key.
        let plain = nextgcore_sbi::oauth::mint_cca(&key, &consumer_id, "NRF", now, 60, &[]);
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&plain), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "control: without x5c this key must still authenticate via the trust store, or this \
             test is not isolating the downgrade question: {:?}",
            resp.http.content
        );

        // Same key, same claims, now WITH x5c and no anchors: refused.
        let with_chain = nextgcore_sbi::oauth::mint_cca(
            &key,
            &consumer_id,
            "NRF",
            now,
            60,
            std::slice::from_ref(&leaf),
        );
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&with_chain), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "an x5c-bearing CCA must NOT fall back to the trust store: falling back would let a \
             requester choose the weaker check: {:?}",
            resp.http.content
        );
        let desc = error_of(&resp)["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            desc.contains("cca_trust_anchors"),
            "the refusal must name the missing configuration: {desc:?}"
        );

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #393: the certificate must be the AUTHORITY, not decoration.**
    ///
    /// A CCA whose `x5c` chain validates, and whose leaf URI SAN matches `sub`,
    /// but whose JWS was signed by a DIFFERENT key than the certificate certifies,
    /// must be refused.
    ///
    /// Without this the implementation could validate a chain, check the SAN, and
    /// then verify the signature against a trust-store key — which would be
    /// theatre: the certificate would constrain nothing about who actually signed
    /// the assertion. So the trust store here holds the signer's key, and the
    /// request must STILL be refused.
    ///
    /// Revert-verified: making `resolve_cca_verifying_key` return the trust-store
    /// key on the `Chain` arm instead of `verified.es256_verifying_key()` makes
    /// this fail with status 200.
    #[tokio::test]
    async fn a_cca_signed_by_a_key_its_certificate_does_not_certify_is_refused() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd393auth");
        let (ca_der, ca, ca_key) = cca_test_ca();

        let certified = nextgcore_sbi::oauth::generate_es256_key();
        let actual_signer = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // The leaf certifies `certified` and names the right NF.
        let leaf = cca_test_leaf(&certified, &consumer_id, &ca, &ca_key);
        // The assertion is signed by `actual_signer` and carries that same leaf.
        let cca = nextgcore_sbi::oauth::mint_cca(
            &actual_signer,
            &consumer_id,
            "NRF",
            now,
            60,
            std::slice::from_ref(&leaf),
        );

        // The trust store holds the ACTUAL signer's key, so an implementation that
        // verified against the store would accept this.
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(consumer_id.clone(), *actual_signer.verifying_key());
        let policy = NrfPolicy {
            cca_trusted_keys: trusted,
            cca_trust_anchors: vec![ca_der],
            ..NrfPolicy::default()
        };

        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "the signature MUST be verified against the key the certificate certifies; \
             verifying against the trust store while carrying a certificate would make the \
             certificate decorative: {:?}",
            resp.http.content
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #393: a chain from an unconfigured CA is refused.** The positive
    /// case must not be reachable with a self-issued certificate, or `x5c` would be
    /// strictly weaker than the trust store it takes precedence over.
    #[tokio::test]
    async fn a_cca_chain_from_an_unconfigured_ca_is_refused() {
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd393ca");
        let (_, rogue_ca, rogue_key) = cca_test_ca();
        let (trusted_ca_der, _, _) = cca_test_ca();

        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // A leaf naming the right NF, from the WRONG CA.
        let leaf = cca_test_leaf(&key, &consumer_id, &rogue_ca, &rogue_key);
        let cca = nextgcore_sbi::oauth::mint_cca(
            &key,
            &consumer_id,
            "NRF",
            now,
            60,
            std::slice::from_ref(&leaf),
        );

        let policy = NrfPolicy {
            cca_trust_anchors: vec![trusted_ca_der],
            ..NrfPolicy::default()
        };
        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "a chain that does not reach a configured anchor must be refused, or anyone could \
             self-issue a certificate naming any NF: {:?}",
            resp.http.content
        );
        assert_eq!(error_of(&resp)["error"], "invalid_client");

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #393, the stated ceiling.** A CCA that chose §13.3.8.2's OTHER arm
    /// (`x5u`) is refused with a reason that NAMES `x5u` as unsupported.
    ///
    /// Asserted rather than merely documented: a conformant peer sending `x5u` gets
    /// told which arm this NRF implements, instead of a generic parse error that
    /// would send an integrator looking in the wrong place. The reasoning for not
    /// implementing `x5u` (pre-authentication SSRF, requester-controlled latency on
    /// the auth path) is in `nextgcore_sbi::cca_x5c`.
    #[tokio::test]
    async fn a_cca_using_x5u_is_refused_with_a_reason_naming_it() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let (consumer_id, producer_id, ctype, _ptype) = register_pair("nrfd393x5u");

        let key = nextgcore_sbi::oauth::generate_es256_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Hand-built, because `mint_cca` deliberately cannot emit `x5u`: this is a
        // conformant PEER's assertion, not one of ours. The URL is the cloud
        // metadata endpoint, which is what an SSRF against this would target.
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "alg": "ES256",
                "typ": "JWT",
                "x5u": "http://169.254.169.254/latest/meta-data/",
            })
            .to_string(),
        );
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": consumer_id, "iss": consumer_id, "aud": "NRF",
                "iat": now, "exp": now + 60,
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{payload}");
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
        let cca = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

        // Even with this NF's key in the trust store, `x5u` is refused -- it is not
        // silently ignored in favour of the store.
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(consumer_id.clone(), *key.verifying_key());
        let policy = NrfPolicy {
            cca_trusted_keys: trusted,
            ..NrfPolicy::default()
        };

        let resp = handle_access_token_request_with_policy(
            &auth_token_req(&consumer_id, &ctype, &producer_id, Some(&cca), None),
            &policy,
        )
        .await;
        assert_eq!(
            resp.status, 400,
            "x5u is not implemented and must be refused, not ignored: {:?}",
            resp.http.content
        );
        let desc = error_of(&resp)["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            desc.contains("x5u") && desc.contains("x5c"),
            "the refusal must name the unsupported arm AND the supported one: {desc:?}"
        );

        let mgr = nf_manager();
        mgr.deregister(&consumer_id).ok();
        mgr.deregister(&producer_id).ok();
    }

    /// **Issue #393 criterion 3.** The trust-store path is UNCHANGED for a CCA
    /// with no `x5c`, so #187's overlay and its coverage do not regress.
    ///
    /// The strongest form of that claim available in a unit test: `mint_cca` with
    /// no chain must produce a byte-identical JOSE header to the fixed literal it
    /// replaced. If the header changed at all, every deployment's CCAs would change
    /// shape, and "nothing regressed" would rest on the NRF being lenient rather
    /// than on the bytes being the same.
    #[test]
    fn minting_without_a_chain_reproduces_the_pre_393_header_exactly() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let key = nextgcore_sbi::oauth::generate_es256_key();
        let cca = nextgcore_sbi::oauth::mint_cca(&key, "nf-1", "NRF", 1_000, 60, &[]);
        let header_b64 = cca.split('.').next().expect("header");
        assert_eq!(
            header_b64,
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
            "with no chain the header must be byte-identical to the literal it replaced, or \
             every existing deployment's CCAs change shape"
        );
        // And the x5c-less header carries no certificate reference at all.
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).expect("b64"))
                .expect("json");
        assert!(header.get("x5c").is_none() && header.get("x5u").is_none());
    }

    /// **Issue #393: `mint_cca` emits a real `x5c`** that the NRF's own parser
    /// reads back as the DER that went in (criterion 1).
    ///
    /// The two halves live in different crates — `mint_cca` encodes, nrfd decodes —
    /// and RFC 7515 §4.1.6 requires STANDARD base64 for `x5c` while the JWS parts
    /// themselves are base64url. That asymmetry is the classic x5c interop bug, so
    /// the round trip is asserted rather than assumed.
    #[test]
    fn mint_cca_emits_an_x5c_the_nrf_decodes_back_to_the_same_der() {
        use nextgcore_sbi::cca_x5c::{cert_reference_from_jose_header, CcaCertReference};
        let (_, ca, ca_key) = cca_test_ca();
        let key = nextgcore_sbi::oauth::generate_es256_key();
        let leaf = cca_test_leaf(&key, "nf-x5c-roundtrip", &ca, &ca_key);

        let cca = nextgcore_sbi::oauth::mint_cca(
            &key,
            "nf-x5c-roundtrip",
            "NRF",
            1_000,
            60,
            std::slice::from_ref(&leaf),
        );
        let header = decode_cca_jose_header(&cca).expect("the header must decode");
        assert_eq!(
            header["alg"], "ES256",
            "alg must survive the header rebuild"
        );
        assert_eq!(header["typ"], "JWT");

        match cert_reference_from_jose_header(&header).expect("x5c parses") {
            CcaCertReference::Chain(chain) => assert_eq!(
                chain.leaf(),
                leaf.as_slice(),
                "the DER must round-trip; RFC 7515 §4.1.6 is standard base64, not base64url"
            ),
            other => panic!("expected an x5c chain, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // nrfd-06: per-path server-side OAuth2 enforcement (TS 33.501 §13.4.1)
    // -----------------------------------------------------------------

    /// Mint an NRF-signed ES256 access token (as the token endpoint does), with
    /// scope `nnrf-nfm nnrf-disc` (#1634).
    fn mint_nrf_token(sub: &str, aud: &str, exp_offset: i64) -> String {
        mint_nrf_token_with(
            sub,
            &serde_json::json!(aud),
            "nnrf-nfm nnrf-disc",
            exp_offset,
        )
    }

    /// [`mint_nrf_token`] with any `aud` and `scope`.
    pub(super) fn mint_nrf_token_with(
        sub: &str,
        aud: &serde_json::Value,
        scope: &str,
        exp_offset: i64,
    ) -> String {
        mint_nrf_token_from(nrf_instance_id(), sub, aud, scope, exp_offset)
    }

    /// [`mint_nrf_token_with`] under any `iss`, still signed with this NRF's key.
    fn mint_nrf_token_from(
        iss: &str,
        sub: &str,
        aud: &serde_json::Value,
        scope: &str,
        exp_offset: i64,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{NRF_KID}"}}"#);
        let claims = serde_json::json!({
            "iss": iss, "sub": sub, "aud": aud, "scope": scope,
            "exp": (now + exp_offset) as u64, "iat": now as u64,
        });
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig: Signature = nrf_signing_key().sign(signing_input.as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    #[test]
    fn test_nrfd_06_protected_path_classification() {
        assert!(oauth2_protected_path("/nnrf-nfm/v1/nf-instances/x"));
        assert!(oauth2_protected_path("/nnrf-disc/v1/nf-instances"));
        assert!(!oauth2_protected_path("/nnrf-oauth2/v1/access-token"));
        assert!(!oauth2_protected_path("/nnrf-oauth2/v1/jwks"));
        assert!(!oauth2_protected_path("/"));
    }

    /// nrfd-06's gate keeps the subject of the token it verified (#1611).
    #[test]
    fn the_oauth2_gate_returns_the_verified_subject_1611() {
        let jwks = nrf_jwks_json();
        let auth = format!("Bearer {}", mint_nrf_token("nf-g", "NRF", 3600));
        assert_eq!(
            oauth2_gate("/nnrf-nfm/v1/nf-instances/x", Some(&auth), true, &jwks)
                .ok()
                .flatten()
                .as_deref(),
            Some("nf-g")
        );
        assert_eq!(
            oauth2_gate("/nnrf-nfm/v1/nf-instances/x", Some(&auth), false, &jwks).ok(),
            Some(None),
            "not required: nothing verified, nothing recorded"
        );
        assert!(oauth2_gate("/nnrf-nfm/v1/nf-instances/x", None, true, &jwks).is_err());
    }

    /// #1634: the gate accepts only a token for this API on this NRF.
    /// - Accepted: scope naming the invoked service, aud `NRF` or this NRF's instance
    ///   ID (also inside an array, and in another case).
    /// - 403 insufficient_scope (with the required scope in the challenge): another
    ///   service's scope, or `nnrf-disc` only on nnrf-nfm, or a scope that merely
    ///   starts with the service name.
    /// - 403 ACCESS_TOKEN_CLAIM_MISMATCH / invalid_token: aud of another NF type or
    ///   instance.
    /// - 401: no token (challenge without `error`), a forged token (`invalid_token`).
    ///
    /// REVERT-VERIFIED: without the scope check the foreign-scope tokens pass; without
    /// the audience check the foreign-audience tokens pass.
    #[test]
    fn the_oauth2_gate_requires_this_api_s_scope_and_this_nrf_as_audience_1634() {
        use serde_json::json;
        let jwks = nrf_jwks_json();
        let nfm = "/nnrf-nfm/v1/nf-instances/x";
        let gate = |path: &str, token: Option<String>| {
            let auth = token.map(|t| format!("Bearer {t}"));
            oauth2_gate(path, auth.as_deref(), true, &jwks)
        };
        let tok = |aud: serde_json::Value, scope: &str| {
            Some(mint_nrf_token_with("nf-1634", &aud, scope, 3600))
        };
        let www = |r: &SbiResponse| {
            r.http
                .get_header("WWW-Authenticate")
                .cloned()
                .unwrap_or_default()
        };
        let cause = |r: &SbiResponse| {
            serde_json::from_str::<serde_json::Value>(r.http.content.as_deref().unwrap_or("{}"))
                .unwrap_or_default()["cause"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };

        for (aud, scope) in [
            (json!("NRF"), "nnrf-nfm"),
            (json!(nrf_instance_id()), "nnrf-disc nnrf-nfm"),
            (
                json!(["AMF", nrf_instance_id().to_ascii_uppercase()]),
                "nnrf-nfm",
            ),
        ] {
            assert_eq!(
                gate(nfm, tok(aud.clone(), scope)).ok().flatten().as_deref(),
                Some("nf-1634"),
                "{aud} {scope}"
            );
        }
        assert!(gate("/nnrf-disc/v1/nf-instances", tok(json!("NRF"), "nnrf-disc")).is_ok());

        for (path, scope) in [
            (nfm, "nsmf-pdusession"),
            (nfm, "nnrf-disc"),
            (nfm, "nnrf-nfmx"),
            (nfm, ""),
            ("/nnrf-disc/v1/nf-instances", "nnrf-nfm"),
        ] {
            let r = *gate(path, tok(json!("NRF"), scope)).expect_err(scope);
            assert_eq!(r.status, 403, "{path} {scope:?}");
            assert_eq!(cause(&r), "", "TS 29.500 defines no cause for it");
            assert!(
                www(&r).contains("error=\"insufficient_scope\""),
                "{}",
                www(&r)
            );
            let service = path.split('/').nth(1).unwrap();
            assert!(
                www(&r).contains(&format!("scope=\"{service}\"")),
                "{}",
                www(&r)
            );
        }

        for aud in [json!("SMF"), json!(["smf-instance-1"]), json!(42)] {
            let r = *gate(nfm, tok(aud.clone(), "nnrf-nfm")).expect_err("aud");
            assert_eq!(r.status, 403, "{aud}");
            assert_eq!(cause(&r), "ACCESS_TOKEN_CLAIM_MISMATCH");
            assert!(www(&r).contains("error=\"invalid_token\""));
            let body: serde_json::Value =
                serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(body["invalidParams"][0]["param"], "aud");
        }

        // #1644 review: a token another issuer minted (were its key ever trusted).
        let foreign =
            mint_nrf_token_from("another-nrf", "nf-1634", &json!("NRF"), "nnrf-nfm", 3600);
        let r = *gate(nfm, Some(foreign)).expect_err("iss");
        assert_eq!(r.status, 403);
        assert_eq!(cause(&r), "ACCESS_TOKEN_CLAIM_MISMATCH");
        let body: serde_json::Value =
            serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["invalidParams"][0]["param"], "iss");

        // RFC 6750 §3.1: another scheme is no Bearer token, so no `error`.
        let r = *oauth2_gate(nfm, Some("Basic dXNlcjpwdw=="), true, &jwks).expect_err("basic");
        assert_eq!(r.status, 401);
        assert!(!www(&r).contains("error="), "{}", www(&r));

        let r = *gate(nfm, None).expect_err("no token");
        assert_eq!(r.status, 401);
        assert!(www(&r).starts_with("Bearer realm=") && !www(&r).contains("error="));
        let r = *gate(nfm, Some("e30.e30.AAAA".to_string())).expect_err("forged");
        assert_eq!(r.status, 401);
        assert!(www(&r).contains("error=\"invalid_token\""));
    }

    /// #1644 review B1: a token the NRF's own token endpoint issues for its APIs
    /// passes the gate. Both forms the endpoint mints: `targetNfType: NRF` (aud
    /// "NRF") and `targetNfInstanceId` = this NRF (aud [its instance ID]), for
    /// nnrf-disc and nnrf-nfm.
    ///
    /// REVERT-VERIFIED: with only nnrf-oauth2 in the NRF's self profile, the token
    /// endpoint answers invalid_scope.
    #[tokio::test]
    async fn a_token_the_nrf_issues_for_its_own_apis_passes_the_gate_1644() {
        use serde_json::json;
        let consumer = "1644c0c0-0000-4000-8000-0000000000a1";
        nf_manager()
            .register(
                NfProfile::from_json(&json!({
                    "nfInstanceId": consumer, "nfType": "AMF", "nfStatus": "REGISTERED",
                }))
                .unwrap(),
            )
            .unwrap();
        let _self_entry = self_entry_test_lock().lock().await;
        register_self_with_own_registry();
        let jwks = nrf_jwks_json();
        let policy = policy_without_client_auth();
        for (target, scope, path) in [
            (
                json!({"targetNfType": "NRF"}),
                "nnrf-disc",
                "/nnrf-disc/v1/nf-instances",
            ),
            (
                json!({"targetNfType": "NRF"}),
                "nnrf-nfm",
                "/nnrf-nfm/v1/nf-instances/x",
            ),
            (
                json!({"targetNfInstanceId": nrf_instance_id()}),
                "nnrf-disc",
                "/nnrf-disc/v1/nf-instances",
            ),
            (
                json!({"targetNfInstanceId": nrf_instance_id()}),
                "nnrf-nfm",
                "/nnrf-nfm/v1/nf-instances/x",
            ),
        ] {
            let mut body = json!({
                "grant_type": "client_credentials", "nfInstanceId": consumer,
                "nfType": "AMF", "scope": scope,
            });
            body.as_object_mut()
                .unwrap()
                .extend(target.as_object().unwrap().clone());
            let mut req = SbiRequest::post("/nnrf-oauth2/v1/access-token");
            req.http.set_content(body.to_string());
            let resp = handle_access_token_request_with_policy(&req, &policy).await;
            assert_eq!(
                resp.status, 200,
                "{target} {scope}: {:?}",
                resp.http.content
            );
            let token: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let auth = format!("Bearer {}", token["access_token"].as_str().unwrap());
            assert_eq!(
                oauth2_gate(path, Some(&auth), true, &jwks)
                    .map_err(|r| r.http.content.clone())
                    .unwrap()
                    .as_deref(),
                Some(consumer),
                "{target} {scope}"
            );
        }
        nf_manager().deregister(consumer).ok();
    }

    /// #1644 review M2: with persistence on, a restart restores the NRF's own entry
    /// and re-arms every restored profile's no-heartbeat timer. The NRF's own entry
    /// must get none, in either order of restore and self-registration, so it stays
    /// REGISTERED past the heartbeat window and its token endpoint keeps issuing.
    ///
    /// REVERT-VERIFIED: without the guard in `arm_heartbeat_timer` (and the disarm in
    /// `register_self_with_own_registry`), a timer is armed for the entry.
    #[tokio::test]
    async fn the_nrf_s_own_entry_never_gets_a_heartbeat_timer_1644() {
        let _self_entry = self_entry_test_lock().lock().await;
        let armed = || {
            HEARTBEAT_TIMERS
                .lock()
                .expect("timers")
                .contains_key(nrf_instance_id())
        };
        register_self_with_own_registry();
        rearm_restored_timers();
        assert!(!armed(), "restore after self-registration");
        register_self_with_own_registry();
        assert!(!armed(), "self-registration after restore");
        arm_heartbeat_timer(nrf_instance_id(), Duration::from_secs(1));
        assert!(!armed(), "nor through any other caller");
        assert_eq!(
            nf_manager()
                .get(nrf_instance_id())
                .expect("the entry stays")
                .nf_status,
            "REGISTERED"
        );
    }

    /// #1644 review m4: the NRF registers itself whenever either its own token
    /// requests or its gated APIs need it, and only then.
    #[test]
    fn the_nrf_registers_itself_when_its_tokens_need_it_1644() {
        assert!(
            registers_itself(true, false),
            "it requests tokens from itself"
        );
        assert!(
            registers_itself(false, true),
            "its APIs require tokens it must issue"
        );
        assert!(registers_itself(true, true));
        assert!(!registers_itself(false, false), "nothing needs the entry");
    }

    #[test]
    fn test_nrfd_06_enforce_oauth2_decisions() {
        let jwks = nrf_jwks_json();

        // Default OFF -> always allowed (matched-sim path preserved).
        assert!(
            enforce_oauth2_on_request("/nnrf-disc/v1/nf-instances", None, false, &jwks).is_none()
        );
        // Enforcement ON, protected path, no token -> 401.
        let r = enforce_oauth2_on_request("/nnrf-disc/v1/nf-instances", None, true, &jwks);
        assert_eq!(r.expect("must reject").status, 401);
        // The token + jwks endpoints stay exempt even with enforcement ON.
        assert!(
            enforce_oauth2_on_request("/nnrf-oauth2/v1/access-token", None, true, &jwks).is_none()
        );
        assert!(enforce_oauth2_on_request("/nnrf-oauth2/v1/jwks", None, true, &jwks).is_none());
        // A valid NRF-issued token on a protected path -> allowed.
        let auth = format!("Bearer {}", mint_nrf_token("sub-x", "NRF", 3600));
        assert!(
            enforce_oauth2_on_request("/nnrf-nfm/v1/nf-instances/x", Some(&auth), true, &jwks)
                .is_none()
        );
    }

    // -----------------------------------------------------------------
    // nrfd-07: producer/consumer optional claims (TS 29.510 §6.3.5.2.4)
    // -----------------------------------------------------------------

    /// **Issue #64 gap 4.** The signing key must SURVIVE a restart: the whole
    /// defect was that a per-process key under a fixed `kid` made every restart and
    /// every HA replica publish a different public key for the same `kid`, so a
    /// producer with a cached JWKS rejected still-valid tokens.
    #[test]
    fn signing_key_persists_across_loads() {
        let dir = std::env::temp_dir().join(format!("nrfd-key-{}", std::process::id()));
        let path = dir.join("nested").join("signing.key");
        let _ = std::fs::remove_dir_all(&dir);

        // First load creates the file (including parent directories).
        let first = load_or_create_signing_key(&path).expect("first load creates a key");
        assert!(path.exists(), "the key must be persisted");

        // A second load returns THE SAME key -- this is the property that makes a
        // restart or a second replica safe.
        let second = load_or_create_signing_key(&path).expect("second load reuses it");
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "reloading must yield the identical key, or tokens signed before the \
             restart stop verifying"
        );
        // And so the published public key is stable too.
        assert_eq!(
            first.verifying_key().to_encoded_point(false).as_bytes(),
            second.verifying_key().to_encoded_point(false).as_bytes()
        );

        // Owner-only permissions: this signs every access token in the PLMN.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the key file must not be world-readable"
            );
        }

        // A corrupt file is an ERROR, never a silent regeneration -- regenerating
        // would reproduce the very defect being fixed.
        std::fs::write(&path, "not-hex").expect("write");
        assert!(
            load_or_create_signing_key(&path).is_err(),
            "a malformed key file must fail loudly"
        );
        // Right encoding, wrong length is also rejected.
        std::fs::write(&path, "aabbcc").expect("write");
        assert!(load_or_create_signing_key(&path).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #64 gap 4: `expires_in` is operator-configurable and defaults to the
    /// previously hardcoded hour.
    #[test]
    fn token_lifetime_defaults_to_one_hour() {
        // The OnceLock is process-global and other tests may not have set it; the
        // default is what matters here.
        assert_eq!(DEFAULT_TOKEN_EXPIRES_IN_SECS, 3600);
        let effective = nrf_token_expires_in();
        assert!(
            effective > 0,
            "a zero lifetime would mint already-expired tokens"
        );
        assert_eq!(
            effective,
            *NRF_TOKEN_EXPIRES_IN
                .get()
                .unwrap_or(&DEFAULT_TOKEN_EXPIRES_IN_SECS)
        );
    }

    #[test]
    fn test_nrfd_07_instance_scoped_claims() {
        use serde_json::json;
        let consumer = NfProfile::from_json(&json!({
            "nfInstanceId": "c-1", "nfType": "SMF", "nfStatus": "REGISTERED",
            "plmnList": [{"mcc": "001", "mnc": "01"}]
        }))
        .unwrap();
        let producer = NfProfile::from_json(&json!({
            "nfInstanceId": "p-1", "nfType": "UDM", "nfStatus": "REGISTERED",
            "plmnList": [{"mcc": "001", "mnc": "01"}],
            "sNssais": [{"sst": 1, "sd": "010203"}],
            // Issue #64 gap 5: the REAL TS 29.510 NFProfile members. This fixture
            // used to carry `"nfSetId": "set-udm-1"`, which NFProfile does not
            // define -- it was only constructible because profile attributes are
            // stored unvalidated, so the test passed while pinning the bug.
            "nfSetIdList": ["set-udm-1", "set-udm-2"],
            "nsiList": ["nsi-001", "nsi-002"]
        }))
        .unwrap();

        // Instance-scoped: aud is the instance-ID array + producer claims set.
        let claims = build_access_token_claims(
            "nrf-iss",
            "c-1",
            "UDM",
            Some(&producer),
            &consumer,
            "nudm-sdm",
            100,
            3700,
        );
        assert_eq!(claims["aud"], json!(["p-1"]));
        assert_eq!(
            claims["producerSnssaiList"],
            json!([{"sst": 1, "sd": "010203"}])
        );
        assert_eq!(claims["consumerPlmnId"], json!({"mcc": "001", "mnc": "01"}));
        assert_eq!(claims["producerPlmnId"], json!({"mcc": "001", "mnc": "01"}));
        // producerNfSetId is a SINGLE NfSetId taken from nfSetIdList.
        assert_eq!(claims["producerNfSetId"], json!("set-udm-1"));
        // producerNsiList carries NSI-IDs from nsiList -- NOT the NF Set IDs it
        // used to be filled with, which is the interop half of gap 5.
        assert_eq!(claims["producerNsiList"], json!(["nsi-001", "nsi-002"]));
        assert_ne!(
            claims["producerNsiList"],
            json!(["set-udm-1", "set-udm-2"]),
            "producerNsiList must not carry NF Set IDs"
        );

        // A profile carrying ONLY the non-spec `nfSetId` yields neither claim:
        // that member does not exist in TS 29.510, so nothing may be derived from
        // it. This is the assertion the old fixture made impossible.
        let bogus = NfProfile::from_json(&json!({
            "nfInstanceId": "p-2", "nfType": "UDM", "nfStatus": "REGISTERED",
            "nfSetId": "set-udm-9"
        }))
        .unwrap();
        let bogus_claims = build_access_token_claims(
            "nrf-iss",
            "c-1",
            "UDM",
            Some(&bogus),
            &consumer,
            "nudm-sdm",
            100,
            3700,
        );
        assert!(
            bogus_claims.get("producerNfSetId").is_none(),
            "a non-spec nfSetId member must not populate the claim: {bogus_claims}"
        );
        assert!(bogus_claims.get("producerNsiList").is_none());

        // Type-scoped (no instance): aud is the bare NF type string.
        let claims2 = build_access_token_claims(
            "nrf-iss", "c-1", "UDM", None, &consumer, "nudm-sdm", 100, 3700,
        );
        assert_eq!(claims2["aud"], json!("UDM"));
        assert!(claims2.get("producerSnssaiList").is_none());
    }

    // -----------------------------------------------------------------
    // nrfd-08: full SubscriptionData + NRF-assigned validityTime
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_08_epoch_to_rfc3339() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn test_nrfd_08_subscription_response_full_fields() {
        use nextgcore_nrfd::nnrf_handler::SubscrCond;
        use nextgcore_nrfd::SubscriptionData;
        let sub = SubscriptionData {
            id: "sub-08".to_string(),
            req_nf_type: Some("AMF".to_string()),
            req_nf_instance_id: Some("amf-1".to_string()),
            notification_uri: "http://amf/cb".to_string(),
            subscr_cond: Some(SubscrCond::nf_type("SMF")),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
            owner: None,
        };
        let body = subscription_response_json(&sub, "2023-11-14T22:13:20Z");
        assert_eq!(body["subscriptionId"], "sub-08");
        assert_eq!(body["nfStatusNotificationUri"], "http://amf/cb");
        assert_eq!(body["reqNfType"], "AMF");
        assert_eq!(body["reqNfInstanceId"], "amf-1");
        assert_eq!(body["subscrCond"]["nfType"], "SMF");
        assert_eq!(body["validityTime"], "2023-11-14T22:13:20Z");
    }

    // -----------------------------------------------------------------
    // nrfd-09: percent-decoded form-urlencoded token body
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_09_form_body_percent_decoded() {
        let body = "grant_type=client_credentials&nfInstanceId=urn%3Auuid%3Aabc-123\
                    &nfType=SMF&targetNfType=UDM&scope=nudm-sdm+nudm-uecm";
        let req = parse_token_request(body);
        assert_eq!(req.grant_type, "client_credentials");
        // %3A -> ':' so the URN round-trips through the authorization check.
        assert_eq!(req.nf_instance_id, "urn:uuid:abc-123");
        assert_eq!(req.nf_type, "SMF");
        assert_eq!(req.target_nf_type, "UDM");
        // '+' -> space in the scope list.
        assert_eq!(req.scope, "nudm-sdm nudm-uecm");
    }

    // -----------------------------------------------------------------
    // nrfd-10: discovery pagination + configurable validityPeriod
    // -----------------------------------------------------------------

    #[test]
    fn test_nrfd_10_paginate_results() {
        use serde_json::json;
        let items: Vec<serde_json::Value> = (0..50).map(|i| json!({ "n": i })).collect();

        // 50 instances, default cap 25 -> 25 returned + more pages exist.
        let (page1, more1) = paginate_results(items.clone(), 1, 25);
        assert_eq!(page1.len(), 25);
        assert!(more1, "page 1 of 50@25 must signal a continuation");
        assert_eq!(page1[0]["n"], 0);

        // Page 2 returns the rest, no further pages.
        let (page2, more2) = paginate_results(items.clone(), 2, 25);
        assert_eq!(page2.len(), 25);
        assert!(!more2);
        assert_eq!(page2[0]["n"], 25);

        // Page past the end -> empty, no more.
        let (page3, more3) = paginate_results(items, 3, 25);
        assert!(page3.is_empty());
        assert!(!more3);

        // validityPeriod default reflects policy (config-driven, nrfd-10).
        assert_eq!(nrf_policy().disc_validity_period, NRF_DISC_VALIDITY_PERIOD);
    }

    // ================================================================
    // nextgcore #68: subscription PATCH, validityTime parsing
    // ================================================================

    /// TS 29.510: validityTime is a DateTime STRING, not an integer duration.
    /// Round-tripping through the emitter proves the two agree, which is what
    /// makes the PATCH handler's duration arithmetic trustworthy.
    #[test]
    fn rfc3339_round_trips_with_the_emitter() {
        for secs in [0u64, 1, 1_000_000_000, 1_700_000_000, 2_000_000_000] {
            let text = epoch_to_rfc3339(secs);
            assert_eq!(
                rfc3339_to_epoch(&text),
                Some(secs),
                "{text} must parse back to {secs}"
            );
        }
    }

    /// INVERTED by PR #250: a non-UTC offset is now APPLIED rather than rejected.
    ///
    /// This asserted `+02:00` parsed to `None`, on the reasoning that misreading an
    /// offset shifts a subscription's expiry by hours. The reasoning was right about
    /// the hazard and wrong about the remedy — the hazard is IGNORING the offset, and
    /// honouring it avoids that without refusing conformant input. Refusing was
    /// actively worse: every consumer of this function reads `None` as "no deadline",
    /// so a conformant `+02:00` expiry made bsfd's #98 subscription matcher and
    /// nsacfd's #96 report decision treat a LAPSED subscription as live. See the
    /// reasoning on `nextgcore_sbi::datetime::rfc3339_to_epoch_signed`.
    ///
    /// The flip is recorded rather than the old assertion deleted, because this
    /// widening is the kind of change a reader should be able to find. It was
    /// invisible to CI on either PR: nrfd only became a CONSUMER of the shared parser
    /// in #246, the parser only started applying offsets in #250, and no branch
    /// contained both — git merged them clean and `main` went red.
    #[test]
    fn rfc3339_applies_a_non_utc_offset_and_rejects_malformed_input() {
        // 12:00 in a +02:00 zone is 10:00 UTC. Subtracting the offset, not ignoring
        // it, is what makes these equal.
        assert_eq!(
            rfc3339_to_epoch("2026-09-07T12:00:00+02:00"),
            rfc3339_to_epoch("2026-09-07T10:00:00Z"),
            "a positive offset is subtracted"
        );
        assert_eq!(
            rfc3339_to_epoch("2026-09-07T12:00:00-05:00"),
            rfc3339_to_epoch("2026-09-07T17:00:00Z"),
            "a negative offset is added"
        );
        // The sign matters: reading -05:00 as +05:00 would be a ten-hour error.
        assert_ne!(
            rfc3339_to_epoch("2026-09-07T12:00:00-05:00"),
            rfc3339_to_epoch("2026-09-07T12:00:00+05:00")
        );
        // Still refused, because a naive local time names no instant at all.
        assert!(rfc3339_to_epoch("2026-09-07T12:00:00").is_none(), "no zone");
        assert!(rfc3339_to_epoch("not-a-date").is_none());
        assert!(rfc3339_to_epoch("").is_none());
        assert!(rfc3339_to_epoch("2026-09-07").is_none(), "no time part");
        assert!(
            rfc3339_to_epoch("2026-13-07T12:00:00Z").is_none(),
            "month 13"
        );
        assert!(
            rfc3339_to_epoch("2026-09-07T25:00:00Z").is_none(),
            "hour 25"
        );
        // Explicit UTC spellings and fractional seconds are accepted.
        assert!(rfc3339_to_epoch("2026-09-07T12:00:00Z").is_some());
        assert!(rfc3339_to_epoch("2026-09-07T12:00:00+00:00").is_some());
        assert!(rfc3339_to_epoch("2026-09-07T12:00:00.500Z").is_some());
    }

    /// The patch resource accepts both a JSON Patch array and a merge-patch
    /// object; validityTime must be found in either.
    #[test]
    fn patch_validity_time_is_extracted_from_both_patch_forms() {
        let merge = serde_json::json!({"validityTime": "2026-09-08T00:00:00Z"});
        assert_eq!(
            extract_patch_validity_time(&merge).as_deref(),
            Some("2026-09-08T00:00:00Z")
        );

        let json_patch = serde_json::json!([
            {"op": "replace", "path": "/validityTime", "value": "2026-09-09T00:00:00Z"}
        ]);
        assert_eq!(
            extract_patch_validity_time(&json_patch).as_deref(),
            Some("2026-09-09T00:00:00Z")
        );

        // `add` is accepted as well as `replace`.
        let added = serde_json::json!([
            {"op": "add", "path": "/validityTime", "value": "2026-09-10T00:00:00Z"}
        ]);
        assert_eq!(
            extract_patch_validity_time(&added).as_deref(),
            Some("2026-09-10T00:00:00Z")
        );

        // A sequence of operations applies in order, so the LAST one wins.
        let sequence = serde_json::json!([
            {"op": "replace", "path": "/validityTime", "value": "2026-09-11T00:00:00Z"},
            {"op": "replace", "path": "/validityTime", "value": "2026-09-12T00:00:00Z"}
        ]);
        assert_eq!(
            extract_patch_validity_time(&sequence).as_deref(),
            Some("2026-09-12T00:00:00Z"),
            "the last operation must win"
        );

        // Operations on other paths are ignored rather than mistaken for it.
        let other = serde_json::json!([
            {"op": "replace", "path": "/notificationUri", "value": "http://x"}
        ]);
        assert!(extract_patch_validity_time(&other).is_none());
        assert!(extract_patch_validity_time(&serde_json::json!({})).is_none());
    }

    /// The PATCH must actually replace the stored validity, not return a
    /// bodyless 200 while the subscription keeps its original expiry.
    #[tokio::test]
    async fn subscription_patch_replaces_validity_and_404s_for_unknown_id() {
        nextgcore_nrfd::init_nf_manager(None);
        let manager = nf_manager();
        let owned = |mut r: SbiRequest| {
            r.peer_cert_nf_instance_id = Some("sub-68-owner".into());
            r
        };

        let sub = nextgcore_nrfd::SubscriptionData {
            id: "sub-68".to_string(),
            req_nf_type: None,
            req_nf_instance_id: None,
            notification_uri: "http://consumer/notify".to_string(),
            subscr_cond: None,
            validity_duration: 60,
            req_notif_events: None,
            notif_condition: None,
            // #1809: a bound subscription, managed by its owner below.
            owner: Some("sub-68-owner".to_string()),
        };
        assert!(manager.add_subscription(sub));

        // An unknown id is 404, not a silent 200.
        let missing =
            handle_subscription_update("no-such-sub", &owned(SbiRequest::default())).await;
        assert_eq!(missing.status, 404, "unknown subscription must be 404");

        // A patch with nothing replaceable is a client error, not a 200.
        let empty_req = owned(SbiRequest::default()).with_body("{}", "application/json");
        let empty = handle_subscription_update("sub-68", &empty_req).await;
        assert_eq!(empty.status, 400);

        // A malformed body is a 400.
        let bad_req = owned(SbiRequest::default()).with_body("{not json", "application/json");
        assert_eq!(
            handle_subscription_update("sub-68", &bad_req).await.status,
            400
        );

        // A validityTime in the PAST is refused rather than applied as an
        // instant expiry.
        let past_req = owned(SbiRequest::default()).with_body(
            r#"{"validityTime":"1971-01-01T00:00:00Z"}"#,
            "application/json",
        );
        assert_eq!(
            handle_subscription_update("sub-68", &past_req).await.status,
            400,
            "a past validityTime must be refused"
        );
        assert_eq!(
            manager
                .find_subscription("sub-68")
                .unwrap()
                .validity_duration,
            60,
            "a refused patch must leave the stored validity untouched"
        );

        // A valid extension replaces the stored duration.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future = epoch_to_rfc3339(now + 3600);
        let ok_req = owned(SbiRequest::default()).with_body(
            format!(r#"{{"validityTime":"{future}"}}"#),
            "application/json",
        );
        let ok = handle_subscription_update("sub-68", &ok_req).await;
        assert_eq!(ok.status, 200);
        let stored = manager
            .find_subscription("sub-68")
            .unwrap()
            .validity_duration;
        assert!(
            (3595..=3600).contains(&stored),
            "stored validity must reflect the patch, got {stored}"
        );

        manager.remove_subscription("sub-68");
    }

    // ==================================================================
    // #68 criterion 9: a complete PUT replacement is NF_PROFILE_CHANGED,
    // not NF_REGISTERED.
    // ==================================================================

    #[test]
    fn registration_event_distinguishes_first_registration_from_replacement() {
        assert_eq!(
            registration_notification_event(true).as_str(),
            "NF_REGISTERED"
        );
        assert_eq!(
            registration_notification_event(false).as_str(),
            "NF_PROFILE_CHANGED",
            "TS 29.510 Section 5.2.2.3.1A: a complete replacement is a change, \
             not an appearance"
        );
    }

    /// The wiring, not just the mapping: drive two real `PUT`s through
    /// `handle_nf_register` with a real subscriber listening, and read the events
    /// off the wire.
    ///
    /// Testing `registration_notification_event` alone would leave the part that
    /// was actually wrong untested — the handler passing `is_new` at all. The
    /// notification is delivered by a `tokio::spawn`ed HTTP/2 call, so the only
    /// way to observe it is to be the subscriber.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_replacement_notifies_profile_changed_over_the_wire() {
        use serde_json::json;
        // #1869: the subscriber is a loopback h2c callback, which only the dev
        // profile dials. Set and left set (CONVENTIONS).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use std::sync::Mutex as StdMutex;

        // A deliberately unique nfType: `nf_manager()` is process-global and
        // other tests in this binary register into it, so the subscription is
        // scoped to a type only this test uses. Same reason the recorded
        // process-global-state learning gives for keying on a unique id.
        const TEST_NF_TYPE: &str = "NRFD68-PUT-EVENT";
        let nf_id = "nrfd68-put-event-nf";

        let received: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&received);

        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let subscriber = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), addr_listener);
        subscriber
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(body) = req.http.content.clone() {
                        sink.lock().expect("sink lock").push(body);
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("subscriber server starts");

        let manager = nf_manager();
        let sub_id = "nrfd68-put-event-sub";
        manager.add_subscription(nextgcore_nrfd::SubscriptionData {
            id: sub_id.to_string(),
            req_nf_type: None,
            req_nf_instance_id: None,
            notification_uri: format!("http://127.0.0.1:{}/callback", addr.port()),
            subscr_cond: Some(nextgcore_nrfd::nnrf_handler::SubscrCond::nf_type(
                TEST_NF_TYPE,
            )),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
            owner: None,
        });

        /// Wait until `want` notifications have arrived, or time out.
        async fn wait_for(sink: &Arc<StdMutex<Vec<String>>>, want: usize) -> Vec<String> {
            for _ in 0..100 {
                {
                    let got = sink.lock().expect("sink lock");
                    if got.len() >= want {
                        return got.clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            sink.lock().expect("sink lock").clone()
        }

        let profile = json!({
            "nfInstanceId": nf_id,
            "nfType": TEST_NF_TYPE,
            "nfStatus": "REGISTERED",
            "capacity": 10,
        });
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
        req.http.set_content(profile.to_string());
        req.peer_cert_nf_instance_id = Some(nf_id.into());
        req.peer_cert_nf_types = vec![TEST_NF_TYPE.into()];

        // --- First PUT: a new instance -> 201 and NF_REGISTERED -------------
        let first = handle_nf_register(nf_id, &req).await;
        assert_eq!(first.status, 201, "first registration is 201 Created");
        let after_first = wait_for(&received, 1).await;
        assert_eq!(
            after_first.len(),
            1,
            "the subscriber must receive exactly one notification, got {after_first:?}"
        );
        let body: serde_json::Value =
            serde_json::from_str(&after_first[0]).expect("notification is JSON");
        assert_eq!(body["event"], "NF_REGISTERED");

        // --- Second PUT: a complete replacement -> 200 and NF_PROFILE_CHANGED
        let mut replacement_body = profile.clone();
        replacement_body["capacity"] = json!(90);
        let mut replacement = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{nf_id}"));
        replacement.http.set_content(replacement_body.to_string());
        replacement.peer_cert_nf_instance_id = Some(nf_id.into());
        replacement.peer_cert_nf_types = vec![TEST_NF_TYPE.into()];

        let second = handle_nf_register(nf_id, &replacement).await;
        assert_eq!(second.status, 200, "a replacement is 200 OK");
        let after_second = wait_for(&received, 2).await;
        assert_eq!(after_second.len(), 2, "got {after_second:?}");
        let body: serde_json::Value =
            serde_json::from_str(&after_second[1]).expect("notification is JSON");
        assert_eq!(
            body["event"], "NF_PROFILE_CHANGED",
            "a complete replacement must NOT be announced as a new registration"
        );
        // The notification carries the replaced profile, so a subscriber can act
        // on the change without a follow-up GET.
        assert_eq!(body["nfProfile"]["capacity"], 90);

        manager.remove_subscription(sub_id);
        manager.deregister(nf_id).ok();
        disarm_heartbeat_timer(nf_id);
    }

    // ==================================================================
    // #68 criterion 6: GET /nf-instances is a HAL UriList and honours
    // nf-type / limit / page.
    // ==================================================================

    #[tokio::test]
    async fn nf_list_is_a_hal_urilist_with_link_objects() {
        use serde_json::json;

        // Unique nfType again: the registry is process-global.
        const TEST_NF_TYPE: &str = "NRFD68-HAL-LIST";
        let ids = [
            "nrfd68-hal-c",
            "nrfd68-hal-a",
            "nrfd68-hal-b",
            "nrfd68-hal-d",
        ];
        let manager = nf_manager();
        for id in ids {
            manager
                .register(
                    nextgcore_nrfd::nnrf_handler::NfProfile::from_json(&json!({
                        "nfInstanceId": id,
                        "nfType": TEST_NF_TYPE,
                        "nfStatus": "REGISTERED",
                    }))
                    .expect("valid profile"),
                )
                .expect("register");
        }

        let get = |uri: &str| {
            let req = SbiRequest::get(uri);
            async move { handle_nf_list_retrieval(&req).await }
        };
        let body_of = |resp: &SbiResponse| -> serde_json::Value {
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("JSON")
        };

        // --- Media type and link-object shape ------------------------------
        let resp = get(&format!("/nnrf-nfm/v1/nf-instances?nf-type={TEST_NF_TYPE}")).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.http.get_header("content-type").map(String::as_str),
            Some(HAL_JSON_CONTENT_TYPE),
            "TS 29.510 Section 6.1.3.2.3.1 serves the collection as 3gppHal+json"
        );
        let body = body_of(&resp);
        assert!(
            body["_links"]["self"]["href"].is_string(),
            "_links values are LinksValueSchema objects carrying href, not bare \
             strings: {body}"
        );
        let items = body["_links"]["item"]
            .as_array()
            .unwrap_or_else(|| panic!("the schema names the member `item`, not `items`: {body}"));
        assert_eq!(items.len(), 4, "nf-type must filter to just our four");
        for item in items {
            assert!(
                item["href"].is_string(),
                "each item is a Link object: {item}"
            );
        }
        assert_eq!(body["totalItemCount"], 4);

        // --- nf-type genuinely filters -------------------------------------
        let others = get("/nnrf-nfm/v1/nf-instances?nf-type=NRFD68-ABSENT-TYPE").await;
        let body = body_of(&others);
        assert_eq!(body["_links"]["item"].as_array().map(|a| a.len()), Some(0));
        assert_eq!(body["totalItemCount"], 0);

        // --- limit + page page through a stable, sorted order ---------------
        let page1 = body_of(
            &get(&format!(
                "/nnrf-nfm/v1/nf-instances?nf-type={TEST_NF_TYPE}&limit=2&page=1"
            ))
            .await,
        );
        let page2 = body_of(
            &get(&format!(
                "/nnrf-nfm/v1/nf-instances?nf-type={TEST_NF_TYPE}&limit=2&page=2"
            ))
            .await,
        );
        let hrefs = |b: &serde_json::Value| -> Vec<String> {
            b["_links"]["item"]
                .as_array()
                .expect("item array")
                .iter()
                .map(|i| i["href"].as_str().expect("href").to_string())
                .collect()
        };
        let (h1, h2) = (hrefs(&page1), hrefs(&page2));
        assert_eq!(h1.len(), 2, "limit must cap the page: {h1:?}");
        assert_eq!(h2.len(), 2, "{h2:?}");
        assert!(
            h1.iter().all(|h| !h2.contains(h)),
            "pages must not overlap: {h1:?} vs {h2:?}"
        );
        // Sorted order, so page 2 is deterministic rather than whatever the
        // underlying map happened to yield.
        assert!(h1[0].ends_with("nrfd68-hal-a"), "{h1:?}");
        assert!(h1[1].ends_with("nrfd68-hal-b"), "{h1:?}");
        assert!(h2[0].ends_with("nrfd68-hal-c"), "{h2:?}");
        assert!(h2[1].ends_with("nrfd68-hal-d"), "{h2:?}");
        // totalItemCount counts the whole filtered set, not the page, so a
        // consumer can tell there is a page 2 at all.
        assert_eq!(page1["totalItemCount"], 4);
        // The self link echoes the paging actually applied.
        assert_eq!(
            page2["_links"]["self"]["href"],
            "/nnrf-nfm/v1/nf-instances?limit=2&page=2"
        );

        // A page past the end is an empty page, not an error.
        let page9 = body_of(
            &get(&format!(
                "/nnrf-nfm/v1/nf-instances?nf-type={TEST_NF_TYPE}&limit=2&page=9"
            ))
            .await,
        );
        assert_eq!(page9["_links"]["item"].as_array().map(|a| a.len()), Some(0));
        assert_eq!(page9["totalItemCount"], 4);

        // --- Unusable paging parameters are refused, not ignored ------------
        // Ignoring them returns a page the consumer did not ask for and cannot
        // detect, which is how the old handler behaved for every request.
        for uri in [
            "/nnrf-nfm/v1/nf-instances?limit=0",
            "/nnrf-nfm/v1/nf-instances?limit=abc",
            "/nnrf-nfm/v1/nf-instances?limit=2&page=0",
            "/nnrf-nfm/v1/nf-instances?page=2",
        ] {
            let resp = get(uri).await;
            assert_eq!(resp.status, 400, "{uri} must be refused");
        }

        for id in ids {
            manager.deregister(id).ok();
        }
    }

    #[test]
    fn query_params_are_split_and_percent_decoded() {
        assert!(query_params("/nnrf-nfm/v1/nf-instances").is_empty());
        assert_eq!(
            query_params("/x?nf-type=AMF&limit=2"),
            vec![
                ("nf-type".to_string(), "AMF".to_string()),
                ("limit".to_string(), "2".to_string()),
            ]
        );
        // A percent-encoded value must compare equal to its decoded form.
        assert_eq!(
            query_params("/x?nf-type=5G%5FEIR"),
            vec![("nf-type".to_string(), "5G_EIR".to_string())]
        );
        // A valueless parameter and a stray separator must not panic or produce
        // a phantom entry.
        assert_eq!(
            query_params("/x?flag&&limit=1"),
            vec![
                ("flag".to_string(), String::new()),
                ("limit".to_string(), "1".to_string()),
            ]
        );
    }

    // ==================================================================
    // #68 criterion 7: GET /bootstrapping.
    // ==================================================================

    #[tokio::test]
    async fn bootstrapping_returns_hal_bootstrapping_info() {
        // Routed through the real dispatcher, because the bug was in the router:
        // /bootstrapping has one path segment and used to fall out at the
        // three-segment guard as a 404.
        let resp = nrf_sbi_request_handler(SbiRequest::get("/bootstrapping")).await;
        assert_eq!(
            resp.status, 200,
            "GET /bootstrapping must be routed, not 404'd by the path guard"
        );
        assert_eq!(
            resp.http.get_header("content-type").map(String::as_str),
            Some(HAL_JSON_CONTENT_TYPE)
        );

        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("JSON");
        assert_eq!(body["status"], "OPERATIVE");
        assert_eq!(body["nrfInstanceId"], nrf_instance_id());

        // The registered relation types of TS 29.510 Table 6.4.6.3.3.1-1, each an
        // object carrying an ABSOLUTE href.
        let api_root = nrf_self_uri();
        for relation in [
            "self",
            "manage",
            "subscribe",
            "discover",
            "authorize",
            "retrieve-key",
        ] {
            let href = body["_links"][relation]["href"]
                .as_str()
                .unwrap_or_else(|| panic!("relation {relation} missing an href: {body}"));
            assert!(
                href.starts_with(api_root),
                "relation {relation} href {href} must be absolute (apiRoot {api_root})"
            );
        }
        assert_eq!(
            body["_links"]["self"]["href"],
            format!("{api_root}/bootstrapping")
        );
        assert_eq!(
            body["_links"]["authorize"]["href"],
            format!("{api_root}/nnrf-oauth2/v1/access-token")
        );

        // oauth2Required must report the posture actually enforced, keyed by NRF
        // service name; a hardcoded value could drift from behaviour.
        let expected = nrf_policy().require_oauth2_server;
        assert_eq!(body["oauth2Required"]["nnrf-nfm"], expected);
        assert_eq!(body["oauth2Required"]["nnrf-disc"], expected);

        // Bootstrapping must stay reachable without a token even when
        // server-side OAuth2 is on — a consumer reads this document to FIND the
        // token endpoint.
        assert!(
            !oauth2_protected_path("/bootstrapping"),
            "an OAuth2-gated bootstrapping resource is unusable by definition"
        );

        // A non-GET on the resource is 405, not 404.
        let post = nrf_sbi_request_handler(SbiRequest::post("/bootstrapping")).await;
        assert_eq!(post.status, 405);
    }

    #[tokio::test]
    async fn bootstrapping_revalidates_with_an_etag() {
        let first = nrf_sbi_request_handler(SbiRequest::get("/bootstrapping")).await;
        let etag = first.http.get_header("etag").expect("ETag present").clone();
        assert!(
            first.http.get_header("cache-control").is_some(),
            "Cache-Control is required alongside the ETag"
        );

        // The document is stable, so a second request yields the same tag.
        let second = nrf_sbi_request_handler(SbiRequest::get("/bootstrapping")).await;
        assert_eq!(second.http.get_header("etag"), Some(&etag));

        // A matching If-None-Match is answered 304 with no body.
        let conditional =
            SbiRequest::get("/bootstrapping").with_header("If-None-Match", etag.as_str());
        let resp = nrf_sbi_request_handler(conditional).await;
        assert_eq!(resp.status, 304);
        assert!(resp.http.content.is_none() || resp.http.content.as_deref() == Some(""));

        // A non-matching tag still returns the document.
        let stale =
            SbiRequest::get("/bootstrapping").with_header("If-None-Match", "\"0000000000000000\"");
        assert_eq!(nrf_sbi_request_handler(stale).await.status, 200);

        // `*` matches any existing representation (RFC 9110 Section 13.1.2).
        let star = SbiRequest::get("/bootstrapping").with_header("If-None-Match", "*");
        assert_eq!(nrf_sbi_request_handler(star).await.status, 304);
    }

    #[test]
    fn if_none_match_compares_weak_and_strong_forms_and_lists() {
        assert!(if_none_match_matches("\"abc\"", "\"abc\""));
        assert!(if_none_match_matches("W/\"abc\"", "\"abc\""));
        assert!(if_none_match_matches("\"xyz\", \"abc\"", "\"abc\""));
        assert!(if_none_match_matches("*", "\"abc\""));
        assert!(!if_none_match_matches("\"xyz\"", "\"abc\""));
        assert!(!if_none_match_matches("", "\"abc\""));
    }

    #[test]
    fn fnv1a64_is_deterministic_and_content_sensitive() {
        // Determinism across runs is the point: an ETag derived from a hash that
        // changes between builds silently invalidates every cached document.
        assert_eq!(fnv1a64("bootstrapping"), fnv1a64("bootstrapping"));
        assert_eq!(fnv1a64(""), 0xcbf2_9ce4_8422_2325);
        assert_ne!(fnv1a64("a"), fnv1a64("b"));
        // A one-character difference deep in a long string must still change it.
        assert_ne!(
            fnv1a64("http://nrf:7777/nnrf-nfm/v1/nf-instances"),
            fnv1a64("http://nrf:7778/nnrf-nfm/v1/nf-instances")
        );
    }

    // ==================================================================
    // #68 criterion 4/5 at the handler boundary: subscribe refuses a
    // condition it cannot honour, and parses validityTime as a DateTime.
    // ==================================================================

    async fn subscribe(body: serde_json::Value) -> SbiResponse {
        let mut req = SbiRequest::post("/nnrf-nfm/v1/subscriptions");
        req.http.set_content(body.to_string());
        // #1809: a verified subscriber, as the production policy requires.
        req.peer_cert_nf_instance_id = Some("nrfd68-subscriber".into());
        // These tests subscribe http callbacks: the dev profile, set on the call
        // rather than through the process-global override (#1869).
        handle_subscription_create_under(&req, nextgcore_sbi::security::SbiProfile::Dev).await
    }

    fn problem_of(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("JSON")
    }

    /// #1869: under production an http nfStatusNotificationUri is a 400 with
    /// `invalidParams` naming it, and nothing is stored; https is accepted.
    #[tokio::test]
    async fn production_subscribe_refuses_an_http_notification_uri_1869() {
        use nextgcore_sbi::security::SbiProfile;
        let uri = format!("http://amf-1869-{}.example/cb", uuid::Uuid::new_v4());
        let mut req = SbiRequest::post("/nnrf-nfm/v1/subscriptions");
        // #1809: a verified subscriber, so the URI check is what is exercised.
        req.peer_cert_nf_instance_id = Some("nrf-1869-subscriber".into());
        req.http
            .set_content(serde_json::json!({ "nfStatusNotificationUri": uri }).to_string());
        let resp = handle_subscription_create_under(&req, SbiProfile::Production).await;
        assert_eq!(resp.status, 400);
        let problem = problem_of(&resp);
        assert_eq!(problem["cause"], "MANDATORY_IE_INCORRECT");
        assert_eq!(
            problem["invalidParams"][0]["param"],
            "/nfStatusNotificationUri"
        );
        assert!(
            !nextgcore_nrfd::nnrf_handler::nf_manager()
                .list_subscriptions()
                .iter()
                .any(|s| s.notification_uri == uri),
            "a refused subscription must not be stored"
        );

        let https = uri.replacen("http://", "https://", 1);
        let mut req = SbiRequest::post("/nnrf-nfm/v1/subscriptions");
        // #1809: a verified subscriber, so the URI check is what is exercised.
        req.peer_cert_nf_instance_id = Some("nrf-1869-subscriber".into());
        req.http
            .set_content(serde_json::json!({ "nfStatusNotificationUri": https }).to_string());
        let resp = handle_subscription_create_under(&req, SbiProfile::Production).await;
        assert_eq!(
            resp.status, 201,
            "an https callback is accepted under production"
        );
    }

    #[tokio::test]
    async fn subscribe_refuses_a_condition_it_cannot_honour() {
        use serde_json::json;

        // An unrecognised condition is a 400. Accepting it is the match-all
        // defect: the old parse produced a criteria-less condition that matched
        // every NF in the registry.
        for cond in [
            json!({}),
            json!({"conditionType": "NOT_A_REAL_COND"}),
            json!({"somethingElse": "x"}),
            // A tagged condition missing its own mandatory member is malformed,
            // not match-all.
            json!({"conditionType": "SERVICE_NAME_LIST_COND"}),
            json!({"conditionType": "NF_GROUP_LIST_COND", "nfGroupIdList": ["g"]}),
        ] {
            let resp = subscribe(json!({
                "nfStatusNotificationUri": "http://consumer.example.com/cb",
                "subscrCond": cond,
            }))
            .await;
            assert_eq!(resp.status, 400, "subscrCond {cond} must be refused");
            assert_eq!(problem_of(&resp)["cause"], "MANDATORY_IE_INCORRECT");
        }

        // A recognised variant whose criterion this NRF cannot evaluate is also
        // refused, and says which criterion and why.
        let resp = subscribe(json!({
            "nfStatusNotificationUri": "http://consumer.example.com/cb",
            "subscrCond": {
                "conditionType": "UPF_COND",
                "taiList": [{"plmnId": {"mcc": "001", "mnc": "01"}, "tac": "0001"}],
            },
        }))
        .await;
        assert_eq!(resp.status, 400);
        let problem = problem_of(&resp);
        assert_eq!(problem["cause"], "SUBSCR_COND_NOT_SUPPORTED");
        assert!(
            problem["detail"]
                .as_str()
                .expect("detail")
                .contains("taiList"),
            "the refusal must name the criterion: {problem}"
        );

        // And an omitted condition is still accepted as "every NF" — refusing
        // that would break the existing NF-status feeds.
        let resp = subscribe(json!({
            "nfStatusNotificationUri": "http://consumer.example.com/cb",
        }))
        .await;
        assert_eq!(resp.status, 201);
        let id = problem_of(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();
        assert!(nf_manager()
            .find_subscription(&id)
            .expect("stored")
            .subscr_cond
            .is_none());
        nf_manager().remove_subscription(&id);
    }

    #[tokio::test]
    async fn subscribe_parses_validity_time_as_a_datetime_and_echoes_the_full_body() {
        use serde_json::json;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();

        // A conformant DateTime proposal is honoured. Read with `as_u64` — the
        // old behaviour — this silently fell through to the 24h default, so the
        // consumer's request had no effect it could observe.
        let resp = subscribe(json!({
            "nfStatusNotificationUri": "http://consumer.example.com/cb",
            "validityTime": epoch_to_rfc3339(now + 600),
            "reqNotifEvents": ["NF_DEREGISTERED", "NF_PROFILE_CHANGED"],
            "notifCondition": {"monitoredAttributes": ["load"]},
            "subscrCond": {"nfSetId": "set-68"},
        }))
        .await;
        assert_eq!(resp.status, 201);
        let body = problem_of(&resp);
        let id = body["subscriptionId"].as_str().expect("id").to_string();

        let stored = nf_manager().find_subscription(&id).expect("stored");
        assert!(
            (595..=600).contains(&stored.validity_duration),
            "the proposed DateTime must set the enforced validity, got {}",
            stored.validity_duration
        );
        assert_ne!(
            stored.validity_duration, NRF_SUBSCRIPTION_DEFAULT_VALIDITY,
            "falling back to the default means the proposal was ignored"
        );

        // reqNotifEvents / notifCondition are retained, not dropped on parse...
        assert_eq!(
            stored.req_notif_events.as_deref(),
            Some(
                &[
                    "NF_DEREGISTERED".to_string(),
                    "NF_PROFILE_CHANGED".to_string()
                ][..]
            )
        );
        assert_eq!(
            stored
                .notif_condition
                .as_ref()
                .and_then(|c| c.monitored_attributes.clone()),
            Some(vec!["load".to_string()])
        );
        // ... and are echoed back, along with the condition VERBATIM: rebuilding
        // it from parsed fields is what used to drop every member the old
        // three-field model did not know about.
        assert_eq!(body["reqNotifEvents"][0], "NF_DEREGISTERED");
        assert_eq!(body["notifCondition"]["monitoredAttributes"][0], "load");
        assert_eq!(body["subscrCond"]["nfSetId"], "set-68");
        nf_manager().remove_subscription(&id);

        // An absent validityTime still gets the NRF default.
        let resp = subscribe(json!({
            "nfStatusNotificationUri": "http://consumer.example.com/cb",
        }))
        .await;
        let id = problem_of(&resp)["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string();
        assert_eq!(
            nf_manager()
                .find_subscription(&id)
                .expect("stored")
                .validity_duration,
            NRF_SUBSCRIPTION_DEFAULT_VALIDITY
        );
        nf_manager().remove_subscription(&id);

        // A proposal beyond the NRF's maximum is clamped, not honoured, so a
        // consumer cannot pin a subscription open indefinitely.
        let resp = subscribe(json!({
            "nfStatusNotificationUri": "http://consumer.example.com/cb",
            "validityTime": epoch_to_rfc3339(now + NRF_SUBSCRIPTION_DEFAULT_VALIDITY * 10),
        }))
        .await;
        let id = problem_of(&resp)["subscriptionId"]
            .as_str()
            .expect("id")
            .to_string();
        assert_eq!(
            nf_manager()
                .find_subscription(&id)
                .expect("stored")
                .validity_duration,
            NRF_SUBSCRIPTION_DEFAULT_VALIDITY
        );
        nf_manager().remove_subscription(&id);

        // Non-conformant validityTime forms are refused rather than coerced.
        for bad in [
            json!(3600),
            json!("not-a-timestamp"),
            json!(epoch_to_rfc3339(now.saturating_sub(600))),
        ] {
            let resp = subscribe(json!({
                "nfStatusNotificationUri": "http://consumer.example.com/cb",
                "validityTime": bad,
            }))
            .await;
            assert_eq!(resp.status, 400, "validityTime {bad} must be refused");
        }

        // Malformed reqNotifEvents / notifCondition are refused too. Both forms
        // of notifCondition at once violates the schema's `not` clause, and
        // silently picking one would apply a filter the consumer did not ask for.
        for bad in [
            json!({"reqNotifEvents": "NF_REGISTERED"}),
            json!({"reqNotifEvents": []}),
            json!({"reqNotifEvents": [1, 2]}),
            json!({"notifCondition": {}}),
            json!({"notifCondition": {"monitoredAttributes": ["load"],
                                      "unmonitoredAttributes": ["capacity"]}}),
        ] {
            let mut body = json!({"nfStatusNotificationUri": "http://consumer.example.com/cb"});
            for (k, v) in bad.as_object().expect("object") {
                body[k] = v.clone();
            }
            let resp = subscribe(body.clone()).await;
            assert_eq!(resp.status, 400, "{body} must be refused");
        }
    }
}

/// #1324: the NRF's own profile carries its host by type.
#[cfg(test)]
mod tests_nrf_self_profile_host_kind_1324 {
    use super::nrf_self_profile_for;

    #[test]
    fn the_nrf_profile_carries_its_host_by_type() {
        for host in nextgcore_sbi::nf_addressing::SAMPLE_HOSTS {
            let authority = nextgcore_sbi::uri_encode::uri_authority(host, 7777);
            let profile = nrf_self_profile_for(&format!("http://{authority}"));
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}

/// #1611: Nnrf_NFManagement NF-instance requests are bound to the caller's
/// verified identity (TS 33.501 §5.9.2.2 NOTE, TS 33.310 §6.1.3c.3,
/// TS 29.510 Table 6.1.7.3-1 INVALID_CLIENT).
#[cfg(test)]
mod registrant_binding_tests_1611 {
    use super::*;
    use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
    use serde_json::json;

    /// A CA and an NRF server leaf, plus a client leaf with the given URI SAN and
    /// RFC 9310 NFTypes, written as PEM files. Returns (ca, server cert, server
    /// key, client cert, client key) paths.
    fn pki(
        tag: &str,
        client_uri: Option<&str>,
        nf_types: Option<&[&str]>,
    ) -> (String, String, String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
        let dir = std::env::temp_dir().join(format!("nrfd-1611-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "nrfd-1611-ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let leaf = |uri: Option<&str>, types: Option<&[&str]>| {
            let mut params =
                CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
            if let Some(u) = uri {
                params
                    .subject_alt_names
                    .push(rcgen::SanType::URI(u.try_into().expect("ia5 uri")));
            }
            if let Some(types) = types {
                // NFTypes ::= SEQUENCE SIZE (1..MAX) OF IA5String (SIZE (1..32))
                let mut body = Vec::new();
                for t in types {
                    body.push(0x16);
                    body.push(t.len() as u8);
                    body.extend_from_slice(t.as_bytes());
                }
                let mut der = vec![0x30, body.len() as u8];
                der.extend(body);
                params
                    .custom_extensions
                    .push(rcgen::CustomExtension::from_oid_content(
                        &[1, 3, 6, 1, 5, 5, 7, 1, 34],
                        der,
                    ));
            }
            let key = KeyPair::generate().expect("leaf key");
            let cert = params.signed_by(&key, &ca, &ca_key).expect("leaf");
            (cert.pem(), key.serialize_pem())
        };
        let (server_cert, server_key) = leaf(None, None);
        let (client_cert, client_key) = leaf(client_uri, nf_types);
        let write = |name: &str, pem: &str| {
            let p = dir.join(name);
            std::fs::write(&p, pem).expect("write pem");
            p.display().to_string()
        };
        (
            write("ca.crt", &ca.pem()),
            write("server.crt", &server_cert),
            write("server.key", &server_key),
            write("client.crt", &client_cert),
            write("client.key", &client_key),
        )
    }

    /// An Envoy-style XFCC header for a terminator that verified a client
    /// certificate naming `uri` and `nf_types`, with (`with_cert`) or without
    /// its URL-encoded PEM in `Cert=` (#1979).
    fn xfcc_1979(_tag: &str, uri: &str, nf_types: &[&str], with_cert: bool) -> String {
        if with_cert {
            test_xfcc(uri, nf_types)
        } else {
            format!("By=spiffe://nrf;URI={uri}")
        }
    }

    /// **#1979.** A trusted terminator's XFCC `Cert=` carries the requester's
    /// certificate, so its RFC 9310 NFTypes bind the forwarded registrant as a
    /// direct certificate's do. Without `Cert=`, or with one that does not
    /// decode, no type is known, and where types are required it is refused.
    ///
    /// REVERT-VERIFIED: with `RegistrantIdentity::of` back to no types for a
    /// forwarded identity, `nf_types` is empty and the first assertion fails.
    #[test]
    fn a_forwarded_certificate_s_nf_types_bind_the_registrant_1979() {
        let id = "19790000-0000-4000-8000-0000000000a1";
        let uri = format!("urn:uuid:{id}");
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let forwarded = |xfcc: &str| {
            let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"));
            req.peer_cert_nf_types = vec!["SCP".into()]; // the terminator's own
            req.http.set_header(XFCC_HEADER, xfcc.to_string());
            from_test_terminator(&mut req);
            RegistrantIdentity::of(&req, &trusting)
        };

        let with = forwarded(&xfcc_1979("xfcc-1979a", &uri, &["AMF"], true));
        assert_eq!(with.nf_types, vec!["AMF".to_string()], "from XFCC Cert=");
        assert!(with.forwarded);
        assert!(with.bind_nf_type("NFRegister", id, "AMF", true).is_none());
        let refused = with
            .bind_nf_type("NFRegister", id, "AUSF", true)
            .expect("an AMF certificate cannot register an AUSF");
        assert_eq!(refused.status, 400);

        let without = forwarded(&xfcc_1979("xfcc-1979b", &uri, &["AMF"], false));
        // #1990: without Cert= the terminator vouches for nothing, not even the
        // identity (URI= alone is never believed).
        assert!(without.instance_ids.is_empty(), "no Cert=, no identity");
        // #2000: nor any NF type: the connection's own (SCP) are the terminator's.
        assert!(
            without.nf_types.is_empty(),
            "the terminator's types are not the caller's"
        );

        let garbage = forwarded(&format!("By=x;Cert=\"not-a-pem\";URI={uri}"));
        assert!(
            garbage.instance_ids.is_empty(),
            "an undecodable Cert= proves nothing"
        );
    }

    /// **#1979.** The bootstrap token (#1952) for an unregistered NF behind a
    /// trusted terminator: the type in the forwarded certificate (XFCC `Cert=`)
    /// proves the requested `nfType`, so an AMF gets its nnrf token as AMF and
    /// not as AUSF.
    ///
    /// REVERT-VERIFIED: with the forwarded branch of the token check removed,
    /// the AMF request is refused and the first assertion fails.
    #[tokio::test]
    async fn a_forwarded_certificate_s_type_proves_the_bootstrap_token_1979() {
        use super::registrant_nf_type_tests_1917::REQUIRED;
        let _self_entry = self_entry_test_lock().lock().await;
        let id = "19790000-0000-4000-8000-0000000000b2";
        let xfcc = xfcc_1979("xfcc-1979c", &format!("urn:uuid:{id}"), &["AMF"], true);
        let policy = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let ask = |nf_type: &str| {
            let mut r = SbiRequest::post("/oauth2/token");
            r.http.set_content(
                json!({
                    "grant_type": "client_credentials", "nfInstanceId": id, "nfType": nf_type,
                    "targetNfType": "NRF", "scope": "nnrf-disc",
                })
                .to_string(),
            );
            r.peer_cert_nf_types = vec!["SCP".into()]; // the terminator's own
            r.http.set_header(XFCC_HEADER, xfcc.clone());
            from_test_terminator(&mut r);
            r
        };
        let as_amf = REQUIRED
            .scope(
                true,
                handle_access_token_request_with_policy(&ask("AMF"), &policy),
            )
            .await;
        assert_eq!(as_amf.status, 200, "{:?}", as_amf.http.content);
        let as_ausf = REQUIRED
            .scope(
                true,
                handle_access_token_request_with_policy(&ask("AUSF"), &policy),
            )
            .await;
        assert_eq!(as_ausf.status, 400, "{:?}", as_ausf.http.content);
    }

    /// **#1990 (R30 MAJOR 1).** The identity and the NF types come from ONE
    /// certificate, the forwarded `Cert=`. A victim's `URI=` beside an
    /// attacker's AMF certificate yields the attacker's identity, never
    /// (victim, [AMF]); and a `Hash=` that does not match `Cert=` is not
    /// believed at all.
    ///
    /// REVERT-VERIFIED: with the identity taken from `URI=` again, the first
    /// assertion names the victim and fails; with the Hash= check removed, the
    /// mismatched header is believed and the second fails.
    #[test]
    fn the_forwarded_identity_and_types_come_from_one_certificate_1990() {
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let req = |xfcc: String| {
            let mut r = SbiRequest::post("/x");
            r.http.set_header(XFCC_HEADER, xfcc);
            from_test_terminator(&mut r);
            r
        };
        let attacker = test_xfcc("19900000-0000-4000-8000-0000000000aa", &["AMF"]);
        let spliced = format!("{attacker};URI=urn:uuid:19900000-0000-4000-8000-00000000vic7");
        assert_eq!(
            extract_transport_client_nf_instance_id(&req(spliced), &trusting).as_deref(),
            Some("19900000-0000-4000-8000-0000000000aa"),
            "the certificate's own identity, not the spliced URI="
        );
        let mismatched = attacker.replacen("Hash=", "Hash=00", 1);
        assert!(
            extract_transport_client_nf_instance_id(&req(mismatched), &trusting).is_none(),
            "a Hash= that does not match Cert= is not believed"
        );
    }

    /// **#1990 (R30, second round).** The XFCC header is believed only from the
    /// configured terminator, recognised by its OWN verified client certificate
    /// over mTLS (`trusted_xfcc_terminators`):
    /// - an unauthenticated connection (client auth is optional by default)
    ///   pasting a victim's public certificate in `Cert=` is ignored;
    /// - another mTLS peer's header is ignored, and its own certificate counts;
    /// - the configured terminator's header is believed, and its own certificate
    ///   is not taken for the caller;
    /// - an appended (multi-entry) header from the terminator is refused.
    ///
    /// REVERT-VERIFIED: with `from_trusted_terminator` true for any connection
    /// with the flag on, the pasted-PEM request is believed and the first
    /// assertion fails; with it ignoring the allowlist, the other peer's header
    /// is believed and the second fails.
    #[test]
    fn xfcc_is_believed_only_from_the_configured_terminator_1990() {
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let victim = "19900000-0000-4000-8000-0000000000cc";
        let pasted = test_xfcc(victim, &["AUSF"]);

        let mut anonymous = SbiRequest::post("/x");
        anonymous.http.set_header(XFCC_HEADER, pasted.clone());
        assert!(
            extract_transport_client_nf_instance_id(&anonymous, &trusting).is_none(),
            "an unauthenticated connection's header is the client's own words"
        );

        let mut other_peer = SbiRequest::post("/x");
        other_peer.peer_cert_present = true;
        other_peer.peer_cert_nf_instance_id = Some("19900000-0000-4000-8000-0000000000dd".into());
        other_peer.http.set_header(XFCC_HEADER, pasted.clone());
        assert_eq!(
            extract_transport_client_nf_instance_id(&other_peer, &trusting).as_deref(),
            Some("19900000-0000-4000-8000-0000000000dd"),
            "a non-terminator peer is itself, whatever its header says"
        );

        let mut terminator = SbiRequest::post("/x");
        from_test_terminator(&mut terminator);
        terminator.http.set_header(XFCC_HEADER, pasted.clone());
        assert_eq!(
            extract_transport_client_nf_instance_id(&terminator, &trusting).as_deref(),
            Some(victim),
            "the configured terminator's header is believed"
        );
        let mut bare_terminator = SbiRequest::post("/x");
        from_test_terminator(&mut bare_terminator);
        assert!(
            extract_transport_client_nf_instance_id(&bare_terminator, &trusting).is_none(),
            "the terminator's own certificate is never the caller's"
        );

        let mut appended = SbiRequest::post("/x");
        from_test_terminator(&mut appended);
        appended
            .http
            .set_header(XFCC_HEADER, format!("{pasted},{pasted}"));
        assert!(extract_transport_client_nf_instance_id(&appended, &trusting).is_none());
    }

    /// **#2000.** A terminator is recognised on ANY URI SAN of its certificate,
    /// not only the one picked as its NF Instance ID: allowlisted by SPIFFE ID,
    /// a certificate that also carries a `urn:uuid:` SAN (which the NF-ID pick
    /// prefers) is still the terminator. A `urn:uuid:` entry matches with or
    /// without the prefix, case-insensitively; a SAN that is in no entry is not
    /// a terminator.
    ///
    /// REVERT-VERIFIED: with `from_trusted_terminator` back to matching only
    /// `peer_cert_nf_instance_id`, the SPIFFE-listed terminator is not
    /// recognised and the first assertion fails.
    #[test]
    fn a_terminator_is_matched_on_any_of_its_uri_sans_2000() {
        let victim = "20000000-0000-4000-8000-0000000000aa";
        let pasted = test_xfcc(victim, &["AUSF"]);
        let uuid = "20000000-0000-4000-8000-0000000000EE";
        let peer = |sans: &[&str]| {
            let mut r = SbiRequest::post("/x");
            r.peer_cert_present = true;
            // What the NF-ID pick yields: the urn:uuid SAN, prefix stripped.
            r.peer_cert_nf_instance_id = Some(uuid.to_string());
            r.peer_cert_uri_sans = sans.iter().map(|s| s.to_string()).collect();
            r.http.set_header(XFCC_HEADER, pasted.clone());
            r
        };
        let listing = |entry: &str| NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![entry.to_string()],
            ..NrfPolicy::default()
        };
        let both = peer(&[&format!("urn:uuid:{uuid}"), TEST_TERMINATOR]);

        assert_eq!(
            extract_transport_client_nf_instance_id(&both, &listing(TEST_TERMINATOR)).as_deref(),
            Some(victim),
            "listed by its SPIFFE ID, the terminator is recognised beside its urn:uuid SAN"
        );
        for entry in [
            format!("urn:uuid:{uuid}"),
            format!("URN:UUID:{}", uuid.to_ascii_lowercase()),
            uuid.to_ascii_lowercase(),
        ] {
            assert_eq!(
                extract_transport_client_nf_instance_id(&both, &listing(&entry)).as_deref(),
                Some(victim),
                "listed by its UUID as {entry:?}"
            );
        }
        // A SPIFFE ID compares exactly, and an unlisted certificate is itself.
        let unlisted = listing("spiffe://cluster.local/ns/5gc/sa/Envoy");
        assert_eq!(
            extract_transport_client_nf_instance_id(&both, &unlisted).as_deref(),
            Some(uuid),
            "a SAN matching no entry is a peer, not a terminator"
        );
        let other = peer(&["spiffe://cluster.local/ns/5gc/sa/other"]);
        assert!(!from_trusted_terminator(&other, &listing(TEST_TERMINATOR)));
    }

    /// **#2012.** Case is ignored only between two UUIDs. A SAN that merely
    /// starts with `urn:uuid:` (a non-UUID after it) matches a non-UUID entry
    /// only as written, exactly; between UUIDs the prefix and case still do
    /// not matter.
    ///
    /// REVERT-VERIFIED: with the #2000 rule back (case-insensitive whenever
    /// either side has the `urn:uuid:` prefix), the case-different non-UUID
    /// entries match and the first assertion fails.
    #[test]
    fn only_two_uuids_compare_case_insensitively_2012() {
        let peer = |san: &str| {
            let mut r = SbiRequest::post("/x");
            r.peer_cert_present = true;
            r.peer_cert_uri_sans = vec![san.to_string()];
            r
        };
        let listing = |entry: &str| NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![entry.to_string()],
            ..NrfPolicy::default()
        };
        let odd = peer("urn:uuid:Envoy-Terminator");
        for entry in [
            "urn:uuid:envoy-terminator",
            "envoy-terminator",
            "Envoy-Terminator",
        ] {
            assert!(
                !from_trusted_terminator(&odd, &listing(entry)),
                "a non-UUID {entry:?} is matched exactly only"
            );
        }
        assert!(from_trusted_terminator(
            &odd,
            &listing("urn:uuid:Envoy-Terminator")
        ));
        let uuid = peer("urn:uuid:20120000-0000-4000-8000-0000000000AB");
        for entry in [
            "urn:uuid:20120000-0000-4000-8000-0000000000ab",
            "URN:UUID:20120000-0000-4000-8000-0000000000AB",
            "20120000-0000-4000-8000-0000000000ab",
        ] {
            assert!(from_trusted_terminator(&uuid, &listing(entry)), "{entry:?}");
        }
        assert_eq!(
            as_uuid("urn:uuid:20120000-0000-4000-8000-0000000000AB"),
            Some("20120000-0000-4000-8000-0000000000AB")
        );
        for not in [
            "urn:uuid:envoy",
            "20120000-0000-4000-8000-0000000000a",
            "20120000x0000-4000-8000-0000000000ab",
            "spiffe://x",
        ] {
            assert_eq!(as_uuid(not), None, "{not:?}");
        }
    }

    /// **#2000.** A terminator's connection without XFCC is (None, []): the
    /// certificate's NF types are the terminator's, never the caller's, even
    /// when the caller also carries a token subject.
    ///
    /// REVERT-VERIFIED: with `RegistrantIdentity::of` keying the NF types on
    /// `forwarded` again, the terminator's SCP type is reported and this fails.
    #[test]
    fn a_terminator_connection_without_xfcc_proves_no_nf_type_2000() {
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let mut bare =
            SbiRequest::put("/nnrf-nfm/v1/nf-instances/20000000-0000-4000-8000-0000000000bb");
        bare.peer_cert_nf_types = vec!["SCP".into()]; // the terminator's own
        from_test_terminator(&mut bare);
        let identity = RegistrantIdentity::of(&bare, &trusting);
        assert!(identity.certificate_identity().is_none());
        assert!(identity.nf_types.is_empty(), "got {:?}", identity.nf_types);

        bare.oauth2_subject = Some("20000000-0000-4000-8000-0000000000bb".into());
        let with_token = RegistrantIdentity::of(&bare, &trusting);
        assert_eq!(with_token.instance_ids.len(), 1, "the token subject only");
        assert!(
            with_token.nf_types.is_empty(),
            "got {:?}",
            with_token.nf_types
        );
    }

    /// **#1990 (R30).** Under production, believing XFCC needs the terminator
    /// allowlist and `client_auth: required`; either missing refuses startup.
    /// Under dev an empty allowlist is only logged.
    ///
    /// REVERT-VERIFIED: with `check_forwarded_trust` returning `Ok` always, the
    /// first assertion fails.
    #[test]
    fn production_needs_the_allowlist_and_required_client_auth_1990() {
        use nextgcore_sbi::security::SbiProfile;
        let tls = |client_auth| NrfServerTls {
            cert: "nrf.crt".into(),
            key: "nrf.key".into(),
            ca: "ca.crt".into(),
            client_auth,
        };
        let on = |terms: Vec<String>| NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: terms,
            ..NrfPolicy::default()
        };
        let listed = vec![TEST_TERMINATOR.to_string()];
        assert!(check_forwarded_trust(
            SbiProfile::Production,
            &on(Vec::new()),
            Some(&tls(ClientAuth::Required))
        )
        .is_err());
        assert!(check_forwarded_trust(
            SbiProfile::Production,
            &on(listed.clone()),
            Some(&tls(ClientAuth::Optional))
        )
        .is_err());
        assert!(check_forwarded_trust(SbiProfile::Production, &on(listed.clone()), None).is_err());
        assert!(check_forwarded_trust(
            SbiProfile::Production,
            &on(listed),
            Some(&tls(ClientAuth::Required))
        )
        .is_ok());
        assert!(check_forwarded_trust(SbiProfile::Dev, &on(Vec::new()), None).is_ok());
        assert!(
            check_forwarded_trust(SbiProfile::Production, &NrfPolicy::default(), None).is_ok(),
            "the flag off needs nothing"
        );
    }

    /// **#1979 (2).** `registrant_nf_types_required` reads the policy it is
    /// given, not the process-global one: a policy that does not require
    /// types answers no even though the global (default) policy does.
    ///
    /// REVERT-VERIFIED: with the function reading `nrf_policy()` again, the
    /// first assertion fails.
    #[test]
    fn the_nf_type_rule_reads_the_policy_it_is_given_1979() {
        let off = NrfPolicy {
            require_registrant_nf_types: false,
            ..NrfPolicy::default()
        };
        assert!(
            nrf_policy().require_registrant_nf_types,
            "control: the global requires them"
        );
        assert!(!registrant_nf_types_required(&off));
        assert!(registrant_nf_types_required(&NrfPolicy::default()));
    }

    /// The real NRF handler behind a mutual-TLS listener, and a client that
    /// presents a certificate with `client_uri` / `nf_types`.
    async fn mtls_nrf(
        tag: &str,
        client_uri: Option<&str>,
        nf_types: Option<&[&str]>,
    ) -> (SbiServer, SbiClient) {
        let (ca, server_cert, server_key, client_cert, client_key) = pki(tag, client_uri, nf_types);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg = NextgcoreSbiServerConfig::new(addr).with_tls(server_key, server_cert);
        cfg.verify_client = true;
        cfg.verify_client_cacert = Some(ca.clone());
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(nrf_sbi_request_handler)
            .await
            .expect("NRF starts");
        let mut client_cfg = SbiClientConfig::new("localhost", addr.port()).with_https();
        client_cfg.ca_cert = Some(ca);
        client_cfg.client_cert = Some(client_cert);
        client_cfg.client_key = Some(client_key);
        (server, SbiClient::new(client_cfg))
    }

    fn profile(id: &str, nf_type: &str) -> serde_json::Value {
        json!({
            "nfInstanceId": id,
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "ipv4Addresses": ["10.16.11.1"]
        })
    }

    fn cause(resp: &SbiResponse) -> String {
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
        body["cause"].as_str().unwrap_or_default().to_string()
    }

    async fn put(client: &SbiClient, id: &str, nf_type: &str) -> SbiResponse {
        client
            .put_json(
                &format!("/nnrf-nfm/v1/nf-instances/{id}"),
                &profile(id, nf_type),
            )
            .await
            .expect("PUT completes")
    }

    async fn patch(client: &SbiClient, id: &str, ops: serde_json::Value) -> SbiResponse {
        let req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{id}"))
            .with_body(ops.to_string(), "application/json-patch+json");
        client.send_request(req).await.expect("PATCH completes")
    }

    fn stored_type(id: &str) -> Option<String> {
        nf_manager().get(id).map(|p| p.nf_type)
    }

    /// Over real mutual TLS, a client whose verified certificate names NF
    /// instance `own` with NFTypes [`CUSTOM_T1611A`] registers, updates and
    /// deregisters only `own`, and only as that type. Registering, updating or
    /// deregistering another instance, or registering or patching `own` as a
    /// type the certificate does not name, is 400 INVALID_CLIENT and leaves the
    /// registry unchanged.
    ///
    /// REVERT-VERIFIED: with the binding calls removed from the handlers, every
    /// refusal here is accepted instead (201/200/204).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nf_management_is_bound_to_the_verified_certificate_1611() {
        let own = "1611a0a0-0000-4000-8000-00000000000a";
        let other = "1611b0b0-0000-4000-8000-00000000000b";
        let (server, client) = mtls_nrf(
            "bound",
            Some(&format!("urn:uuid:{own}")),
            Some(&["CUSTOM_T1611A"]),
        )
        .await;
        let run = async {
            // Another NF's instance: never registered under the caller's cert.
            let resp = put(&client, other, "CUSTOM_T1611A").await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert!(
                stored_type(other).is_none(),
                "nothing was stored for {other}"
            );

            // Its own instance as a type the certificate does not name.
            let resp = put(&client, own, "CUSTOM_T1611B").await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert!(stored_type(own).is_none());

            // Its own instance as its own type; the UUID is matched
            // case-insensitively (TS 29.510 §5.2.2.2.2).
            let upper = own.to_ascii_uppercase();
            let resp = put(&client, &upper, "CUSTOM_T1611A").await;
            assert_eq!(resp.status, 201, "{:?}", resp.http.content);
            // One entry, under the canonical ID (#1633); drop it.
            let _ = nf_manager().deregister(&upper);
            let resp = put(&client, own, "CUSTOM_T1611A").await;
            assert_eq!(resp.status, 201, "{:?}", resp.http.content);

            // NFUpdate: a heartbeat-style patch is fine, a re-typing patch is not.
            let resp = patch(
                &client,
                own,
                json!([{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}]),
            )
            .await;
            assert_eq!(resp.status, 200, "{:?}", resp.http.content);
            let resp = patch(
                &client,
                own,
                json!([{"op": "replace", "path": "/nfType", "value": "CUSTOM_T1611B"}]),
            )
            .await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert_eq!(stored_type(own).as_deref(), Some("CUSTOM_T1611A"));

            // Checked before the lookup: an instance nobody registered is 400, not
            // 404, so the caller learns nothing about which instances exist.
            let resp = patch(
                &client,
                other,
                json!([{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]),
            )
            .await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{other}"))
                .await
                .expect("DELETE completes");
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);

            // Another NF's existing instance: neither patched nor deregistered.
            let theirs = NfProfile::from_json(&profile(other, "CUSTOM_T1611B")).expect("profile");
            nf_manager().register(theirs).expect("stored");
            let resp = patch(
                &client,
                other,
                json!([{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]),
            )
            .await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{other}"))
                .await
                .expect("DELETE completes");
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert_eq!(stored_type(other).as_deref(), Some("CUSTOM_T1611B"));

            // Its own: deregistered.
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{own}"))
                .await
                .expect("DELETE completes");
            assert_eq!(resp.status, 204, "{:?}", resp.http.content);
            assert!(stored_type(own).is_none());
        };
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("bounded");
        let _ = nf_manager().deregister(other);
        server.stop().await.ok();
    }

    /// **#1633 review m2.** The registrant binding compares as the registry
    /// keys: a UUID case-insensitively, any other ID exactly. Over real mutual
    /// TLS, a certificate for `nrfd1633-m2` cannot register `NRFD1633-M2`, a
    /// distinct registry entry (400 INVALID_CLIENT, nothing stored), but
    /// registers its own ID; a certificate naming a UUID in upper case manages
    /// the lower-case instance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_registrant_binding_folds_only_uuid_case_1633() {
        let own = "nrfd1633-m2";
        let other = own.to_ascii_uppercase();
        let (server, client) = mtls_nrf(
            "m2-1633",
            Some(&format!("urn:uuid:{own}")),
            Some(&["CUSTOM_T1633M2"]),
        )
        .await;
        let run = async {
            let resp = put(&client, &other, "CUSTOM_T1633M2").await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert!(stored_type(&other).is_none(), "nothing stored for {other}");
            let resp = put(&client, own, "CUSTOM_T1633M2").await;
            assert_eq!(resp.status, 201, "{:?}", resp.http.content);
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{other}"))
                .await
                .expect("DELETE completes");
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(stored_type(own).as_deref(), Some("CUSTOM_T1633M2"));
        };
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("bounded");
        let _ = nf_manager().deregister(own);
        server.stop().await.ok();

        let lower = "1633d0d0-0000-4000-8000-0000000000c3";
        let upper = lower.to_ascii_uppercase();
        let (server, client) = mtls_nrf(
            "m2-1633-uuid",
            Some(&format!("urn:uuid:{upper}")),
            Some(&["CUSTOM_T1633M2"]),
        )
        .await;
        let run = async {
            let resp = put(&client, lower, "CUSTOM_T1633M2").await;
            assert_eq!(resp.status, 201, "{:?}", resp.http.content);
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{lower}"))
                .await
                .expect("DELETE completes");
            assert_eq!(resp.status, 204, "{:?}", resp.http.content);
        };
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("bounded");
        let _ = nf_manager().deregister(lower);
        server.stop().await.ok();
    }

    /// A verified certificate without an NFTypes extension still binds the
    /// instance (TS 33.310 §6.1.3c.3 URI-ID), but asserts no type to bind. Over
    /// real mTLS and under the NRF's shipped (production) policy, #1917: it
    /// therefore registers as no type at all, its own instance included.
    ///
    /// REVERT-VERIFIED (#1917): with the empty-NFTypes branch of `bind_nf_type`
    /// returning `None` again, the own-instance PUT is 201 and this fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_without_nf_types_binds_only_the_instance_1611() {
        let own = "1611c0c0-0000-4000-8000-00000000000c";
        let other = "1611d0d0-0000-4000-8000-00000000000d";
        let (server, client) = mtls_nrf("no-types", Some(&format!("urn:uuid:{own}")), None).await;
        let run = async {
            let resp = put(&client, other, "CUSTOM_T1611C").await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            let resp = put(&client, own, "CUSTOM_T1611C").await;
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert!(
                resp.http
                    .content
                    .as_deref()
                    .unwrap_or_default()
                    .contains("names no NF type"),
                "{:?}",
                resp.http.content
            );
            assert!(stored_type(own).is_none(), "nothing stored for {own}");
        };
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("bounded");
        let _ = nf_manager().deregister(own);
        server.stop().await.ok();
    }

    /// A verified certificate with NFTypes but no URI SAN names no NF instance,
    /// so since #1617 step f it cannot manage one: NFRegister is refused
    /// `400 INVALID_CLIENT` whatever type the profile names (nothing stored), and
    /// NFDeregister of a stored instance is refused with the entry kept.
    ///
    /// REVERT-VERIFIED (#1617 step f): with `require_registrant_identity: false`
    /// the first PUT is refused only for its type (the identity refusal is gone)
    /// and this test names it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_without_a_uri_san_manages_no_instance_1617() {
        let id = "1611e0e0-0000-4000-8000-00000000000e";
        let other = "1611f0f0-0000-4000-8000-00000000000f";
        let (server, client) = mtls_nrf("no-uri", None, Some(&["CUSTOM_T1611E"])).await;
        let run = async {
            for nf_type in ["CUSTOM_T1611F", "CUSTOM_T1611E"] {
                let resp = put(&client, id, nf_type).await;
                assert_eq!(resp.status, 400, "{nf_type}: {:?}", resp.http.content);
                assert_eq!(cause(&resp), "INVALID_CLIENT");
                assert!(
                    resp.http
                        .content
                        .as_deref()
                        .unwrap_or_default()
                        .contains("no verified client certificate identity"),
                    "{:?}",
                    resp.http.content
                );
                assert_eq!(stored_type(id), None, "{nf_type}: nothing stored");
            }
            let theirs = NfProfile::from_json(&profile(other, "CUSTOM_T1611F")).expect("profile");
            nf_manager().register(theirs).expect("stored");
            let resp = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{other}"))
                .await
                .expect("DELETE completes");
            assert_eq!(resp.status, 400, "{:?}", resp.http.content);
            assert_eq!(cause(&resp), "INVALID_CLIENT");
            assert_eq!(stored_type(other).as_deref(), Some("CUSTOM_T1611F"));
        };
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("bounded");
        let _ = nf_manager().deregister(id);
        let _ = nf_manager().deregister(other);
        server.stop().await.ok();
    }

    fn request_with(
        peer_id: Option<&str>,
        peer_types: &[&str],
        xfcc: Option<&str>,
        sub: Option<&str>,
    ) -> SbiRequest {
        let mut req = SbiRequest::put("/nnrf-nfm/v1/nf-instances/x");
        req.peer_cert_nf_instance_id = peer_id.map(str::to_string);
        req.peer_cert_nf_types = peer_types.iter().map(|t| t.to_string()).collect();
        if let Some(x) = xfcc {
            req.http.set_header(XFCC_HEADER, x.to_string());
            from_test_terminator(&mut req);
        }
        req.oauth2_subject = sub.map(str::to_string);
        req
    }

    /// The identity sources and their precedence: no verified identity binds
    /// nothing (TS 33.501 §13.3.1.1 implicit authentication); a verified token
    /// `sub` binds the instance; a forwarded identity binds the instance but not
    /// the terminator's own NF types; a certificate and a token must agree.
    #[test]
    fn the_registrant_identity_comes_only_from_verified_evidence_1611() {
        let plain = NrfPolicy::default();
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };

        // Plaintext / TLS-only: nothing to bind; a forged XFCC is ignored.
        let none = RegistrantIdentity::of(
            &plaintext(request_with(
                None,
                &[],
                Some(&test_xfcc("forged", &[])),
                None,
            )),
            &plain,
        );
        assert_eq!(none, RegistrantIdentity::default());
        assert!(none.bind_instance("NFRegister", "any").is_none());
        assert!(none
            .bind_nf_type("NFRegister", "any", "UDM", false)
            .is_none());

        // A verified token subject.
        let token = RegistrantIdentity::of(&request_with(None, &[], None, Some("nf-a")), &plain);
        assert!(token.bind_instance("NFRegister", "nf-a").is_none());
        assert_eq!(
            token
                .bind_instance("NFRegister", "nf-b")
                .expect("refused")
                .status,
            400
        );

        // A trusted forwarded identity: the connection's (terminator's) types
        // are not the registrant's.
        let fwd = RegistrantIdentity::of(
            &request_with(None, &["SCP"], Some(&test_xfcc("nf-c", &[])), None),
            &trusting,
        );
        assert_eq!(
            fwd.instance_ids,
            [("forwarded client certificate", "nf-c".to_string())]
        );
        assert!(fwd.nf_types.is_empty());
        assert!(fwd.forwarded);
        // Dev: accepted as asserted. Production (#1917): the forwarded caller's
        // type cannot be verified, so it is refused.
        assert!(fwd
            .bind_nf_type("NFRegister", "nf-c", "AMF", false)
            .is_none());
        let refused = fwd
            .bind_nf_type("NFRegister", "nf-c", "AMF", true)
            .expect("#1917: a forwarded identity's type is unverifiable");
        assert_eq!(refused.status, 400);
        assert!(refused
            .http
            .content
            .as_deref()
            .unwrap_or_default()
            .contains("a TLS terminator forwarded for it (XFCC Cert=) names no NF type"));

        // The direct certificate outranks the header and carries its types.
        let direct = RegistrantIdentity::of(
            &request_with(Some("nf-d"), &["AMF"], Some(&test_xfcc("nf-z", &[])), None),
            &trusting,
        );
        assert_eq!(
            direct.instance_ids,
            [("client certificate", "nf-d".to_string())]
        );
        assert!(!direct.forwarded);
        assert!(direct
            .bind_nf_type("NFRegister", "nf-d", "amf", true)
            .is_none());
        let refused = direct
            .bind_nf_type("NFRegister", "nf-d", "UDM", false)
            .expect("refused");
        assert_eq!(refused.status, 400);
        assert!(refused
            .http
            .content
            .as_deref()
            .unwrap_or_default()
            .contains("INVALID_CLIENT"));

        // Certificate and token must both match.
        let both =
            RegistrantIdentity::of(&request_with(Some("nf-e"), &[], None, Some("nf-f")), &plain);
        assert!(both.bind_instance("NFRegister", "nf-e").is_some());
        assert!(both.bind_instance("NFRegister", "nf-f").is_some());
    }
}

/// #1617 step b: the NRF's listener TLS from the command line, the environment
/// and `nrf.sbi.server[0].tls`; optional client authentication on the one
/// listener; the NF-management enforcement point; and the NRF's self client.
#[cfg(test)]
mod server_tls_tests_1617 {
    use super::*;
    use nextgcore_sbi::client::SbiClient;
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    const NRF_ID: &str = "6b1d7e3c-0000-4000-8000-0000000000f0";
    const AMF_ID: &str = "6b1d7e3c-0000-4000-8000-000000000af0";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn yaml_tls(text: &str) -> SbiServerTlsYaml {
        let y: NrfYaml = serde_yaml::from_str(text).expect("yaml");
        y.nrf
            .and_then(|n| n.sbi)
            .and_then(|s| s.server)
            .and_then(|v| v.into_iter().next())
            .and_then(|s| s.tls)
            .expect("nrf.sbi.server[0].tls")
    }

    const SHIPPED_SHAPE: &str = "nrf:\n  sbi:\n    server:\n      - address: 0.0.0.0\n        port: 7777\n        tls:\n          enabled: true\n          cert: /y/nrf.crt\n          key: /y/nrf.key\n          ca: /y/ca.crt\n          min_version: \"1.2\"\n";

    /// Off unless asked for, from any source; the shipped `tls:` shape parses.
    #[test]
    fn tls_is_off_by_default_and_on_from_any_source_1617() {
        let none = TlsFlags::default();
        assert_eq!(resolve_server_tls(&none, env(&[]), None).unwrap(), None);
        let off = yaml_tls("nrf:\n  sbi:\n    server:\n      - tls:\n          enabled: false\n");
        assert_eq!(
            resolve_server_tls(&none, env(&[]), Some(&off)).unwrap(),
            None
        );

        let on = yaml_tls(SHIPPED_SHAPE);
        let tls = resolve_server_tls(&none, env(&[]), Some(&on))
            .unwrap()
            .unwrap();
        assert_eq!(
            tls,
            NrfServerTls {
                cert: "/y/nrf.crt".into(),
                key: "/y/nrf.key".into(),
                ca: "/y/ca.crt".into(),
                client_auth: ClientAuth::Optional,
            }
        );

        let by_env = resolve_server_tls(&none, env(&[(NRF_SERVER_TLS_ENV, "true")]), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                by_env.cert.as_str(),
                by_env.key.as_str(),
                by_env.ca.as_str()
            ),
            (DEFAULT_SERVER_CERT, DEFAULT_SERVER_KEY, DEFAULT_CLIENT_CA)
        );
        assert_eq!(by_env.client_auth, ClientAuth::Optional);
        // The environment turns a YAML `enabled: true` off, and the flag wins.
        assert_eq!(
            resolve_server_tls(&none, env(&[(NRF_SERVER_TLS_ENV, "false")]), Some(&on)).unwrap(),
            None
        );
        let flag = TlsFlags {
            tls: true,
            ..TlsFlags::default()
        };
        assert!(
            resolve_server_tls(&flag, env(&[(NRF_SERVER_TLS_ENV, "false")]), None)
                .unwrap()
                .is_some()
        );
    }

    /// The command line beats the environment, which beats the YAML, path by path.
    #[test]
    fn each_path_comes_from_the_most_specific_source_1617() {
        let on = yaml_tls(SHIPPED_SHAPE);
        let flags = TlsFlags {
            cert: Some("/c/nrf.crt".into()),
            ..TlsFlags::default()
        };
        let tls = resolve_server_tls(
            &flags,
            env(&[
                (NRF_SERVER_TLS_CERT_ENV, "/e/nrf.crt"),
                (NRF_SERVER_TLS_KEY_ENV, "/e/nrf.key"),
                (NRF_SERVER_TLS_CA_ENV, " "),
            ]),
            Some(&on),
        )
        .unwrap()
        .unwrap();
        assert_eq!(tls.cert, "/c/nrf.crt");
        assert_eq!(tls.key, "/e/nrf.key");
        // An empty variable is unset.
        assert_eq!(tls.ca, "/y/ca.crt");
    }

    /// Client authentication is requested and optional by default, required only
    /// when asked; a bad value, a bad boolean, an unsupported minimum version and
    /// `--mtls` without TLS fail rather than serving weaker than asked.
    #[test]
    fn client_auth_is_optional_unless_required_and_bad_values_fail_1617() {
        let on = yaml_tls(SHIPPED_SHAPE);
        let none = TlsFlags::default();
        let auth = |e: &[(&str, &str)], y: &SbiServerTlsYaml, f: &TlsFlags| {
            resolve_server_tls(f, env(e), Some(y)).map(|t| t.unwrap().client_auth)
        };
        assert_eq!(auth(&[], &on, &none).unwrap(), ClientAuth::Optional);
        let mtls = TlsFlags {
            mtls: true,
            ..TlsFlags::default()
        };
        assert_eq!(auth(&[], &on, &mtls).unwrap(), ClientAuth::Required);
        // --mtls is the stricter choice: an environment `optional` does not undo it.
        assert_eq!(
            auth(&[(NRF_SERVER_TLS_CLIENT_AUTH_ENV, "optional")], &on, &mtls).unwrap(),
            ClientAuth::Required
        );
        assert_eq!(
            auth(&[(NRF_SERVER_TLS_CLIENT_AUTH_ENV, "Required")], &on, &none).unwrap(),
            ClientAuth::Required
        );
        let required = yaml_tls(
            "nrf:\n  sbi:\n    server:\n      - tls:\n          enabled: true\n          client_auth: required\n",
        );
        assert_eq!(auth(&[], &required, &none).unwrap(), ClientAuth::Required);
        assert!(auth(&[(NRF_SERVER_TLS_CLIENT_AUTH_ENV, "none")], &on, &none).is_err());

        assert!(resolve_server_tls(&none, env(&[(NRF_SERVER_TLS_ENV, "maybe")]), None).is_err());
        let v13 = yaml_tls(
            "nrf:\n  sbi:\n    server:\n      - tls:\n          enabled: true\n          min_version: \"1.0\"\n",
        );
        assert!(resolve_server_tls(&none, env(&[]), Some(&v13)).is_err());
        let err = resolve_server_tls(&mtls, env(&[]), None).unwrap_err();
        assert!(err.to_string().contains("--mtls"), "{err}");
    }

    /// The enforcement point: only a (direct or trusted-forwarded) certificate
    /// identity passes. Without one the request is counted, and refused
    /// `400 INVALID_CLIENT` only when enforcement is on (step f).
    #[test]
    fn nf_management_needs_a_certificate_identity_to_pass_the_hook_1617() {
        let plain = NrfPolicy::default();
        let trusting = NrfPolicy {
            trust_forwarded_client_cert: true,
            trusted_xfcc_terminators: vec![TEST_TERMINATOR.to_string()],
            ..NrfPolicy::default()
        };
        let req = |peer: Option<&str>, xfcc: Option<&str>, sub: Option<&str>| {
            let mut r = SbiRequest::put("/nnrf-nfm/v1/nf-instances/x");
            r.peer_cert_nf_instance_id = peer.map(str::to_string);
            if let Some(x) = xfcc {
                r.http.set_header(XFCC_HEADER, x.to_string());
                from_test_terminator(&mut r);
            }
            r.oauth2_subject = sub.map(str::to_string);
            r
        };
        let none = RegistrantIdentity::of(&req(None, None, None), &plain);
        let token_only = RegistrantIdentity::of(&req(None, None, Some("nf-a")), &plain);
        let direct = RegistrantIdentity::of(&req(Some("nf-a"), None, None), &plain);
        let forwarded =
            RegistrantIdentity::of(&req(None, Some(&test_xfcc("nf-a", &[])), None), &trusting);
        let untrusted_forward = RegistrantIdentity::of(
            &plaintext(req(None, Some(&test_xfcc("nf-a", &[])), None)),
            &plain,
        );

        let before = nextgcore_nrfd::metrics::unverified_nf_management_total();
        for (who, id) in [
            ("none", &none),
            ("token", &token_only),
            ("xfcc", &untrusted_forward),
        ] {
            assert_eq!(id.certificate_identity(), None, "{who}");
            assert!(
                id.require_certificate("NFRegister", "nf-a", false)
                    .is_none(),
                "{who}"
            );
            let refused = id
                .require_certificate("NFRegister", "nf-a", true)
                .unwrap_or_else(|| panic!("{who}: refused when enforced"));
            assert_eq!(refused.status, 400);
            assert!(refused
                .http
                .content
                .as_deref()
                .unwrap_or_default()
                .contains("INVALID_CLIENT"));
        }
        assert!(
            nextgcore_nrfd::metrics::unverified_nf_management_total() >= before + 6,
            "every unverified request is counted"
        );
        for (who, id) in [("direct", &direct), ("forwarded", &forwarded)] {
            assert_eq!(id.certificate_identity(), Some("nf-a"), "{who}");
            assert!(
                id.require_certificate("NFRegister", "nf-a", true).is_none(),
                "{who}"
            );
        }
    }

    /// Every shipped compose NRF config parses and serves TLS with client auth
    /// optional, from the stack's own certificate volume (#1617 step d: the
    /// one listener, a certificate requested but not required).
    #[test]
    fn every_shipped_nrf_config_serves_tls_with_optional_client_auth_1617() {
        let dir = repo_root().join("docker/rust/configs");
        let mut checked = 0;
        for sub in std::fs::read_dir(&dir).unwrap() {
            let sub = sub.unwrap().path();
            if !sub.is_dir() {
                continue;
            }
            for f in std::fs::read_dir(&sub).unwrap() {
                let f = f.unwrap().path();
                let name = f.file_name().unwrap().to_string_lossy().into_owned();
                if !(name.starts_with("nrf") && name.ends_with(".yaml")) {
                    continue;
                }
                let yaml = load_config(f.to_str().unwrap())
                    .unwrap_or_else(|e| panic!("{}: {e}", f.display()))
                    .unwrap();
                let tls = yaml
                    .nrf
                    .as_ref()
                    .and_then(|n| n.sbi.as_ref())
                    .and_then(|s| s.server.as_ref())
                    .and_then(|v| v.first())
                    .and_then(|s| s.tls.as_ref());
                assert_eq!(
                    resolve_server_tls(&TlsFlags::default(), env(&[]), tls).unwrap(),
                    Some(NrfServerTls {
                        cert: "/etc/nextgcore/certs/nrf.crt".into(),
                        key: "/etc/nextgcore/certs/nrf.key".into(),
                        ca: "/etc/nextgcore/certs/ca.crt".into(),
                        client_auth: ClientAuth::Optional,
                    }),
                    "{}",
                    f.display()
                );
                checked += 1;
            }
        }
        assert!(checked >= 5, "found {checked} NRF configs");
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .expect("repo root")
    }

    /// The shipped generator's PKI (the NRF row pins [`NRF_ID`]).
    struct DevPki(PathBuf);

    impl DevPki {
        fn generate(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("nrfd-1617b-pki-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let out = std::process::Command::new("bash")
                .arg(repo_root().join("docker/rust/certs/generate-dev-certs.sh"))
                .arg("--out")
                .arg(&dir)
                .output()
                .expect("run generate-dev-certs.sh (needs bash and openssl)");
            assert!(
                out.status.success(),
                "generate-dev-certs.sh failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            DevPki(dir)
        }

        fn file(&self, name: &str) -> String {
            self.0.join(name).display().to_string()
        }

        fn nrf_tls(&self) -> NrfServerTls {
            NrfServerTls {
                cert: self.file("nrf.crt"),
                key: self.file("nrf.key"),
                ca: self.file("ca.crt"),
                client_auth: ClientAuth::Optional,
            }
        }
    }

    impl Drop for DevPki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The self client: the listener's CA, its own certificate's DNS-ID `nrf`,
    /// and its own certificate as the client certificate only when that names
    /// the NRF's instance. Explicit NRF client settings win.
    #[test]
    fn the_nrf_dials_itself_with_its_own_ca_name_and_certificate_1617() {
        let pki = DevPki::generate("self");
        let tls = pki.nrf_tls();
        tls.check_files().expect("the generated files");

        let own = tls.self_client_tls(env(&[]), NRF_ID);
        assert_eq!(own.ca_cert, pki.file("ca.crt"));
        assert_eq!(own.server_name.as_deref(), Some("nrf"));
        assert_eq!(
            own.client_cert.as_deref(),
            Some(pki.file("nrf.crt").as_str())
        );
        assert_eq!(
            own.client_key.as_deref(),
            Some(pki.file("nrf.key").as_str())
        );
        assert_eq!(own.error, None);
        // The UUID compares case-insensitively (TS 29.510 §5.2.2.2.2).
        let upper = tls.self_client_tls(env(&[]), &NRF_ID.to_ascii_uppercase());
        assert_eq!(upper.client_cert, own.client_cert);

        // A certificate that names another instance is not presented.
        let other = tls.self_client_tls(env(&[]), AMF_ID);
        assert_eq!(other.client_cert, None);
        assert_eq!(other.client_key, None);
        assert_eq!(other.server_name.as_deref(), Some("nrf"));

        use nextgcore_sbi::nrf_tls::{
            NRF_TLS_CA_ENV, NRF_TLS_CLIENT_CERT_ENV, NRF_TLS_CLIENT_KEY_ENV,
            NRF_TLS_SERVER_NAME_ENV,
        };
        let explicit = tls.self_client_tls(
            env(&[
                (NRF_TLS_CA_ENV, "/x/ca.crt"),
                (NRF_TLS_CLIENT_CERT_ENV, "/x/c.crt"),
                (NRF_TLS_CLIENT_KEY_ENV, "/x/c.key"),
                (NRF_TLS_SERVER_NAME_ENV, "nrf.example"),
            ]),
            NRF_ID,
        );
        assert_eq!(explicit.ca_cert, "/x/ca.crt");
        assert_eq!(explicit.client_cert.as_deref(), Some("/x/c.crt"));
        assert_eq!(explicit.client_key.as_deref(), Some("/x/c.key"));
        assert_eq!(explicit.server_name.as_deref(), Some("nrf.example"));
        // Half an explicit pair stays an error, not a silent fallback to ours.
        let half = tls.self_client_tls(env(&[(NRF_TLS_CLIENT_CERT_ENV, "/x/c.crt")]), NRF_ID);
        assert!(half.error.is_some());

        let missing = NrfServerTls {
            ca: pki.file("missing-ca.crt"),
            ..pki.nrf_tls()
        };
        let err = missing.check_files().unwrap_err();
        assert!(err.to_string().contains("missing-ca.crt"), "{err}");
    }

    /// Over the real handler behind `NrfServerTls::apply` (optional client auth):
    /// - a client with no certificate completes the handshake and discovery is
    ///   200, but since step f its NFRegister, NFUpdate and NFDeregister are each
    ///   refused 400 INVALID_CLIENT and counted unverified, and none of them
    ///   applies anything (no entry created; a stored entry neither patched nor
    ///   removed). REVERT-VERIFIED: with `require_registrant_identity: false`
    ///   the PUT is 201 and the first refusal assertion names it;
    /// - a client whose certificate does not chain to the CA is refused at the
    ///   handshake;
    /// - the NRF's self client (`self_client_tls`, dialling `127.0.0.1`) is
    ///   verified as `nrf`, registers the NRF's own instance with its certificate
    ///   and obtains an access token from its own token endpoint, the transport
    ///   `OAuth2Client::new(nrf_self_uri())` uses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_tls_listener_serves_callers_with_and_without_certificates_1617() {
        let _g = nextgcore_sbi::nrf_tls::NRF_CLIENT_TLS_TEST_LOCK
            .lock()
            .await;
        // It registers the dev PKI's NRF ID (#1733).
        let _self_entry = self_entry_test_lock().lock().await;
        let pki = DevPki::generate("listener");
        let foreign = DevPki::generate("foreign");
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let cfg = pki.nrf_tls().apply(NextgcoreSbiServerConfig::new(addr));
        assert!(cfg.verify_client && cfg.verify_client_optional);
        let server = SbiServer::on_listener(cfg, listener);
        server.start(nrf_sbi_request_handler).await.expect("starts");
        let uri = format!("https://127.0.0.1:{}", addr.port());
        let client_with = |cert: Option<(String, String)>| {
            let mut c = nextgcore_sbi::client::SbiClientConfig::new("127.0.0.1", addr.port())
                .with_https()
                .with_tls_server_name("nrf");
            c.ca_cert = Some(pki.file("ca.crt"));
            if let Some((crt, key)) = cert {
                c.client_cert = Some(crt);
                c.client_key = Some(key);
            }
            SbiClient::new(c)
        };
        let anon_id = "1617b000-0000-4000-8000-0000000000a1";
        let run = async {
            let anon = client_with(None);
            let r = anon
                .get("/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF")
                .await
                .expect("no certificate: the handshake completes");
            assert_eq!(r.status, 200);
            let refused = |r: &SbiResponse, what: &str| {
                assert_eq!(r.status, 400, "{what} refused: {:?}", r.http.content);
                let body = r.http.content.as_deref().unwrap_or_default();
                assert!(body.contains("INVALID_CLIENT"), "{what}: {body}");
                assert!(
                    body.contains("no verified client certificate identity"),
                    "{what}: {body}"
                );
            };
            let before = nextgcore_nrfd::metrics::unverified_nf_management_total();
            let r = anon
                .put_json(
                    &format!("/nnrf-nfm/v1/nf-instances/{anon_id}"),
                    &json!({"nfInstanceId": anon_id, "nfType": "CUSTOM_T1617B",
                            "nfStatus": "REGISTERED", "heartBeatTimer": 10}),
                )
                .await
                .expect("PUT completes");
            refused(&r, "NFRegister");
            assert!(nf_manager().get(anon_id).is_none(), "nothing registered");
            let after_put = nextgcore_nrfd::metrics::unverified_nf_management_total();
            assert!(after_put > before, "NFRegister counted");
            // An entry its owner registered: the anonymous caller may neither
            // patch nor remove it.
            nf_manager()
                .register(
                    NfProfile::from_json(&json!({"nfInstanceId": anon_id,
                        "nfType": "CUSTOM_T1617B", "nfStatus": "REGISTERED"}))
                    .expect("profile"),
                )
                .expect("stored");
            let req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{anon_id}")).with_body(
                json!([{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]).to_string(),
                "application/json-patch+json",
            );
            let r = anon.send_request(req).await.expect("PATCH completes");
            refused(&r, "NFUpdate");
            assert_eq!(
                nf_manager().get(anon_id).map(|p| p.nf_status).as_deref(),
                Some("REGISTERED"),
                "not patched"
            );
            let after_patch = nextgcore_nrfd::metrics::unverified_nf_management_total();
            assert!(after_patch > after_put, "NFUpdate counted");
            let r = anon
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{anon_id}"))
                .await
                .expect("DELETE completes");
            refused(&r, "NFDeregister");
            assert!(nf_manager().get(anon_id).is_some(), "not removed");
            assert!(
                nextgcore_nrfd::metrics::unverified_nf_management_total() > after_patch,
                "NFDeregister counted"
            );
            nf_manager().deregister(anon_id).ok();

            let forged = client_with(Some((foreign.file("amf.crt"), foreign.file("amf.key"))));
            let err = forged
                .get("/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF")
                .await
                .expect_err("a certificate of another CA is refused");
            assert!(
                !matches!(err, nextgcore_sbi::error::SbiError::HttpError { .. }),
                "refused at the handshake, not by a handler: {err:?}"
            );

            // The NRF's self client.
            nextgcore_sbi::nrf_tls::set_nrf_client_tls_override(Some(
                pki.nrf_tls().self_client_tls(env(&[]), NRF_ID),
            ));
            let own = SbiClient::for_nrf_uri(&uri).expect("self URI");
            let r = own
                .put_json(
                    &format!("/nnrf-nfm/v1/nf-instances/{NRF_ID}"),
                    &nrf_self_profile_for(&uri)
                        .as_object()
                        .cloned()
                        .map(|mut p| {
                            p.insert("nfInstanceId".into(), json!(NRF_ID));
                            serde_json::Value::Object(p)
                        })
                        .unwrap(),
                )
                .await
                .expect("the self client reaches the NRF over TLS");
            assert!(
                r.status == 201 || r.status == 200,
                "the NRF registers itself with its certificate: {} {:?}",
                r.status,
                r.http.content
            );
            let oauth = nextgcore_sbi::oauth::OAuth2Client::new(&uri, NRF_ID, NfType::Nrf);
            let token = oauth.get_token(NfType::Nrf, "nnrf-disc").await;
            nf_manager().deregister(NRF_ID).ok();
            let token = token.expect("the self token client is granted over TLS");
            assert!(!token.is_empty());
        };
        let outcome = tokio::time::timeout(Duration::from_secs(60), run).await;
        nextgcore_sbi::nrf_tls::set_nrf_client_tls_override(None);
        server.stop().await.ok();
        outcome.expect("finishes");
    }
}

/// #1617 step 1: the shipped dev PKI (`docker/rust/certs/generate-dev-certs.sh`)
/// issues every NF a certificate the NRF can verify a registrant by. Run the
/// real script, then drive the real NRF handler behind a mutual-TLS listener
/// with each issued certificate.
#[cfg(test)]
mod dev_pki_tests_1617 {
    use super::*;
    use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .expect("repo root")
    }

    /// (cert name, nfType, nfInstanceId) rows of `nf-identities.txt`.
    fn identities() -> Vec<(String, String, String)> {
        let path = repo_root().join("docker/rust/certs/nf-identities.txt");
        let text = std::fs::read_to_string(&path).expect("identity table");
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                assert!(f.len() >= 3, "malformed identity row {l:?}");
                (f[0].to_string(), f[1].to_string(), f[2].to_string())
            })
            .collect()
    }

    /// The script's output, in a directory removed when this is dropped (it
    /// holds private keys).
    struct DevPki(PathBuf);

    impl DevPki {
        fn generate(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("nrfd-1617-pki-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let pki = DevPki(dir);
            let script = repo_root().join("docker/rust/certs/generate-dev-certs.sh");
            let out = std::process::Command::new("bash")
                .arg(&script)
                .arg("--out")
                .arg(&pki.0)
                .output()
                .expect("run generate-dev-certs.sh (needs bash and openssl)");
            assert!(
                out.status.success(),
                "generate-dev-certs.sh failed: {}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            pki
        }

        fn file(&self, name: &str) -> String {
            self.0.join(name).display().to_string()
        }
    }

    impl Drop for DevPki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Every issued certificate carries `urn:uuid:<nfInstanceId>` and RFC 9310
    /// NFTypes `[nfType]` from its table row (TS 33.310 §6.1.3c.3), as the
    /// NRF's own certificate parser reads them.
    ///
    /// REVERT-VERIFIED: with the pre-#1617 script (DNS SANs only) every
    /// certificate yields no NF instance ID and no NF types.
    #[test]
    fn every_dev_certificate_names_its_nf_instance_and_type_1617() {
        let pki = DevPki::generate("profile");
        let ids = identities();
        assert!(ids.len() >= 10, "the table covers the stack: {ids:?}");
        for (name, nf_type, id) in ids {
            let der = nextgcore_sbi::tls::load_certs(&pki.file(&format!("{name}.crt")))
                .expect("issued certificate")
                .remove(0);
            assert_eq!(
                nextgcore_sbi::peer_cert::nf_instance_id_from_der(&der).as_deref(),
                Some(id.as_str()),
                "{name}.crt URI SAN"
            );
            assert_eq!(
                nextgcore_sbi::peer_cert::nf_types_from_der(&der),
                vec![nf_type.clone()],
                "{name}.crt NFTypes"
            );
        }
    }

    /// Over real mutual TLS, with the NRF serving `nrf.crt`, each NF's
    /// certificate is accepted as a TLS client and registers, heartbeats and
    /// deregisters its own nfInstanceId as its own nfType (201 / 200 / 204),
    /// and is refused 400 INVALID_CLIENT for another NF's ID or as another
    /// nfType (#1611 binding).
    ///
    /// REVERT-VERIFIED: with the pre-#1617 script, the certificates have
    /// `extendedKeyUsage = serverAuth` only and the handshake fails as a TLS
    /// client; with no URN, the other-ID PUT is 201; with no NFTypes, the
    /// other-type PUT is 201.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_dev_certificate_registers_only_itself_over_mtls_1617() {
        // The NRF row's ID is the one the #1617 listener test registers, and
        // every row's ID must be absent here (#1733).
        let _self_entry = self_entry_test_lock().lock().await;
        let pki = DevPki::generate("register");
        let ids = identities();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let mut cfg =
            NextgcoreSbiServerConfig::new(addr).with_tls(pki.file("nrf.key"), pki.file("nrf.crt"));
        cfg.verify_client = true;
        cfg.verify_client_cacert = Some(pki.file("ca.crt"));
        let server = SbiServer::on_listener(cfg, listener);
        server
            .start(nrf_sbi_request_handler)
            .await
            .expect("NRF starts with the dev nrf.crt");
        let run = async {
            for (i, (name, nf_type, id)) in ids.iter().enumerate() {
                // The dev PKI names no loopback address (#1617 step a): the
                // NRF is verified as `nrf` while dialled on 127.0.0.1.
                let mut client_cfg = SbiClientConfig::new("127.0.0.1", addr.port())
                    .with_https()
                    .with_tls_server_name("nrf");
                client_cfg.ca_cert = Some(pki.file("ca.crt"));
                client_cfg.client_cert = Some(pki.file(&format!("{name}.crt")));
                client_cfg.client_key = Some(pki.file(&format!("{name}.key")));
                let client = SbiClient::new(client_cfg);
                let profile = |id: &str| {
                    json!({
                        "nfInstanceId": id,
                        "nfType": nf_type,
                        "nfStatus": "REGISTERED",
                        "heartBeatTimer": 10,
                        "ipv4Addresses": ["10.16.17.1"]
                    })
                };

                // Another row's ID: the certificate does not name it.
                let (_, _, other) = &ids[(i + 1) % ids.len()];
                let resp = client
                    .put_json(
                        &format!("/nnrf-nfm/v1/nf-instances/{other}"),
                        &profile(other),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("{name}: PUT over mTLS: {e}"));
                assert_eq!(resp.status, 400, "{name} registering {other}");
                assert!(
                    nf_manager().get(other).is_none(),
                    "{name}: {other} not stored"
                );

                // Its own ID as a type the certificate's NFTypes do not name.
                let mut retyped = profile(id);
                retyped["nfType"] = json!(if nf_type == "UDM" { "UDR" } else { "UDM" });
                let resp = client
                    .put_json(&format!("/nnrf-nfm/v1/nf-instances/{id}"), &retyped)
                    .await
                    .expect("PUT completes");
                assert_eq!(resp.status, 400, "{name} registering as another type");
                assert!(nf_manager().get(id).is_none(), "{name}: not stored");

                let resp = client
                    .put_json(&format!("/nnrf-nfm/v1/nf-instances/{id}"), &profile(id))
                    .await
                    .expect("PUT completes");
                assert_eq!(resp.status, 201, "{name}: {:?}", resp.http.content);
                let req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{id}")).with_body(
                    json!([{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}])
                        .to_string(),
                    "application/json-patch+json",
                );
                let resp = client.send_request(req).await.expect("PATCH completes");
                assert_eq!(resp.status, 200, "{name}: {:?}", resp.http.content);
                let resp = client
                    .delete(&format!("/nnrf-nfm/v1/nf-instances/{id}"))
                    .await
                    .expect("DELETE completes");
                assert_eq!(resp.status, 204, "{name}: {:?}", resp.http.content);
            }
        };
        let outcome = tokio::time::timeout(Duration::from_secs(60), run).await;
        server.stop().await.ok();
        outcome.expect("dev PKI registrations finish");
    }
}

/// #1633: TS 29.510 §5.2.2.2.2: an NF Instance ID UUID in upper case is handled as
/// if it were lower case. One NF, however its ID is cased, is one registry entry.
#[cfg(test)]
mod registry_uuid_case_tests_1633 {
    use super::*;
    use serde_json::json;

    /// Over the real handler: the upper-case PUT replaces (200) the lower-case
    /// registration instead of adding a second instance; GET, PATCH, discovery by
    /// `target-nf-instance-id` and DELETE in the other case all reach the one entry,
    /// and the stored profile carries the canonical (lower-case) ID.
    ///
    /// REVERT-VERIFIED: without the canonicalisation the upper-case PUT is a second
    /// 201 and discovery returns the NF twice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_nf_is_one_entry_however_its_uuid_is_cased_1633() {
        let lower = "1633aaaa-bbbb-4ccc-8ddd-eeeeffff0001";
        let upper = lower.to_ascii_uppercase();
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        server
            .start(nrf_handler_as_path_certificate)
            .await
            .expect("starts");
        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let profile = |id: &str| {
            json!({
                "nfInstanceId": id,
                "nfType": "CUSTOM_T1633",
                "nfStatus": "REGISTERED",
                "heartBeatTimer": 10,
                "ipv4Addresses": ["10.16.33.1"]
            })
        };
        let entries = || {
            nf_manager()
                .list()
                .into_iter()
                .filter(|p| p.nf_instance_id.eq_ignore_ascii_case(lower))
                .count()
        };
        let run = async {
            let r = client
                .put_json(
                    &format!("/nnrf-nfm/v1/nf-instances/{lower}"),
                    &profile(lower),
                )
                .await
                .expect("PUT");
            assert_eq!(r.status, 201);
            let r = client
                .put_json(
                    &format!("/nnrf-nfm/v1/nf-instances/{upper}"),
                    &profile(&upper),
                )
                .await
                .expect("PUT");
            assert_eq!(r.status, 200, "a replacement of the same instance");
            assert_eq!(entries(), 1);

            let r = client
                .get(&format!("/nnrf-nfm/v1/nf-instances/{upper}"))
                .await
                .expect("GET");
            assert_eq!(r.status, 200);
            let body: serde_json::Value =
                serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(body["nfInstanceId"], lower, "stored under the canonical ID");

            let patch = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{upper}")).with_body(
                json!([{"op": "replace", "path": "/ipv4Addresses", "value": ["10.16.33.2"]}])
                    .to_string(),
                "application/json-patch+json",
            );
            let r = client.send_request(patch).await.expect("PATCH");
            assert_eq!(r.status, 200, "{:?}", r.http.content);
            assert_eq!(
                nf_manager().get(lower).expect("one").ipv4_addresses,
                ["10.16.33.2"]
            );
            assert_eq!(entries(), 1);

            let r = client
                .get(&format!(
                    "/nnrf-disc/v1/nf-instances?target-nf-type=CUSTOM_T1633&requester-nf-type=AMF\
                     &target-nf-instance-id={upper}"
                ))
                .await
                .expect("discover");
            assert_eq!(r.status, 200, "{:?}", r.http.content);
            let body: serde_json::Value =
                serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                body["nfInstances"].as_array().map(Vec::len),
                Some(1),
                "{body}"
            );

            let r = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{upper}"))
                .await
                .expect("DELETE");
            assert_eq!(r.status, 204);
            assert_eq!(entries(), 0);
        };
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("bounded");
        let _ = nf_manager().deregister(lower);
        server.stop().await.ok();
    }
}

/// #1667: an NF obtains its token for this NRF's own APIs BEFORE its first
/// NFRegister (TS 29.510 §6.1.8 / §6.2.8), so the token endpoint grants
/// `nnrf-nfm` / `nnrf-disc` to a consumer the registry does not hold yet, on the
/// identity it proved, and the nrfd-06 gate admits that token.
#[cfg(test)]
mod nrf_api_tokens_tests_1667 {
    use super::*;
    use serde_json::json;

    /// A token request for `nf_type` `id`, targeting `target`, presented over a
    /// connection whose verified client certificate is `cert` (URN, NFTypes).
    fn token_req(
        id: &str,
        nf_type: &str,
        target: serde_json::Value,
        scope: &str,
        cert: Option<(&str, &[&str])>,
    ) -> SbiRequest {
        let mut body = json!({
            "grant_type": "client_credentials", "nfInstanceId": id, "nfType": nf_type,
            "scope": scope,
        });
        for (k, v) in target.as_object().expect("target fields") {
            body[k] = v.clone();
        }
        let mut r = SbiRequest::post("/oauth2/token");
        r.http.set_content(body.to_string());
        if let Some((cert_id, types)) = cert {
            r.peer_cert_nf_instance_id = Some(cert_id.to_string());
            r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        }
        r
    }

    fn error_of(resp: &SbiResponse) -> String {
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        format!(
            "{} {}",
            v["error"].as_str().unwrap_or_default(),
            v["error_description"].as_str().unwrap_or_default()
        )
    }

    /// An NF the registry does not hold, authenticated by its client
    /// certificate under the default policy (client authentication required),
    /// gets a token for each NRF API, aimed at `targetNfType: NRF` or at this
    /// NRF's instance ID; the gate admits it as that NF; without it, NFRegister
    /// is 401. This holds with the NRF's own entry ABSENT from its registry.
    ///
    /// REVERT-VERIFIED: without `unregistered_nrf_api_consumer`, and separately
    /// without the self-profile fallback in the producer set, no token is
    /// granted (the first request is refused, not 200).
    #[tokio::test]
    async fn an_unregistered_nf_gets_an_nrf_token_on_its_certificate_1667() {
        let _self_entry = self_entry_test_lock().lock().await;
        nf_manager().deregister(nrf_instance_id()).ok();
        let id = "1667c0c0-0000-4000-8000-00000000000c";
        assert!(nf_manager().get(id).is_none(), "unregistered");
        let policy = NrfPolicy::default();
        assert!(policy.require_client_auth, "the real default");
        let jwks = nrf_jwks_json();
        let nfm = format!("/nnrf-nfm/v1/nf-instances/{id}");
        let disc = "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF";

        for (target, scope, path) in [
            (json!({"targetNfType": "NRF"}), "nnrf-nfm", nfm.as_str()),
            (json!({"targetNfType": "NRF"}), "nnrf-disc", disc),
            (
                json!({"targetNfInstanceId": nrf_instance_id()}),
                "nnrf-nfm",
                nfm.as_str(),
            ),
        ] {
            let resp = handle_access_token_request_with_policy(
                &token_req(id, "AMF", target.clone(), scope, Some((id, &["AMF"]))),
                &policy,
            )
            .await;
            assert_eq!(resp.status, 200, "{target} {scope}: {}", error_of(&resp));
            let v: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let token = v["access_token"].as_str().expect("access_token");
            let sub = oauth2_gate(path, Some(&format!("Bearer {token}")), true, &jwks)
                .unwrap_or_else(|r| panic!("{target} {scope}: gate refused {}", r.status));
            assert_eq!(sub.as_deref(), Some(id), "the token's subject is the NF");
        }
        assert!(nf_manager().get(id).is_none(), "a token registers nothing");

        let refused = *oauth2_gate(&nfm, None, true, &jwks).expect_err("no token");
        assert_eq!(refused.status, 401, "NFRegister without a token");
    }

    /// **#1952.** Where the NRF requires verified NF types (#1917/#1926), the
    /// bootstrap grant does too: an unregistered NF whose certificate names no
    /// NF type gets no nnrf token claiming AUSF (or anything); one naming AUSF
    /// does. Under a dev NRF without TLS the asserted type is still accepted.
    ///
    /// REVERT-VERIFIED: with the `registrant_nf_types_required()` block removed
    /// from `unregistered_nrf_api_consumer`, the typeless request gets 200 and
    /// the first assertion fails.
    #[tokio::test]
    async fn a_typeless_certificate_gets_no_nrf_token_where_types_are_required_1952() {
        use super::registrant_nf_type_tests_1917::REQUIRED;
        let _self_entry = self_entry_test_lock().lock().await;
        let id = "19520000-0000-4000-8000-00000000000a";
        assert!(nf_manager().get(id).is_none(), "unregistered");
        let policy = NrfPolicy::default();
        let nrf = json!({"targetNfType": "NRF"});
        let ask = |types: &'static [&'static str]| {
            token_req(id, "AUSF", nrf.clone(), "nnrf-disc", Some((id, types)))
        };

        let resp = REQUIRED
            .scope(
                true,
                handle_access_token_request_with_policy(&ask(&[]), &policy),
            )
            .await;
        assert_eq!(
            resp.status,
            400,
            "typeless, types required: {}",
            error_of(&resp)
        );
        assert!(
            error_of(&resp).contains("cannot be verified"),
            "refused for the unverified type: {}",
            error_of(&resp)
        );

        let resp = REQUIRED
            .scope(
                true,
                handle_access_token_request_with_policy(&ask(&["AUSF"]), &policy),
            )
            .await;
        assert_eq!(
            resp.status,
            200,
            "a certificate naming AUSF: {}",
            error_of(&resp)
        );

        let resp = REQUIRED
            .scope(
                false,
                handle_access_token_request_with_policy(&ask(&[]), &policy),
            )
            .await;
        assert_eq!(
            resp.status,
            200,
            "dev without TLS keeps the asserted type: {}",
            error_of(&resp)
        );
        assert!(nf_manager().get(id).is_none(), "a token registers nothing");
    }

    /// The bootstrap grant is only for this NRF's APIs, and only on proof: an
    /// unregistered NF is still refused `invalid_client` with no proven
    /// identity, for another target, for a non-NRF scope, or as an nfType its
    /// certificate does not name.
    ///
    /// REVERT-VERIFIED: with the scope check removed, the `namf-comm` request
    /// is not refused 400 `invalid_client`; with the NFTypes check removed,
    /// neither is the AMF request over an SMF certificate.
    #[tokio::test]
    async fn an_unregistered_nf_gets_no_other_token_and_none_without_proof_1667() {
        let _self_entry = self_entry_test_lock().lock().await;
        let id = "1667d0d0-0000-4000-8000-00000000000d";
        let cert: Option<(&str, &[&str])> = Some((id, &["AMF"]));
        let nrf = json!({"targetNfType": "NRF"});
        for (what, req, policy) in [
            (
                "no proven identity",
                token_req(id, "AMF", nrf.clone(), "nnrf-nfm", None),
                NrfPolicy {
                    require_client_auth: false,
                    ..NrfPolicy::default()
                },
            ),
            (
                "another target type",
                token_req(
                    id,
                    "AMF",
                    json!({"targetNfType": "SMF"}),
                    "nsmf-pdusession",
                    cert,
                ),
                NrfPolicy::default(),
            ),
            (
                "another target instance",
                token_req(
                    id,
                    "AMF",
                    json!({"targetNfInstanceId": "1667e0e0-0000-4000-8000-00000000000e"}),
                    "nnrf-nfm",
                    cert,
                ),
                NrfPolicy::default(),
            ),
            (
                "a scope that is not an NRF API",
                token_req(id, "AMF", nrf.clone(), "nnrf-nfm namf-comm", cert),
                NrfPolicy::default(),
            ),
            (
                "an nfType the certificate does not name",
                token_req(id, "AMF", nrf.clone(), "nnrf-nfm", Some((id, &["SMF"]))),
                NrfPolicy::default(),
            ),
        ] {
            let resp = handle_access_token_request_with_policy(&req, &policy).await;
            assert_eq!(resp.status, 400, "{what}");
            let err = error_of(&resp);
            assert!(
                err.starts_with("invalid_client ") && err.contains("not registered"),
                "{what}: {err}"
            );
            if what.starts_with("an nfType") {
                assert!(err.contains("NF types of its client certificate"), "{err}");
            }
        }
    }

    /// The claims of a token the endpoint answered with.
    fn claims_of(resp: &SbiResponse) -> (String, serde_json::Value) {
        use base64::Engine;
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        let token = v["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();
        let payload = token.split('.').nth(1).expect("JWS payload");
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url");
        (token, serde_json::from_slice(&claims).expect("claims JSON"))
    }

    /// #1750: the bootstrap grant is authorized on "the target is this NRF", so
    /// the exact producer is known and `aud` is this NRF's instance ID (TS 29.510
    /// Table 6.3.5.2.4-1), however the target was named: by `targetNfType: NRF`
    /// or by this NRF's instance ID. The gate admits it; a token naming another
    /// NRF's instance, or the NRF type of a peer set, is not one for this NRF
    /// unless it names this instance or the type. A registered consumer asking
    /// by type still gets the type: its producer set is every registered NRF.
    ///
    /// REVERT-VERIFIED: without the pin in `handle_access_token_request`, the
    /// `targetNfType: NRF` grant has `aud: "NRF"` and the first assertion names it.
    #[tokio::test]
    async fn the_bootstrap_token_names_this_nrf_instance_as_audience_1750() {
        let _self_entry = self_entry_test_lock().lock().await;
        let id = "1750c0c0-0000-4000-8000-00000000000c";
        assert!(nf_manager().get(id).is_none(), "unregistered");
        let policy = NrfPolicy::default();
        let jwks = nrf_jwks_json();
        let nfm = format!("/nnrf-nfm/v1/nf-instances/{id}");
        for target in [
            json!({"targetNfType": "NRF"}),
            json!({"targetNfInstanceId": nrf_instance_id()}),
            json!({"targetNfType": "NRF", "targetNfInstanceId": nrf_instance_id()}),
        ] {
            let resp = handle_access_token_request_with_policy(
                &token_req(id, "AMF", target.clone(), "nnrf-nfm", Some((id, &["AMF"]))),
                &policy,
            )
            .await;
            assert_eq!(resp.status, 200, "{target}: {}", error_of(&resp));
            let (token, claims) = claims_of(&resp);
            assert_eq!(
                claims["aud"],
                json!([nrf_instance_id()]),
                "{target}: the bootstrap token's audience is this NRF instance"
            );
            assert_eq!(claims["sub"], json!(id));
            let sub = oauth2_gate(&nfm, Some(&format!("Bearer {token}")), true, &jwks)
                .unwrap_or_else(|r| panic!("{target}: gate refused {}", r.status));
            assert_eq!(sub.as_deref(), Some(id));
        }
        assert!(nf_manager().get(id).is_none(), "a token registers nothing");

        // Another NRF's instance ID: signed by this NRF's key, still not a token
        // for this NRF.
        let other_nrf = "1750eeee-0000-4000-8000-0000000000f0";
        let foreign = super::tests::mint_nrf_token_with(id, &json!([other_nrf]), "nnrf-nfm", 3600);
        let refused = *oauth2_gate(&nfm, Some(&format!("Bearer {foreign}")), true, &jwks)
            .expect_err("another NRF's audience");
        assert_eq!(refused.status, 403, "{:?}", refused.http.content);
        assert!(
            refused
                .http
                .content
                .as_deref()
                .unwrap_or_default()
                .contains("ACCESS_TOKEN_CLAIM_MISMATCH"),
            "{:?}",
            refused.http.content
        );

        // A registered consumer asking by type: unchanged, the NF type.
        let registered = "1750d0d0-0000-4000-8000-00000000000d";
        nf_manager()
            .register(
                NfProfile::from_json(&json!({"nfInstanceId": registered, "nfType": "AMF",
                    "nfStatus": "REGISTERED"}))
                .expect("profile"),
            )
            .expect("stored");
        let resp = handle_access_token_request_with_policy(
            &token_req(
                registered,
                "AMF",
                json!({"targetNfType": "NRF"}),
                "nnrf-nfm",
                Some((registered, &["AMF"])),
            ),
            &policy,
        )
        .await;
        nf_manager().deregister(registered).ok();
        assert_eq!(resp.status, 200, "{}", error_of(&resp));
        assert_eq!(claims_of(&resp).1["aud"], json!("NRF"));
    }
}

/// #1719: the registrant's `nfSetIdList` under `nrf.nf_set_allowlist`, through
/// the real NFRegister and NFUpdate handlers.
#[cfg(test)]
mod tests_guami_uniqueness_2035 {
    use super::*;
    use serde_json::json;

    fn guami(amf_id: &str) -> serde_json::Value {
        json!({ "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": amf_id })
    }

    async fn put_amf(id: &str, set: Option<&str>, guamis: &[&str], backup: &[&str]) -> SbiResponse {
        let mut amf_info = json!({
            "amfRegionId": "20",
            "guamiList": guamis.iter().map(|g| guami(g)).collect::<Vec<_>>(),
        });
        if let Some(set) = set {
            amf_info["amfSetId"] = json!(set);
        }
        if !backup.is_empty() {
            amf_info["backupInfoAmfFailure"] =
                json!(backup.iter().map(|g| guami(g)).collect::<Vec<_>>());
        }
        let body = json!({
            "nfInstanceId": id, "nfType": "AMF", "nfStatus": "REGISTERED",
            "heartBeatTimer": 10, "ipv4Addresses": ["10.20.35.1"], "amfInfo": amf_info,
        });
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"))
            .with_body(body.to_string(), "application/json");
        req.peer_cert_nf_instance_id = Some(id.to_string());
        req.peer_cert_nf_types = vec!["AMF".to_string()];
        handle_nf_register(id, &req).await
    }

    async fn patch(id: &str, ops: serde_json::Value) -> SbiResponse {
        let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{id}"))
            .with_body(ops.to_string(), "application/json-patch+json");
        req.peer_cert_nf_instance_id = Some(id.to_string());
        req.peer_cert_nf_types = vec!["AMF".to_string()];
        handle_nf_update(id, &req).await
    }

    fn listed(id: &str) -> Vec<String> {
        nf_manager()
            .get(id)
            .map(|p| {
                nextgcore_nrfd::sbi_path::guami_list_of(&p.to_json())
                    .iter()
                    .filter_map(|g| g.get("amfId").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// #2035: a GUAMI identifies one AMF (TS 23.003 §2.10.1) and only an AMF Set
    /// shares it, so an AMF may not register, or patch in, a GUAMI that an AMF
    /// of another AMF Set (or naming none) already lists: 403, nothing stored.
    /// An AMF of the same set may list it, an AMF of another set may name it in
    /// `backupInfoAmfFailure`, and a heartbeat patch of a held profile passes.
    ///
    /// REVERT-VERIFIED: with `refuse_guami_of_another_set` returning `None`, the
    /// other set's registration is 201; with the patch's added GUAMIs left
    /// empty, the patch adding the GUAMI is 200.
    #[tokio::test]
    async fn a_guami_is_listed_only_within_one_amf_set_2035() {
        let a = "20350a0a-0000-4000-8000-00000000000a";
        let b = "20350b0b-0000-4000-8000-00000000000b";
        let c = "20350c0c-0000-4000-8000-00000000000c";
        let d = "20350d0d-0000-4000-8000-00000000000d";
        let e = "20350e0e-0000-4000-8000-00000000000e";
        let g = "2035a1";
        let resp = put_amf(a, Some("001"), &[g], &[]).await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        // Another set: refused, nothing stored.
        let resp = put_amf(b, Some("002"), &[g, "2035b1"], &[]).await;
        assert_eq!(resp.status, 403, "{:?}", resp.http.content);
        assert!(nf_manager().get(b).is_none());
        // No set named: refused too.
        let resp = put_amf(e, None, &[g], &[]).await;
        assert_eq!(resp.status, 403, "{:?}", resp.http.content);
        // The same set (case aside): admitted.
        let resp = put_amf(c, Some("001"), &[&g.to_ascii_uppercase()], &[]).await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        // Another set backing it up: admitted.
        let resp = put_amf(d, Some("002"), &["2035d1"], &[g]).await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        // ...but not patching it into its own guamiList.
        let resp = patch(
            d,
            json!([{ "op": "add", "path": "/amfInfo/guamiList/-", "value": guami(g) }]),
        )
        .await;
        assert_eq!(resp.status, 403, "{:?}", resp.http.content);
        assert_eq!(listed(d), vec!["2035d1".to_string()]);
        // A heartbeat of a held profile passes.
        let resp = patch(
            a,
            json!([{ "op": "replace", "path": "/nfStatus", "value": "REGISTERED" }]),
        )
        .await;
        assert!(matches!(resp.status, 200 | 204), "{:?}", resp.http.content);
        for id in [a, c, d] {
            let _ = nf_manager().deregister(id);
        }
    }
}

#[cfg(test)]
mod tests_nf_set_ids_1719 {
    use super::*;
    use serde_json::json;

    tokio::task_local! {
        /// The allowlist the handlers see inside `ALLOWLIST.scope(..)`, in place of
        /// the process policy. Task-local, so the other tests in this binary keep
        /// the default (no allowlist).
        pub(super) static ALLOWLIST: Option<Vec<NfSetAllowYaml>>;
    }

    const SET1: &str = "set1.pcfset.5gc.mnc001.mcc001";
    const SET2: &str = "set2.pcfset.5gc.mnc001.mcc001";

    fn allowlist(own: &str) -> Option<Vec<NfSetAllowYaml>> {
        Some(vec![
            NfSetAllowYaml {
                nf_set_id: SET1.to_string(),
                nf_types: Some(vec!["PCF".to_string()]),
                nf_instance_ids: Some(vec![own.to_ascii_uppercase()]),
            },
            // Any PCF may claim set 2.
            NfSetAllowYaml {
                nf_set_id: SET2.to_string(),
                nf_types: Some(vec!["PCF".to_string()]),
                nf_instance_ids: None,
            },
        ])
    }

    async fn put(id: &str, nf_type: &str, sets: &[&str]) -> SbiResponse {
        let body = json!({
            "nfInstanceId": id,
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "ipv4Addresses": ["10.17.19.1"],
            "nfSetIdList": sets,
        });
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"))
            .with_body(body.to_string(), "application/json");
        // #1617 step f: NF management needs a verified certificate identity, so
        // each request carries one naming its own instance, and (#1917) the NF
        // type it registers as. The allowlist check runs after both.
        req.peer_cert_nf_instance_id = Some(id.to_string());
        req.peer_cert_nf_types = test_certificate_nf_type(&req, id).into_iter().collect();
        handle_nf_register(id, &req).await
    }

    async fn patch(id: &str, ops: serde_json::Value) -> SbiResponse {
        patch_as(id, ops, &[]).await
    }

    /// A patch from a certificate naming the stored type and `more` (#1917: a
    /// re-typing patch needs a certificate that names the new type too).
    async fn patch_as(id: &str, ops: serde_json::Value, more: &[&str]) -> SbiResponse {
        let mut req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{id}"))
            .with_body(ops.to_string(), "application/json-patch+json");
        req.peer_cert_nf_instance_id = Some(id.to_string());
        req.peer_cert_nf_types = test_certificate_nf_type(&req, id).into_iter().collect();
        req.peer_cert_nf_types
            .extend(more.iter().map(|t| t.to_string()));
        handle_nf_update(id, &req).await
    }

    fn stored_sets(id: &str) -> Option<Vec<String>> {
        nf_manager().get(id).map(|p| {
            nf_set_ids_of(&p.to_json())
                .into_iter()
                .map(String::from)
                .collect()
        })
    }

    /// With an allowlist, NFRegister and NFUpdate admit only the NF Sets the
    /// registrant is provisioned for, matched case-insensitively (TS 23.003
    /// §28.12). A refused request is 403 and stores nothing: a rogue PCF that
    /// claims another PCF's set is not registered, an NF of another type is not
    /// either, and a patch that adds a set leaves the stored profile as it was.
    /// A heartbeat patch of an allowed profile still succeeds, and a retried
    /// NFRegister stores one record.
    ///
    /// REVERT-VERIFIED: with `refuse_unallowed_nf_sets` returning `None`, the
    /// rogue registration is 201 and the first refusal assertion fails.
    #[tokio::test]
    async fn only_provisioned_nf_sets_are_registered_1719() {
        let own = "17190a0a-0000-4000-8000-00000000000a";
        let rogue = "17190b0b-0000-4000-8000-00000000000b";
        let smf = "17190c0c-0000-4000-8000-00000000000c";
        ALLOWLIST
            .scope(allowlist(own), async {
                // #1617 step f runs first: with no verified identity the claim
                // is refused 400 INVALID_CLIENT before the allowlist is consulted.
                let bare = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{rogue}")).with_body(
                    json!({"nfInstanceId": rogue, "nfType": "PCF",
                               "nfStatus": "REGISTERED", "nfSetIdList": [SET1]})
                    .to_string(),
                    "application/json",
                );
                let resp = handle_nf_register(rogue, &bare).await;
                assert_eq!(
                    resp.status, 400,
                    "identity before the allowlist: {:?}",
                    resp.http.content
                );
                assert!(stored_sets(rogue).is_none());

                // A PCF of no allowed set: refused, nothing stored.
                let resp = put(rogue, "PCF", &[SET1]).await;
                assert_eq!(resp.status, 403, "{:?}", resp.http.content);
                assert!(stored_sets(rogue).is_none(), "nothing stored for {rogue}");
                // Another type claiming the set: refused.
                let resp = put(smf, "SMF", &[SET2]).await;
                assert_eq!(resp.status, 403, "{:?}", resp.http.content);
                assert!(stored_sets(smf).is_none());

                // The provisioned PCF, spelling the set in upper case: admitted.
                let upper = SET1.to_ascii_uppercase();
                let resp = put(own, "PCF", &[&upper]).await;
                assert_eq!(resp.status, 201, "{:?}", resp.http.content);
                // A retry is one record (200, a replacement).
                let resp = put(own, "PCF", &[&upper]).await;
                assert_eq!(resp.status, 200, "{:?}", resp.http.content);
                assert_eq!(stored_sets(own), Some(vec![upper.clone()]));

                // Any PCF may claim set 2.
                let resp = put(rogue, "PCF", &[SET2]).await;
                assert_eq!(resp.status, 201, "{:?}", resp.http.content);

                // NFUpdate adding set 1 to the rogue: refused, profile unchanged.
                let resp = patch(
                    rogue,
                    json!([{"op": "add", "path": "/nfSetIdList/-", "value": SET1}]),
                )
                .await;
                assert_eq!(resp.status, 403, "{:?}", resp.http.content);
                assert_eq!(stored_sets(rogue), Some(vec![SET2.to_string()]));

                // R19: NFUpdate re-typing the rogue to SMF while it keeps set 2,
                // which only PCFs may claim: refused, type and sets unchanged. Its
                // certificate names SMF too, so the set check is what refuses it.
                let resp = patch_as(
                    rogue,
                    json!([{"op": "replace", "path": "/nfType", "value": "SMF"}]),
                    &["SMF"],
                )
                .await;
                assert_eq!(
                    resp.status, 403,
                    "a re-typing patch re-checks every held set: {:?}",
                    resp.http.content
                );
                assert_eq!(
                    nf_manager().get(rogue).map(|p| p.nf_type).as_deref(),
                    Some("PCF")
                );
                assert_eq!(stored_sets(rogue), Some(vec![SET2.to_string()]));

                // A heartbeat patch keeps working.
                let resp = patch(
                    own,
                    json!([{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}]),
                )
                .await;
                assert!(
                    resp.status == 200 || resp.status == 204,
                    "{} {:?}",
                    resp.status,
                    resp.http.content
                );
            })
            .await;
        for id in [own, rogue, smf] {
            let _ = nf_manager().deregister(id);
        }
    }

    /// R19: a profile restored from the state file is held to the allowlist at
    /// startup. Its unallowed sets are stripped and stored, so `target-nf-set-id`
    /// discovery no longer returns it for them. An allowed set is kept, a profile
    /// left with no set loses `nfSetIdList`, an allowed profile is untouched, and
    /// each changed profile comes back with change items for NF_PROFILE_CHANGED.
    ///
    /// REVERT-VERIFIED: with the strip skipped (every profile `continue`s), the
    /// rogue is still discovered in set 1 and the first assertion fails.
    #[test]
    fn a_restored_profile_loses_the_sets_it_may_not_claim_1719() {
        let own = "17190e0e-0000-4000-8000-00000000000e";
        let mixed = "17190f0f-0000-4000-8000-00000000000f";
        let only = "17191010-0000-4000-8000-000000000010";
        let restore = |id: &str, sets: &[&str]| {
            let p = NfProfile::from_json(&json!({
                "nfInstanceId": id,
                "nfType": "PCF",
                "nfStatus": "REGISTERED",
                "nfSetIdList": sets,
            }))
            .expect("a valid profile");
            nf_manager().register(p).expect("stored");
        };
        restore(own, &[SET1]);
        restore(mixed, &[SET1, SET2]);
        restore(only, &[SET1]);
        let policy = NrfPolicy {
            nf_set_allowlist: allowlist(own),
            ..NrfPolicy::default()
        };
        let ours: Vec<NfProfile> = [own, mixed, only]
            .iter()
            .filter_map(|id| nf_manager().get(id))
            .collect();
        let changed = strip_unallowed_restored_nf_sets(&policy, ours);

        let discovered = |set: &str| -> Vec<String> {
            discover_profiles(&DiscoveryQuery {
                target_nf_type: "PCF".to_string(),
                requester_nf_type: "SMF".to_string(),
                target_nf_set_id: Some(set.to_string()),
                ..Default::default()
            })
            .iter()
            .filter_map(|p| p.get("nfInstanceId").and_then(|v| v.as_str()))
            .filter(|id| [own, mixed, only].contains(id))
            .map(String::from)
            .collect()
        };
        assert_eq!(
            discovered(SET1),
            vec![own.to_string()],
            "only the provisioned PCF is in set 1"
        );
        assert_eq!(
            discovered(SET2),
            vec![mixed.to_string()],
            "the allowed set is kept"
        );
        assert_eq!(stored_sets(mixed), Some(vec![SET2.to_string()]));
        assert_eq!(stored_sets(only), Some(Vec::new()));
        assert!(nf_manager()
            .get(only)
            .is_some_and(|p| p.to_json().get("nfSetIdList").is_none()));
        assert_eq!(
            stored_sets(own),
            Some(vec![SET1.to_string()]),
            "the allowed one is untouched"
        );
        let mut ids: Vec<&str> = changed
            .iter()
            .map(|(p, _)| p.nf_instance_id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![mixed, only]);
        assert!(
            changed.iter().all(|(_, c)| !c.is_empty()),
            "each change is notified"
        );
        for id in [own, mixed, only] {
            let _ = nf_manager().deregister(id);
        }
    }

    /// **#1822 item 4.** The restore-time enforcement `main` runs strips the
    /// disallowed set and tells a subscriber to the profile NF_PROFILE_CHANGED over
    /// the wire, naming `nfSetIdList`; a profile it leaves alone notifies nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_enforcement_notifies_the_stripped_profile_1822() {
        use std::sync::Mutex as StdMutex;
        let own = "18220a0a-0000-4000-8000-00000000000a";
        let mixed = "18220b0b-0000-4000-8000-00000000000b";
        let received: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let subscriber = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        subscriber
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(body) = req.http.content.clone() {
                        sink.lock().expect("sink lock").push(body);
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("subscriber server starts");
        for (id, sets) in [(own, vec![SET1]), (mixed, vec![SET1, SET2])] {
            let p = NfProfile::from_json(&json!({
                "nfInstanceId": id,
                "nfType": "PCF",
                "nfStatus": "REGISTERED",
                "nfSetIdList": sets,
            }))
            .expect("a valid profile");
            nf_manager().register(p).expect("stored");
            nf_manager().add_subscription(nextgcore_nrfd::SubscriptionData {
                id: format!("nrfd1822-{id}"),
                req_nf_type: None,
                req_nf_instance_id: None,
                notification_uri: format!("http://127.0.0.1:{}/callback", addr.port()),
                subscr_cond: Some(nextgcore_nrfd::nnrf_handler::SubscrCond::nf_instance_id(id)),
                validity_duration: 3600,
                req_notif_events: None,
                notif_condition: None,
                owner: None,
            });
        }
        let policy = NrfPolicy {
            nf_set_allowlist: allowlist(own),
            ..NrfPolicy::default()
        };
        let restored: Vec<NfProfile> = [own, mixed]
            .iter()
            .filter_map(|id| nf_manager().get(id))
            .collect();
        enforce_nf_set_allowlist_at_restore(&policy, restored);

        for _ in 0..100 {
            if !received.lock().expect("sink lock").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Long enough for a second, wrong, notification to arrive too.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let got = received.lock().expect("sink lock").clone();
        assert_eq!(
            got.len(),
            1,
            "one notification, for the stripped PCF: {got:?}"
        );
        let body: serde_json::Value = serde_json::from_str(&got[0]).expect("JSON");
        assert_eq!(body["event"], "NF_PROFILE_CHANGED");
        assert!(
            body["nfInstanceUri"]
                .as_str()
                .is_some_and(|u| u.ends_with(&format!("/nf-instances/{mixed}"))),
            "{body}"
        );
        assert!(
            body["profileChanges"]
                .as_array()
                .is_some_and(|c| c.iter().any(|i| i["path"] == "/nfSetIdList")),
            "the change names nfSetIdList: {body}"
        );
        assert_eq!(stored_sets(mixed), Some(vec![SET2.to_string()]));
        for id in [own, mixed] {
            nf_manager().remove_subscription(&format!("nrfd1822-{id}"));
            let _ = nf_manager().deregister(id);
        }
    }

    /// **#1822 item 4.** `main` runs the restore-time enforcement on every restored
    /// profile, before it publishes the policy. A source guard, because `main`
    /// itself cannot run in a unit test.
    #[test]
    fn main_enforces_the_allowlist_on_restored_profiles_1822() {
        let source = include_str!("main.rs");
        let main = &source[source.find("async fn main()").expect("main")..];
        let main = &main[..main.find("\n}\n").expect("its end")];
        let call = main
            .find("\n    enforce_nf_set_allowlist_at_restore(&policy, nf_manager().list());\n")
            .expect("main enforces the allowlist on every restored profile");
        let publish = main
            .find("\n    NRF_POLICY.set(policy).ok();\n")
            .expect("main publishes the policy");
        assert!(
            call < publish,
            "the enforcement runs before the policy is published"
        );
    }

    /// Without an allowlist (the default), a registrant's sets are accepted as
    /// sent, so existing deployments keep working; startup warns.
    #[tokio::test]
    async fn without_an_allowlist_sets_are_accepted_as_registered_1719() {
        let id = "17190d0d-0000-4000-8000-00000000000d";
        let resp = ALLOWLIST.scope(None, put(id, "PCF", &[SET1])).await;
        assert_eq!(resp.status, 201, "{:?}", resp.http.content);
        assert_eq!(stored_sets(id), Some(vec![SET1.to_string()]));
        let _ = nf_manager().deregister(id);
    }

    /// The allowlist is parsed from `nrf.nf_set_allowlist`, absent means none.
    #[test]
    fn the_allowlist_comes_from_the_config_1719() {
        let yaml: NrfYaml = serde_yaml::from_str(
            "nrf:\n  nf_set_allowlist:\n    - nf_set_id: set1.pcfset.5gc.mnc001.mcc001\n      \
             nf_types: [PCF]\n",
        )
        .expect("parses");
        let policy = NrfPolicy::from_yaml(&yaml);
        let allow = policy.nf_set_allowlist.as_ref().expect("configured");
        assert_eq!(allow.len(), 1);
        assert!(policy
            .unallowed_nf_sets(["SET1.pcfset.5gc.mnc001.mcc001"], "pcf", "any")
            .is_empty());
        assert_eq!(
            policy.unallowed_nf_sets([SET2], "PCF", "any"),
            vec![SET2],
            "a set not listed is refused"
        );
        let none: NrfYaml = serde_yaml::from_str("nrf: {}\n").expect("parses");
        assert!(NrfPolicy::from_yaml(&none).nf_set_allowlist.is_none());
    }
}

/// #1617 step f: the NRF refuses NFRegister / NFUpdate / NFDeregister from a
/// caller with no verified certificate identity, plaintext included (operator
/// decision; TS 33.310 §6.1.3c.3, TS 33.501 §13.1.0), with `400 INVALID_CLIENT`
/// (TS 29.510 Table 6.1.7.3-1), and a refused request applies nothing.
#[cfg(test)]
mod unverified_registrant_tests_1617 {
    use super::*;
    use serde_json::json;

    fn assert_refused(r: &SbiResponse, what: &str) {
        assert_eq!(r.status, 400, "{what}: {:?}", r.http.content);
        let body = r.http.content.as_deref().unwrap_or_default();
        let problem: serde_json::Value = serde_json::from_str(body).expect("ProblemDetails");
        assert_eq!(problem["cause"], "INVALID_CLIENT", "{what}: {body}");
        assert!(
            body.contains("no verified client certificate identity"),
            "{what}: {body}"
        );
    }

    fn put_req(id: &str, nf_type: &str) -> SbiRequest {
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"));
        req.http.set_content(
            json!({"nfInstanceId": id, "nfType": nf_type, "nfStatus": "REGISTERED"}).to_string(),
        );
        req
    }

    fn patch_req(id: &str) -> SbiRequest {
        SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{id}")).with_body(
            json!([{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]).to_string(),
            "application/json-patch+json",
        )
    }

    fn stored(id: &str, nf_type: &str) {
        nf_manager()
            .register(
                NfProfile::from_json(
                    &json!({"nfInstanceId": id, "nfType": nf_type, "nfStatus": "REGISTERED"}),
                )
                .expect("profile"),
            )
            .expect("stored");
    }

    /// No knob: the shipped policy enforces, and the YAML/env loader has no key
    /// that turns it off.
    ///
    /// REVERT-VERIFIED: with the default flipped back to false this fails.
    #[test]
    fn the_nrf_requires_a_registrant_certificate_by_default_1617() {
        assert!(NrfPolicy::default().require_registrant_identity);
        assert!(nrf_policy().require_registrant_identity);
    }

    /// Over a real plaintext h2c listener (the dev SBI profile's transport): no
    /// certificate can be presented, so every NF-management operation is refused
    /// and counted; nothing is created, patched or removed. Discovery still
    /// answers (it keeps today's auth).
    ///
    /// REVERT-VERIFIED: with `require_registrant_identity: false` the PUT is
    /// 201 and the `NFRegister` assertion names it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_plaintext_caller_manages_no_nf_instance_1617() {
        let id = "1617f000-0000-4000-8000-0000000000f1";
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        server.start(nrf_sbi_request_handler).await.expect("starts");
        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let run = async {
            let before = nextgcore_nrfd::metrics::unverified_nf_management_total();
            let r = client
                .put_json(
                    &format!("/nnrf-nfm/v1/nf-instances/{id}"),
                    &json!({"nfInstanceId": id, "nfType": "CUSTOM_T1617F",
                            "nfStatus": "REGISTERED", "heartBeatTimer": 10}),
                )
                .await
                .expect("PUT completes");
            assert_refused(&r, "NFRegister");
            assert!(nf_manager().get(id).is_none(), "nothing registered");
            assert!(
                !HEARTBEAT_TIMERS.lock().expect("timers").contains_key(id),
                "no supervision timer armed"
            );
            let after_put = nextgcore_nrfd::metrics::unverified_nf_management_total();
            assert!(after_put > before, "NFRegister counted");

            stored(id, "CUSTOM_T1617F");
            let r = client.send_request(patch_req(id)).await.expect("PATCH");
            assert_refused(&r, "NFUpdate");
            assert_eq!(
                nf_manager().get(id).map(|p| p.nf_status).as_deref(),
                Some("REGISTERED"),
                "not patched"
            );
            let r = client
                .delete(&format!("/nnrf-nfm/v1/nf-instances/{id}"))
                .await
                .expect("DELETE completes");
            assert_refused(&r, "NFDeregister");
            assert!(nf_manager().get(id).is_some(), "not removed");

            let r = client
                .get(
                    "/nnrf-disc/v1/nf-instances?target-nf-type=CUSTOM_T1617F&requester-nf-type=SMF",
                )
                .await
                .expect("discovery completes");
            assert_eq!(r.status, 200, "discovery keeps today's auth");
        };
        let outcome = tokio::time::timeout(Duration::from_secs(30), run).await;
        nf_manager().deregister(id).ok();
        server.stop().await.ok();
        outcome.expect("bounded");
    }

    /// A caller naming the NRF's own nfInstanceId (#1617 step f bullet): with no
    /// certificate it is refused like any other unverified caller, and with
    /// another NF's verified certificate `bind_instance` refuses it. The NRF's
    /// own entry is untouched either way. Only `nrf.crt` binds the NRF's ID.
    ///
    /// REVERT-VERIFIED: with `bind_instance` ignored in `handle_nf_register`,
    /// the AMF certificate's PUT replaces the NRF's entry (200) and this fails.
    #[tokio::test]
    async fn a_foreign_caller_cannot_manage_the_nrf_s_own_entry_1617() {
        let _self_entry = self_entry_test_lock().lock().await;
        register_self_with_own_registry();
        let nrf = nrf_instance_id();
        let amf = "1617f000-0000-4000-8000-0000000000a5";
        let before = nf_manager().get(nrf).expect("self entry");

        let r = handle_nf_register(nrf, &put_req(nrf, "AMF")).await;
        assert_refused(&r, "anonymous NFRegister");
        let r = handle_nf_update(nrf, &patch_req(nrf)).await;
        assert_refused(&r, "anonymous NFUpdate");
        let r = handle_nf_deregister(
            nrf,
            &SbiRequest::delete(format!("/nnrf-nfm/v1/nf-instances/{nrf}")),
        )
        .await;
        assert_refused(&r, "anonymous NFDeregister");

        let as_amf = |mut req: SbiRequest| {
            req.peer_cert_nf_instance_id = Some(amf.into());
            req.peer_cert_nf_types = vec!["AMF".into()];
            req
        };
        for r in [
            handle_nf_register(nrf, &as_amf(put_req(nrf, "AMF"))).await,
            handle_nf_update(nrf, &as_amf(patch_req(nrf))).await,
            handle_nf_deregister(
                nrf,
                &as_amf(SbiRequest::delete(format!(
                    "/nnrf-nfm/v1/nf-instances/{nrf}"
                ))),
            )
            .await,
        ] {
            assert_eq!(r.status, 400, "{:?}", r.http.content);
            let body = r.http.content.as_deref().unwrap_or_default();
            assert!(body.contains("INVALID_CLIENT"), "{body}");
            assert!(body.contains("does not match"), "{body}");
        }
        let after = nf_manager().get(nrf).expect("the NRF's entry is kept");
        assert_eq!(after.nf_type, before.nf_type);
        assert_eq!(after.nf_status, "REGISTERED");
    }

    /// A state file restored the NRF's own entry from a run that registered
    /// itself; this run does not (`registers_itself` false), so startup removes
    /// it, once.
    ///
    /// REVERT-VERIFIED: with `drop_restored_self_entry` returning before the
    /// deregister, the entry stays and the second assertion names it.
    #[tokio::test]
    async fn a_restored_self_entry_is_dropped_when_the_nrf_does_not_register_itself_1617() {
        let _self_entry = self_entry_test_lock().lock().await;
        register_self_with_own_registry();
        assert!(drop_restored_self_entry(), "the restored entry is removed");
        assert!(
            nf_manager().get(nrf_instance_id()).is_none(),
            "the NRF's own entry is gone"
        );
        assert!(!drop_restored_self_entry(), "nothing left to remove");
    }

    /// **#1821, TS 29.510 §5.2.2.6.1.** Dropping the restored self entry tells a
    /// subscriber to that entry NF_DEREGISTERED, over the wire, exactly once: the
    /// second call finds nothing and sends nothing. Before, the entry vanished
    /// with no notification.
    ///
    /// The subscription names the NRF's own instance, and every test that adds or
    /// removes that entry holds `self_entry_test_lock`, so no other test's change
    /// reaches this sink.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_restored_self_entry_notifies_nf_deregistered_1821() {
        use std::sync::Mutex as StdMutex;
        let _self_entry = self_entry_test_lock().lock().await;

        let received: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let subscriber = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), listener);
        subscriber
            .start(move |req: SbiRequest| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(body) = req.http.content.clone() {
                        sink.lock().expect("sink lock").push(body);
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("subscriber server starts");

        register_self_with_own_registry();
        let manager = nf_manager();
        let sub_id = "nrfd1821-self-entry-sub";
        manager.add_subscription(nextgcore_nrfd::SubscriptionData {
            id: sub_id.to_string(),
            req_nf_type: None,
            req_nf_instance_id: None,
            notification_uri: format!("http://127.0.0.1:{}/callback", addr.port()),
            subscr_cond: Some(nextgcore_nrfd::nnrf_handler::SubscrCond::nf_instance_id(
                nrf_instance_id(),
            )),
            validity_duration: 3600,
            req_notif_events: None,
            notif_condition: None,
            owner: None,
        });

        let wait_for = |want: usize| {
            let received = Arc::clone(&received);
            async move {
                for _ in 0..100 {
                    if received.lock().expect("sink lock").len() >= want {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                received.lock().expect("sink lock").clone()
            }
        };

        assert!(drop_restored_self_entry(), "the restored entry is removed");
        let got = wait_for(1).await;
        assert_eq!(got.len(), 1, "one notification, got {got:?}");
        let body: serde_json::Value = serde_json::from_str(&got[0]).expect("JSON");
        assert_eq!(body["event"], "NF_DEREGISTERED");
        assert!(
            body["nfInstanceUri"]
                .as_str()
                .is_some_and(|u| u.ends_with(&format!("/nf-instances/{}", nrf_instance_id()))),
            "it names the NRF's own instance: {body}"
        );

        assert!(!drop_restored_self_entry(), "nothing left to remove");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            received.lock().expect("sink lock").len(),
            1,
            "a second call finds nothing and sends nothing"
        );
        manager.remove_subscription(sub_id);
    }

    /// **#1821.** `main` drops the restored self entry exactly when the NRF does
    /// not register itself: the `else` of the self-registration choice. A source
    /// guard, because `main` itself cannot run in a unit test.
    #[test]
    fn main_drops_the_restored_self_entry_when_it_does_not_register_itself_1821() {
        let source = include_str!("main.rs");
        let main = &source[source.find("async fn main()").expect("main")..];
        let main = &main[..main.find("\n}\n").expect("its end")];
        let choice = "    } else if self_registers {\n";
        let at = main.find(choice).expect("the self-registration choice");
        let branch = &main[at + choice.len()..];
        let branch = &branch[..branch.find("\n    }\n").expect("its end")];
        assert!(
            branch.trim_end().ends_with(
                "register_self_with_own_registry();\n    } else {\n        drop_restored_self_entry();"
            ),
            "the else branch drops the restored entry: {branch}"
        );
    }
}

/// #1809: a subscription is managed only by the consumer that created it.
/// Every request goes through `nrf_sbi_request_handler`, so the routing that
/// hands the caller to the handler is covered as well as the check itself.
#[cfg(test)]
mod subscription_owner_tests_1809 {
    use super::*;
    use serde_json::json;

    tokio::task_local! {
        /// Overrides [`NrfPolicy::require_subscriber_identity`] for one test's
        /// task, so the dev behaviour is testable without touching the
        /// process-global policy the rest of the binary reads.
        pub(super) static REQUIRED: bool;
    }

    const OWNER: &str = "18090000-0000-4000-8000-00000000000a";
    const OTHER: &str = "18090000-0000-4000-8000-00000000000b";

    fn as_caller(mut req: SbiRequest, cert: Option<&str>, token_sub: Option<&str>) -> SbiRequest {
        req.peer_cert_nf_instance_id = cert.map(str::to_string);
        req.oauth2_subject = token_sub.map(str::to_string);
        req
    }

    /// Subscribe as `cert`/`token_sub` and return the new subscription's id.
    /// https (#1869): an http callback is refused under the production
    /// profile, which an unset environment resolves to.
    async fn subscribe_as(cert: Option<&str>, token_sub: Option<&str>) -> String {
        let req = SbiRequest::post("/nnrf-nfm/v1/subscriptions").with_body(
            json!({
                "nfStatusNotificationUri": "https://consumer.invalid/notify",
                "reqNfInstanceId": OWNER,
            })
            .to_string(),
            "application/json",
        );
        let resp = nrf_sbi_request_handler(as_caller(req, cert, token_sub)).await;
        assert_eq!(resp.status, 201, "subscribe: {:?}", resp.http.content);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("JSON");
        body["subscriptionId"].as_str().expect("id").to_string()
    }

    fn patch(id: &str, cert: Option<&str>, token_sub: Option<&str>) -> SbiRequest {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req = SbiRequest::patch(format!("/nnrf-nfm/v1/subscriptions/{id}")).with_body(
            json!({ "validityTime": epoch_to_rfc3339(now + 600) }).to_string(),
            "application/json",
        );
        as_caller(req, cert, token_sub)
    }

    fn delete(id: &str, cert: Option<&str>, token_sub: Option<&str>) -> SbiRequest {
        as_caller(
            SbiRequest::delete(format!("/nnrf-nfm/v1/subscriptions/{id}")),
            cert,
            token_sub,
        )
    }

    fn assert_forbidden(r: &SbiResponse, what: &str) {
        assert_eq!(r.status, 403, "{what}: {:?}", r.http.content);
        let body = r.http.content.as_deref().unwrap_or_default();
        assert!(
            body.contains("was not created by the requester"),
            "{what}: {body}"
        );
    }

    #[tokio::test]
    async fn subscribe_binds_the_verified_identity() {
        let id = subscribe_as(Some(OWNER), Some(OWNER)).await;
        let stored = nf_manager().find_subscription(&id).expect("stored");
        assert_eq!(
            stored.owner.as_deref(),
            Some(OWNER),
            "certificate and token agree"
        );
        nf_manager().remove_subscription(&id);

        let id = subscribe_as(Some(OWNER), None).await;
        let stored = nf_manager().find_subscription(&id).expect("stored");
        assert_eq!(
            stored.owner.as_deref(),
            Some(OWNER),
            "the certificate alone"
        );
        nf_manager().remove_subscription(&id);

        let id = subscribe_as(None, Some(OTHER)).await;
        let stored = nf_manager().find_subscription(&id).expect("stored");
        assert_eq!(
            stored.owner.as_deref(),
            Some(OTHER),
            "else the token subject"
        );
        nf_manager().remove_subscription(&id);
    }

    #[tokio::test]
    async fn another_consumer_cannot_extend_a_subscription() {
        let id = subscribe_as(Some(OWNER), None).await;
        let before = nf_manager()
            .find_subscription(&id)
            .unwrap()
            .validity_duration;

        for (cert, sub, what) in [
            (Some(OTHER), None, "another certificate"),
            (None, Some(OTHER), "another token subject"),
            (
                Some(OWNER),
                Some(OTHER),
                "the owner's certificate with a foreign token",
            ),
            (None, None, "an anonymous caller"),
        ] {
            let r = nrf_sbi_request_handler(patch(&id, cert, sub)).await;
            assert_forbidden(&r, what);
            assert_eq!(
                nf_manager()
                    .find_subscription(&id)
                    .unwrap()
                    .validity_duration,
                before,
                "{what}: a refused PATCH must leave the validity untouched"
            );
        }

        let r = nrf_sbi_request_handler(patch(&id, Some(OWNER), None)).await;
        assert_eq!(r.status, 200, "the owner extends: {:?}", r.http.content);
        assert!(
            (595..=600).contains(
                &nf_manager()
                    .find_subscription(&id)
                    .unwrap()
                    .validity_duration
            ),
            "the owner's PATCH is applied"
        );
        nf_manager().remove_subscription(&id);
    }

    #[tokio::test]
    async fn another_consumer_cannot_cancel_a_subscription() {
        let id = subscribe_as(Some(OWNER), None).await;

        for (cert, sub, what) in [
            (Some(OTHER), None, "another certificate"),
            (None, Some(OTHER), "another token subject"),
            (None, None, "an anonymous caller"),
        ] {
            let r = nrf_sbi_request_handler(delete(&id, cert, sub)).await;
            assert_forbidden(&r, what);
            assert!(
                nf_manager().find_subscription(&id).is_some(),
                "{what}: a refused DELETE must leave the subscription in place"
            );
        }

        // The UUID compares case-insensitively, as the registry keys it.
        let upper = OWNER.to_ascii_uppercase();
        // The owner's certificate with a foreign token is not the owner either.
        let r = nrf_sbi_request_handler(delete(&id, Some(OWNER), Some(OTHER))).await;
        assert_forbidden(&r, "the owner's certificate with a foreign token");
        assert!(nf_manager().find_subscription(&id).is_some());

        let r = nrf_sbi_request_handler(delete(&id, None, Some(&upper))).await;
        assert_eq!(r.status, 204, "the owner cancels: {:?}", r.http.content);
        assert!(nf_manager().find_subscription(&id).is_none());
    }

    /// Under `dev` a subscription created without any verified identity (a
    /// plaintext stack) has nothing to bind to and stays manageable.
    #[tokio::test]
    async fn under_dev_an_unbound_subscription_stays_manageable() {
        REQUIRED
            .scope(false, async {
                let id = subscribe_as(None, None).await;
                assert_eq!(nf_manager().find_subscription(&id).unwrap().owner, None);
                let r = nrf_sbi_request_handler(patch(&id, None, None)).await;
                assert_eq!(r.status, 200, "{:?}", r.http.content);
                let r = nrf_sbi_request_handler(delete(&id, None, None)).await;
                assert_eq!(r.status, 204, "{:?}", r.http.content);
            })
            .await;
    }

    fn assert_invalid_client(r: &SbiResponse, needle: &str, what: &str) {
        assert_eq!(r.status, 400, "{what}: {:?}", r.http.content);
        let body = r.http.content.as_deref().unwrap_or_default();
        let problem: serde_json::Value = serde_json::from_str(body).expect("ProblemDetails");
        assert_eq!(problem["cause"], "INVALID_CLIENT", "{what}: {body}");
        assert!(body.contains(needle), "{what}: {body}");
    }

    fn subscribe_req(cert: Option<&str>, token_sub: Option<&str>, uri: &str) -> SbiRequest {
        as_caller(
            SbiRequest::post("/nnrf-nfm/v1/subscriptions").with_body(
                json!({ "nfStatusNotificationUri": uri }).to_string(),
                "application/json",
            ),
            cert,
            token_sub,
        )
    }

    /// No stored subscription carries `uri`.
    fn nothing_stored_for(uri: &str) -> bool {
        let m = nf_manager();
        !m.subscription_ids().iter().any(|id| {
            m.find_subscription(id)
                .is_some_and(|s| s.notification_uri == uri)
        })
    }

    /// Under production (the policy default) a Subscribe with no verified
    /// identity is refused as #1617 refuses cert-less NF management, and
    /// nothing is stored.
    ///
    /// REVERT-VERIFIED: with `subscription_owner` returning `Ok(None)` for a
    /// caller with no identity whatever `required` says, the Subscribe is 201.
    #[tokio::test]
    async fn under_production_an_anonymous_subscribe_is_refused() {
        assert!(NrfPolicy::default().require_subscriber_identity);
        let uri = "https://anonymous-1809.invalid/notify";
        let r = nrf_sbi_request_handler(subscribe_req(None, None, uri)).await;
        assert_invalid_client(&r, "no verified identity", "anonymous");
        assert!(
            nothing_stored_for(uri),
            "a refused Subscribe stores nothing"
        );
    }

    /// One identity rule on create and on manage: a caller whose certificate
    /// and token name different NFs cannot subscribe, so no creator is ever
    /// locked out of its own subscription.
    ///
    /// REVERT-VERIFIED: with the disagreement check removed from
    /// `subscription_owner`, the mixed caller gets 201.
    #[tokio::test]
    async fn a_caller_whose_identities_disagree_cannot_subscribe() {
        let uri = "https://mixed-1809.invalid/notify";
        let r = nrf_sbi_request_handler(subscribe_req(Some(OWNER), Some(OTHER), uri)).await;
        assert_invalid_client(&r, "does not match its other verified identity", "mixed");
        assert!(
            nothing_stored_for(uri),
            "a refused Subscribe stores nothing"
        );
    }

    /// R26 on #1831: a restart re-arms an ownerless subscription for at most
    /// 24 h, whatever validity an old PATCH stored, and leaves an owned one as
    /// stored; and a PATCH is capped at 24 h like a Subscribe.
    ///
    /// REVERT-VERIFIED: with `restored_validity` returning the stored value,
    /// the ownerless subscription keeps its 10 days and the first assertion
    /// fails; with the PATCH cap removed, the PATCH stores 10 days.
    #[tokio::test]
    async fn validity_is_capped_at_24_hours_for_restored_ownerless_and_patched_1809() {
        const TEN_DAYS: u64 = 10 * 86400;
        let sub = |id: &str, owner: Option<&str>| nextgcore_nrfd::SubscriptionData {
            id: id.to_string(),
            req_nf_type: None,
            req_nf_instance_id: None,
            notification_uri: format!("http://{id}.invalid/notify"),
            subscr_cond: None,
            validity_duration: TEN_DAYS,
            req_notif_events: None,
            notif_condition: None,
            owner: owner.map(str::to_string),
        };
        let m = nf_manager();
        m.add_subscription(sub("cap-ownerless-1809", None));
        m.add_subscription(sub("cap-owned-1809", Some(OWNER)));
        rearm_restored_timers();
        assert_eq!(
            m.find_subscription("cap-ownerless-1809")
                .unwrap()
                .validity_duration,
            NRF_SUBSCRIPTION_DEFAULT_VALIDITY,
            "an ownerless subscription lapses within 24 h of the restart"
        );
        assert_eq!(
            m.find_subscription("cap-owned-1809")
                .unwrap()
                .validity_duration,
            TEN_DAYS,
            "an owned one keeps what was stored"
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req = as_caller(
            SbiRequest::patch("/nnrf-nfm/v1/subscriptions/cap-owned-1809").with_body(
                json!({ "validityTime": epoch_to_rfc3339(now + TEN_DAYS) }).to_string(),
                "application/json",
            ),
            Some(OWNER),
            None,
        );
        let r = nrf_sbi_request_handler(req).await;
        assert_eq!(r.status, 200, "{:?}", r.http.content);
        let body: serde_json::Value =
            serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
        let granted = rfc3339_to_epoch(body["validityTime"].as_str().unwrap()).unwrap();
        assert!(
            granted <= now + NRF_SUBSCRIPTION_DEFAULT_VALIDITY + 5,
            "the response returns the granted validity, not the proposal"
        );
        assert_eq!(
            m.find_subscription("cap-owned-1809")
                .unwrap()
                .validity_duration,
            NRF_SUBSCRIPTION_DEFAULT_VALIDITY,
            "a PATCH is capped like a Subscribe"
        );
        m.remove_subscription("cap-ownerless-1809");
        m.remove_subscription("cap-owned-1809");
    }

    /// Under production an ownerless subscription (restored from a state file
    /// written before #1809) cannot be updated or removed by anyone, the
    /// consumer that may have created it included: nobody can prove it.
    ///
    /// REVERT-VERIFIED: with `bind_subscription` returning `None` for an
    /// ownerless subscription whatever `required` says, both succeed.
    #[tokio::test]
    async fn under_production_an_ownerless_restored_subscription_is_frozen() {
        let id = "restored-ownerless-1809";
        nf_manager().add_subscription(nextgcore_nrfd::SubscriptionData {
            id: id.to_string(),
            req_nf_type: None,
            req_nf_instance_id: Some(OWNER.to_string()),
            notification_uri: "http://restored-1809.invalid/notify".to_string(),
            subscr_cond: None,
            validity_duration: 600,
            req_notif_events: None,
            notif_condition: None,
            owner: None,
        });
        for (cert, what) in [(Some(OWNER), "the claimed consumer"), (None, "anonymous")] {
            let r = nrf_sbi_request_handler(patch(id, cert, None)).await;
            assert_eq!(r.status, 403, "{what} PATCH: {:?}", r.http.content);
            assert!(
                r.http
                    .content
                    .as_deref()
                    .unwrap_or_default()
                    .contains("no verified owner"),
                "{what}"
            );
            assert_eq!(
                nf_manager()
                    .find_subscription(id)
                    .unwrap()
                    .validity_duration,
                600,
                "{what}: nothing applied"
            );
            let r = nrf_sbi_request_handler(delete(id, cert, None)).await;
            assert_eq!(r.status, 403, "{what} DELETE: {:?}", r.http.content);
            assert!(
                nf_manager().find_subscription(id).is_some(),
                "{what}: still stored"
            );
        }
        nf_manager().remove_subscription(id);
    }

    #[tokio::test]
    async fn an_unknown_subscription_is_still_404() {
        let r = nrf_sbi_request_handler(delete("no-such-1809", Some(OTHER), None)).await;
        assert_eq!(r.status, 404);
        let r = nrf_sbi_request_handler(patch("no-such-1809", Some(OTHER), None)).await;
        assert_eq!(r.status, 404);
    }
}

/// #1795: the NRF's listener follows the SBI security profile.
#[cfg(test)]
mod sbi_profile_tests_1795 {
    use super::*;
    use nextgcore_sbi::security::SbiProfile;

    /// REVERT-VERIFIED: with the production arm of `check_listener_profile`
    /// removed, a cleartext NRF is admitted under production and this fails.
    #[test]
    fn the_nrf_never_serves_cleartext_under_production_1795() {
        let err = check_listener_profile(SbiProfile::Production, None)
            .expect_err("a cleartext NRF is refused under production");
        assert!(
            err.to_string().contains("does not serve cleartext"),
            "{err}"
        );
        let tls = NrfServerTls {
            cert: "/c".into(),
            key: "/k".into(),
            ca: "/ca".into(),
            client_auth: ClientAuth::Optional,
        };
        check_listener_profile(SbiProfile::Production, Some(&tls))
            .expect("the NRF's own TLS is admitted under production");
        check_listener_profile(SbiProfile::Dev, None).expect("dev keeps its cleartext NRF");
    }
}

/// #1917: under the production profile, NF management is bound to the NF type the
/// caller's OWN verified certificate names (RFC 9310 NFTypes, TS 33.310 §6.1.3c.3,
/// TS 33.501 §5.9.2.2 NOTE). A certificate naming none cannot register, update or
/// deregister as any type; under dev it still may.
#[cfg(test)]
mod registrant_nf_type_tests_1917 {
    use super::*;
    use serde_json::json;

    tokio::task_local! {
        /// Overrides [`NrfPolicy::require_registrant_nf_types`] for one test's
        /// task, so the dev behaviour is testable without touching the
        /// process-global policy the rest of the binary reads.
        pub(super) static REQUIRED: bool;
    }

    /// A request from a directly verified certificate for `id` naming `types`.
    fn from_cert(mut req: SbiRequest, id: &str, types: &[&str]) -> SbiRequest {
        req.peer_cert_nf_instance_id = Some(id.to_string());
        req.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        req
    }

    fn put(id: &str, nf_type: &str, types: &[&str]) -> SbiRequest {
        let mut req = SbiRequest::put(format!("/nnrf-nfm/v1/nf-instances/{id}"));
        req.http.set_content(
            json!({"nfInstanceId": id, "nfType": nf_type, "nfStatus": "REGISTERED"}).to_string(),
        );
        from_cert(req, id, types)
    }

    fn patch(id: &str, types: &[&str]) -> SbiRequest {
        let req = SbiRequest::patch(format!("/nnrf-nfm/v1/nf-instances/{id}")).with_body(
            json!([{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]).to_string(),
            "application/json-patch+json",
        );
        from_cert(req, id, types)
    }

    fn assert_unverifiable_type(r: &SbiResponse, what: &str) {
        assert_eq!(r.status, 400, "{what}: {:?}", r.http.content);
        let body = r.http.content.as_deref().unwrap_or_default();
        assert!(body.contains("INVALID_CLIENT"), "{what}: {body}");
        assert!(
            body.contains("names no NF type"),
            "{what}: refused for the missing NFTypes, not another reason: {body}"
        );
    }

    /// The default fails closed, and the dev opt-out is per task only.
    #[test]
    fn a_policy_nobody_set_requires_the_certificate_nf_type_1917() {
        assert!(NrfPolicy::default().require_registrant_nf_types);
    }

    /// **#1917.** A certificate with no NFTypes registers as no type under
    /// production (an SMF could otherwise register as AUSF and be granted
    /// nudm-ueau tokens, #1866), but as the asserted type under dev. A certificate
    /// naming the type registers under production.
    ///
    /// REVERT-VERIFIED: with the empty-NFTypes branch of `bind_nf_type` returning
    /// `None` again, the production PUT is 201 and the first assertion fails.
    #[tokio::test]
    async fn a_certificate_without_nf_types_registers_as_no_type_under_production_1917() {
        let id = "19170000-0000-4000-8000-000000000001";
        let r = REQUIRED
            .scope(true, handle_nf_register(id, &put(id, "AUSF", &[])))
            .await;
        assert_unverifiable_type(&r, "production NFRegister without NFTypes");
        assert!(nf_manager().get(id).is_none(), "nothing stored");

        let r = REQUIRED
            .scope(false, handle_nf_register(id, &put(id, "AUSF", &[])))
            .await;
        assert_eq!(
            r.status, 201,
            "dev keeps today's behaviour: {:?}",
            r.http.content
        );
        let _ = nf_manager().deregister(id);

        // Positive control: the certificate names the type it registers as.
        let r = REQUIRED
            .scope(true, handle_nf_register(id, &put(id, "AUSF", &["AUSF"])))
            .await;
        assert_eq!(r.status, 201, "{:?}", r.http.content);
        // ... and only that type.
        let other = "19170000-0000-4000-8000-000000000002";
        let r = REQUIRED
            .scope(
                true,
                handle_nf_register(other, &put(other, "AUSF", &["SMF"])),
            )
            .await;
        assert_eq!(r.status, 400, "an SMF certificate cannot register an AUSF");
        let _ = nf_manager().deregister(id);
    }

    /// **#1917.** NFUpdate and NFDeregister bind the same way: a certificate with
    /// no NFTypes cannot manage the entry under production, and can under dev.
    ///
    /// REVERT-VERIFIED: with `registrant_nf_types_required()` passed as `false`
    /// at the NFUpdate site, the production PATCH succeeds and this fails; the
    /// same at the NFDeregister site fails the DELETE assertion.
    #[tokio::test]
    async fn update_and_deregister_need_the_certificate_nf_type_under_production_1917() {
        let id = "19170000-0000-4000-8000-000000000003";
        nf_manager()
            .register(
                NfProfile::from_json(
                    &json!({"nfInstanceId": id, "nfType": "SMF", "nfStatus": "REGISTERED"}),
                )
                .expect("profile"),
            )
            .expect("stored");

        let r = REQUIRED
            .scope(true, handle_nf_update(id, &patch(id, &[])))
            .await;
        assert_unverifiable_type(&r, "production NFUpdate without NFTypes");
        let delete = from_cert(
            SbiRequest::delete(format!("/nnrf-nfm/v1/nf-instances/{id}")),
            id,
            &[],
        );
        let r = REQUIRED
            .scope(true, handle_nf_deregister(id, &delete))
            .await;
        assert_unverifiable_type(&r, "production NFDeregister without NFTypes");
        assert!(nf_manager().get(id).is_some(), "the entry is untouched");

        let r = REQUIRED
            .scope(false, handle_nf_update(id, &patch(id, &[])))
            .await;
        assert!(
            (200..300).contains(&r.status),
            "dev NFUpdate: {} {:?}",
            r.status,
            r.http.content
        );
        let r = REQUIRED
            .scope(false, handle_nf_deregister(id, &delete))
            .await;
        assert_eq!(r.status, 204, "dev NFDeregister: {:?}", r.http.content);
    }
}

/// #1926 (DECISION 2026-11-19): the NRF requires verified callers wherever it can
/// verify them, not only under the production profile.
#[cfg(test)]
mod verification_required_tests_1926 {
    use super::*;
    use nextgcore_sbi::security::SbiProfile;

    fn tls() -> NrfServerTls {
        NrfServerTls {
            cert: "nrf.crt".into(),
            key: "nrf.key".into(),
            ca: "ca.crt".into(),
            client_auth: ClientAuth::Optional,
        }
    }

    /// The decision as a table: production, or a listener that verifies client
    /// certificates. Optional client auth counts: a presented certificate is
    /// verified, so a caller can be.
    ///
    /// REVERT-VERIFIED: with `|| server_tls.is_some()` dropped, the dev-with-TLS
    /// row fails.
    #[test]
    fn verified_callers_are_required_wherever_the_nrf_can_verify_them_1926() {
        assert!(
            !verification_required(SbiProfile::Dev, None),
            "dev, cleartext"
        );
        assert!(
            verification_required(SbiProfile::Dev, Some(&tls())),
            "dev, TLS"
        );
        assert!(verification_required(SbiProfile::Production, None));
        let required = NrfServerTls {
            client_auth: ClientAuth::Required,
            ..tls()
        };
        assert!(verification_required(SbiProfile::Dev, Some(&required)));
    }

    /// Every shipped stack's NRF serves TLS, so under the dev profile those
    /// stacks have the refusals on: the docker compose nrf.yaml, the k8s
    /// ConfigMap and the Helm chart as rendered (CI sets NEXTGCORE_HELM_REQUIRED,
    /// so the Helm leg is never skipped there). A dev NRF without TLS keeps them
    /// off.
    #[test]
    fn every_shipped_stack_requires_verified_callers_under_dev_1926() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut stacks: Vec<(String, String)> = vec![(
            "docker nrf.yaml".into(),
            std::fs::read_to_string(root.join("docker/rust/configs/5gc/nrf.yaml")).unwrap(),
        )];
        let cm: serde_yaml::Value = serde_yaml::from_str(
            &std::fs::read_to_string(root.join("k8s/manifests/configmap.yaml")).unwrap(),
        )
        .unwrap();
        stacks.push((
            "k8s ConfigMap nrf.yaml".into(),
            cm["data"]["nrf.yaml"]
                .as_str()
                .expect("nrf.yaml")
                .to_string(),
        ));
        if let Some(text) = nextgcore_core::helm_render::helm_rendered_config(&root, "nrf.yaml") {
            stacks.push(("Helm nrf.yaml".into(), text));
        }
        let flags = TlsFlags {
            tls: false,
            cert: None,
            key: None,
            mtls: false,
            ca: None,
        };
        for (name, text) in &stacks {
            let yaml: NrfYaml =
                serde_yaml::from_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let server_tls = resolve_server_tls(
                &flags,
                |_| None,
                yaml.nrf
                    .as_ref()
                    .and_then(|n| n.sbi.as_ref())
                    .and_then(|s| s.server.as_ref())
                    .and_then(|v| v.first())
                    .and_then(|s| s.tls.as_ref()),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                verification_required(SbiProfile::Dev, server_tls.as_ref()),
                "{name}: the NRF verifies client certificates, so it requires verified callers"
            );
        }
        // A dev NRF with TLS turned off by the environment: unchanged, off.
        let off = resolve_server_tls(
            &flags,
            |v| (v == NRF_SERVER_TLS_ENV).then(|| "false".to_string()),
            None,
        )
        .unwrap();
        assert!(!verification_required(SbiProfile::Dev, off.as_ref()));
    }

    /// `main` sets BOTH policies from [`verification_required`], after the
    /// listener's TLS is resolved and before the policy is published.
    ///
    /// REVERT-VERIFIED: with either assignment back on the profile alone, this
    /// fails.
    #[test]
    fn main_sets_both_policies_from_the_listener_s_verification_1926() {
        let source = include_str!("main.rs");
        let main = &source[source.find("async fn main()").expect("main")..];
        let main = &main[..main
            .find("\n    NRF_POLICY.set(policy).ok();\n")
            .expect("the policy is published")];
        let tls_at = main
            .find("let server_tls = resolve_server_tls(")
            .expect("TLS");
        let at = main
            .find("let verification = verification_required(")
            .expect("verification_required is called");
        assert!(tls_at < at, "the listener's TLS is resolved first");
        for policy in [
            "policy.require_subscriber_identity = verification || policy.trust_forwarded_client_cert;",
            "policy.require_registrant_nf_types = verification || policy.trust_forwarded_client_cert;",
        ] {
            assert!(main[at..].contains(policy), "{policy}");
        }
    }
}
