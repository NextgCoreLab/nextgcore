//! SCP HTTP/2 Forwarding Engine (TS 29.500 §6.10)
//!
//! Real proxy data path for the SCP, replacing the former comment stubs in
//! `sbi_path.rs`:
//!
//! - **Model C** (indirect communication without delegated discovery): the
//!   consumer sets `3gpp-Sbi-Target-apiRoot`; the SCP opens an HTTP/2 client
//!   connection to that apiRoot and relays the request/response.
//! - **Model D** (indirect communication with delegated discovery): the
//!   consumer sets `3gpp-Sbi-Discovery-*` headers; the SCP queries the NRF
//!   (`nnrf-disc`), parses the SearchResult, selects a producer, forwards,
//!   and returns `3gpp-Sbi-Producer-Id` to the consumer.
//! - **Binding stickiness** (TS 29.500 §6.12): a `3gpp-Sbi-Binding` header on
//!   a producer response is cached; a later request carrying the same value
//!   in `3gpp-Sbi-Routing-Binding` is routed to the same producer without a
//!   new discovery.
//! - **Oci/Lci** (`3gpp-Sbi-Oci`, `3gpp-Sbi-Lci`) and all other end-to-end
//!   headers are propagated untouched in both directions.
//!
//! Header handling is case-insensitive throughout (hyper lowercases all
//! HTTP/2 header names on the wire). Hop-by-hop headers (RFC 9110 §7.6.1)
//! and the SCP-consumed `3gpp-Sbi-Target-apiRoot` / `3gpp-Sbi-Discovery-*` /
//! `3gpp-Sbi-Routing-Binding` headers are stripped before forwarding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::constants::{custom_header, discovery_header};
use nextgcore_sbi::message::{
    ProblemDetails, SbiHttpMessage, SbiRequest, SbiResponse, UriComponents,
};
use nextgcore_sbi::oauth::{OAuth2Client, TokenConsumer};
use nextgcore_sbi::types::{NfType, UriScheme};
use nextgcore_sbi::SbiError;

use crate::cache::BoundedCache;
use crate::circuit_breaker::CircuitBreaker;
use crate::sbi_path::{
    parse_search_result, rank_nf_service_endpoints, DiscoveryCache, EndpointSelectionError,
};

/// Default upstream connect timeout (bounded per TS 29.500 §6.11 guidance).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Default upstream request timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Default hard ceiling on entries in each proxy cache (scpd-#102). Bounds the
/// peer-influenced binding / discovery / client maps against slow-memory-growth
/// (TS 33.522 §4.2.3.3).
const DEFAULT_MAX_CACHE_ENTRIES: usize = 4096;
/// Default cache entry lifetime for the client / binding / circuit-breaker
/// caches. The discovery cache keeps its own per-entry `validityPeriod` TTL.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Default consecutive failures before a producer's circuit trips Open.
const DEFAULT_CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
/// Default time a tripped circuit stays Open before admitting a probe.
const DEFAULT_CIRCUIT_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Fallback NF Instance ID claimed by the SCP when acquiring delegated OAuth2
/// access tokens (`nfInstanceId` in the TS 29.510 token request) if none is
/// configured. A stable value keeps NRF-side token bookkeeping coherent.
const DEFAULT_SCP_NF_INSTANCE_ID: &str = "nextgcore-scp";

/// Default SCP own-FQDN used to build the `Via` (relayed errors, §6.10.8.3),
/// `Server` (SCP-originated errors, §6.10.8.2) and loop-detection identity
/// (`SCP-<FQDN>`, §6.10.10.3) when none is configured.
const DEFAULT_SCP_FQDN: &str = "scp.5gc.local";

/// `Via` header name (RFC 9110 §7.6.3; reused for SCP loop detection /
/// relayed-error annotation per TS 29.500 §6.10.8.3 / §6.10.10.3).
const VIA_HEADER: &str = "Via";
/// `Server` header name (RFC 9110 §10.2.4; SCP-originated error identity,
/// TS 29.500 §6.10.8.2).
const SERVER_HEADER: &str = "Server";
/// `3gpp-Sbi-Max-Forward-Hops` header (TS 29.500 §5.2.3.2.14 / §6.10.10.2).
/// Not in `nextgcore_sbi::custom_header`; defined locally (additive, consumer-side).
const MAX_FORWARD_HOPS_HEADER: &str = "3gpp-Sbi-Max-Forward-Hops";
/// `WWW-Authenticate` response header (RFC 9110 §11.6.1) carrying the
/// producer's Bearer challenge (TS 29.500 §6.10.11.2.3).
const WWW_AUTHENTICATE_HEADER: &str = "WWW-Authenticate";

/// Query parameters the SCP consumes internally and MUST NOT forward to the
/// producer. `ck` is the cache-key (TS 29.500 §6.10.2.6); the list is a const
/// so future SCP-internal params can be added in one place (scpd-05).
const SCP_INTERNAL_PARAMS: &[&str] = &["ck"];

/// Hop-by-hop headers that must not be forwarded by a proxy
/// (RFC 9110 §7.6.1; `host`/`content-length` are recomputed by the client).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// SCP proxy configuration.
#[derive(Debug, Clone)]
pub struct ScpProxyConfig {
    /// NRF base URI for Model D delegated discovery
    /// (e.g. `http://127.0.0.1:7777`). When unset, Model D requests are
    /// rejected with 503.
    pub nrf_uri: Option<String>,
    /// Upstream connect timeout.
    pub connect_timeout: Duration,
    /// Upstream request timeout.
    pub request_timeout: Duration,
    /// The SCP's own NF Instance ID, sent as `nfInstanceId` in delegated
    /// OAuth2 token requests to the NRF (TS 29.510 §6.3). When `None`, a
    /// stable default (`DEFAULT_SCP_NF_INSTANCE_ID`) is used.
    pub nf_instance_id: Option<String>,
    /// The SCP's own FQDN/identity, used to build `Via` (relayed errors,
    /// §6.10.8.3), `Server` (SCP-originated errors, §6.10.8.2) and the
    /// loop-detection identity `SCP-<FQDN>` (§6.10.10.3). Defaults to
    /// [`DEFAULT_SCP_FQDN`].
    pub own_fqdn: String,
    /// Whether the next hop on a forwarded request is another SCP rather than
    /// the producer. When `true`, the selected producer apiRoot is conveyed in
    /// `3gpp-Sbi-Target-apiRoot` instead of being stripped (TS 29.500
    /// §6.10.2.5, scpd-10). Defaults to `false` (next hop is the producer).
    pub next_hop_scp: bool,
    /// Hard ceiling on entries in each proxy cache (client pools, binding
    /// stickiness, discovery cache, circuit breakers) — scpd-#102.
    pub max_cache_entries: usize,
    /// Lifetime of a client / binding / circuit-breaker cache entry. The
    /// discovery cache keeps its own per-entry `validityPeriod` TTL.
    pub cache_ttl: Duration,
    /// Consecutive failures before a producer's circuit trips Open.
    pub circuit_failure_threshold: u32,
    /// Time a tripped circuit stays Open before admitting a probe.
    pub circuit_open_timeout: Duration,
    /// Assert the requesting consumer's identity in a delegated (Model D) token
    /// request **even when the consumer supplied no CCA of its own**
    /// (nextgcore #101 criterion 2).
    ///
    /// Default `false`, and that default is not timidity. After #64 the NRF's
    /// token endpoint authenticates the requester by a CCA keyed to
    /// `nfInstanceId`; the SCP can only sign with its OWN key, so naming the
    /// consumer in the body while signing as ourselves produces a request a
    /// conformant NRF rejects. Asserting the consumer's identity is therefore
    /// only safe when the consumer attests it (its own CCA — the conformant
    /// Model D case, TS 33.501 §13.4.1.3.2) or when the operator declares the
    /// NRF does not require client authentication, which is what this flag is.
    ///
    /// Set it only for such an NRF: with it on and no consumer CCA, the token
    /// request carries an unattested identity.
    pub trust_requester_identity: bool,
    /// Maximum producers a single Model D request may be forwarded to before the
    /// SCP gives up (scpd-#209). `1` disables reselection; the default `3` bounds
    /// the fan-out so one consumer request cannot walk a large `SearchResult`.
    /// Clamped to at least 1. Only reached on a *provably undelivered* forward, so
    /// this is not a retry budget for a producer that answered.
    pub max_producer_attempts: usize,
}

/// Default number of producers one Model D request may be forwarded to
/// (scpd-#209): the selected one plus two alternates.
const DEFAULT_MAX_PRODUCER_ATTEMPTS: usize = 3;

impl Default for ScpProxyConfig {
    fn default() -> Self {
        Self {
            nrf_uri: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            nf_instance_id: None,
            own_fqdn: DEFAULT_SCP_FQDN.to_string(),
            next_hop_scp: false,
            max_cache_entries: DEFAULT_MAX_CACHE_ENTRIES,
            cache_ttl: DEFAULT_CACHE_TTL,
            circuit_failure_threshold: DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
            circuit_open_timeout: DEFAULT_CIRCUIT_OPEN_TIMEOUT,
            trust_requester_identity: false,
            max_producer_attempts: DEFAULT_MAX_PRODUCER_ATTEMPTS,
        }
    }
}

/// A parsed `apiRoot` per TS 29.501 §4.4.1:
/// `scheme://host[:port][/deployment-prefix]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRoot {
    pub scheme: UriScheme,
    pub host: String,
    pub port: u16,
    /// Optional deployment-specific path prefix (leading `/`, no trailing).
    pub prefix: String,
}

impl ApiRoot {
    /// Parse an apiRoot URI. Rejects anything without an `http`/`https`
    /// scheme or with an empty/invalid authority.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let uri = uri.trim();
        let (scheme, rest) = if let Some(rest) = uri.strip_prefix("https://") {
            (UriScheme::Https, rest)
        } else if let Some(rest) = uri.strip_prefix("http://") {
            (UriScheme::Http, rest)
        } else {
            return Err(format!("apiRoot has no http/https scheme: {uri}"));
        };

        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, String::new()),
        };
        if authority.is_empty() {
            return Err(format!("apiRoot has empty authority: {uri}"));
        }

        let (host, port) = match authority.rsplit_once(':') {
            // Avoid mis-parsing a bare IPv6 literal as host:port
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| format!("apiRoot has invalid port: {uri}"))?;
                (h.to_string(), port)
            }
            _ => {
                let default_port = match scheme {
                    UriScheme::Https => 443,
                    UriScheme::Http => 80,
                };
                (authority.to_string(), default_port)
            }
        };

        Ok(Self {
            scheme,
            host,
            port,
            prefix: path.trim_end_matches('/').to_string(),
        })
    }

    /// Canonical `scheme://host:port[/prefix]` form (used as client-cache and
    /// binding-cache value).
    pub fn to_uri(&self) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme, self.host, self.port, self.prefix
        )
    }
}

/// Normalize a `3gpp-Sbi-Binding` / `3gpp-Sbi-Routing-Binding` value for use
/// as a cache key: lowercase with all whitespace removed, so
/// `bl=nf-instance; nfinst=X` and `BL=NF-INSTANCE;NFINST=X` match.
fn normalize_binding(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Everything the SCP needs to mint a delegated (Model D) access token for the
/// NF Service Consumer that sent the request (TS 33.501 §13.4.1.3.2).
#[derive(Debug, Clone)]
struct DelegatedAuth {
    /// NF type of the discovered producer — the token's `targetNfType`.
    target_nf_type: NfType,
    /// Whose token this is. Either the consumer (when its identity can be
    /// attested) or the SCP itself; see [`ScpProxy::delegated_auth`].
    consumer: TokenConsumer,
    /// The scope the consumer explicitly asked for in `3gpp-Sbi-Access-Scope`,
    /// if any. When absent the scope is derived from the request URI's service
    /// name, as before.
    requested_scope: Option<String>,
    /// True when `consumer` is the requester rather than the SCP. Only used for
    /// logging, so an operator can tell an SCP-attested token from a
    /// consumer-attested one.
    consumer_attested: bool,
}

/// Remove any `Authorization` header (case-insensitive) from a forwardable
/// header map. Used on the Model D path before the SCP attaches its own
/// delegated OAuth2 token: the consumer's token (if any) was not scoped to the
/// discovered producer, so it must not leak through.
fn strip_authorization(headers: &mut HashMap<String, String>) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case("authorization"));
}

/// Map a `3gpp-Sbi-Discovery-target-nf-type` header value (e.g. `"UDM"`,
/// case-insensitive) to an [`NfType`] for OAuth2 token scoping. Mirrors
/// [`NfType::to_str`]; unknown values yield `None` (the SCP then forwards
/// without minting a token rather than guessing a wrong audience).
fn nf_type_from_str(s: &str) -> Option<NfType> {
    let upper = s.trim().to_ascii_uppercase();
    let nf = match upper.as_str() {
        "NRF" => NfType::Nrf,
        "UDM" => NfType::Udm,
        "AMF" => NfType::Amf,
        "SMF" => NfType::Smf,
        "AUSF" => NfType::Ausf,
        "NEF" => NfType::Nef,
        "PCF" => NfType::Pcf,
        "SMSF" => NfType::Smsf,
        "NSSF" => NfType::Nssf,
        "UDR" => NfType::Udr,
        "LMF" => NfType::Lmf,
        "GMLC" => NfType::Gmlc,
        "5G_EIR" => NfType::FiveGEir,
        "SEPP" => NfType::Sepp,
        "UPF" => NfType::Upf,
        "N3IWF" => NfType::N3iwf,
        "AF" => NfType::Af,
        "UDSF" => NfType::Udsf,
        "BSF" => NfType::Bsf,
        "CHF" => NfType::Chf,
        "NWDAF" => NfType::Nwdaf,
        "PCSCF" => NfType::Pcscf,
        "CBCF" => NfType::Cbcf,
        "HSS" => NfType::Hss,
        "UCMF" => NfType::Ucmf,
        "SCP" => NfType::Scp,
        "NSSAAF" => NfType::Nssaaf,
        "MFAF" => NfType::Mfaf,
        "MBSMF" => NfType::Mbsmf,
        "MBSTF" => NfType::Mbstf,
        "PANF" => NfType::Panf,
        "TSCTSF" => NfType::Tsctsf,
        "EASDF" => NfType::Easdf,
        "EES" => NfType::Ees,
        "DCCF" => NfType::Dccf,
        "NSACF" => NfType::Nsacf,
        "PKMF" => NfType::Pkmf,
        "MNPF" => NfType::Mnpf,
        "SMSF_5G" => NfType::Smsf5G,
        _ => return None,
    };
    Some(nf)
}

/// Case-insensitive header lookup on a plain header map (used for forwardable
/// request headers, which are a bare `HashMap` rather than an `SbiHttpMessage`).
fn header_get<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// Case-insensitive header set on a plain header map: removes any case-variant
/// of `name` then inserts `value` under `name`.
fn header_set(headers: &mut HashMap<String, String>, name: &str, value: String) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case(name));
    headers.insert(name.to_string(), value);
}

/// True for SCP-internal query params that must never reach the producer
/// (currently just the `ck` cache-key, TS 29.500 §6.10.2.6).
fn is_scp_internal_param(name: &str) -> bool {
    SCP_INTERNAL_PARAMS
        .iter()
        .any(|p| name.eq_ignore_ascii_case(p))
}

/// True when a `WWW-Authenticate` challenge on the response names the `Bearer`
/// scheme (TS 29.500 §6.10.11.2.3 token-retry trigger).
fn www_authenticate_is_bearer(response: &SbiResponse) -> bool {
    response
        .http
        .get_header(WWW_AUTHENTICATE_HEADER)
        .map(|v| v.to_ascii_lowercase().contains("bearer"))
        .unwrap_or(false)
}

/// Parse a `3gpp-Sbi-Max-Forward-Hops` value (TS 29.500 §5.2.3.2.14), e.g.
/// `5; nodetype=scp`, into `(hop_count, nodetype)`. Returns `None` when the
/// leading hop count is not a number.
fn parse_max_forward_hops(value: &str) -> Option<(u32, Option<String>)> {
    let mut parts = value.split(';');
    let count = parts.next()?.trim().parse::<u32>().ok()?;
    let mut nodetype = None;
    for p in parts {
        if let Some((k, v)) = p.split_once('=') {
            if k.trim().eq_ignore_ascii_case("nodetype") {
                nodetype = Some(v.trim().to_string());
            }
        }
    }
    Some((count, nodetype))
}

/// Map a received `3gpp-Sbi-Discovery-<x>` header name to its nnrf-disc query
/// parameter name `<x>` (TS 29.500 §6.10.3.2 ↔ TS 29.510 §6.2.3.2.3). Returns
/// `None` for non-discovery headers and for the factors handled out-of-band
/// (`target-nf-type` / `requester-nf-type` are added explicitly; `hnrf-uri`
/// selects the queried NRF and is not an nnrf-disc parameter). The generic
/// prefix-strip covers every other factor (guami, tai, snssais, dnn,
/// target/requester-plmn-list, requester-features, target-nf-instance-id,
/// requester-nf-instance-id, service-names, target-nf-set-id, nsi, …).
fn nnrf_disc_param_from_discovery_header(name: &str) -> Option<String> {
    let prefix = discovery_header::PREFIX;
    let is_disc = name
        .get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix));
    if !is_disc {
        return None;
    }
    let param = name[prefix.len()..].to_ascii_lowercase();
    if param.is_empty()
        || matches!(
            param.as_str(),
            "target-nf-type" | "requester-nf-type" | "hnrf-uri"
        )
    {
        return None;
    }
    Some(param)
}

/// Build a `3gpp-Sbi-Producer-Id` value in the TS 29.500 §5.2.3.2.8 ABNF form
/// `nfinst=<uuid>[; nfset=<set-id>]`. Returns `None` for an empty instance id.
fn build_producer_id(nf_instance_id: &str, nf_set_id: Option<&str>) -> Option<String> {
    if nf_instance_id.is_empty() {
        return None;
    }
    let mut value = format!("nfinst={nf_instance_id}");
    if let Some(set) = nf_set_id.filter(|s| !s.is_empty()) {
        value.push_str("; nfset=");
        value.push_str(set);
    }
    Some(value)
}

/// A `3gpp-Sbi-Binding` / `3gpp-Sbi-Routing-Binding` value decomposed into its
/// binding level and entity identifiers (TS 29.500 §5.2.3.2.5/§5.2.3.2.6).
/// Only the members the SCP keys stickiness on are retained.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ParsedBinding {
    /// Binding level: `nf-instance` / `nf-set` / `nf-service-set` (lowercased).
    bl: Option<String>,
    nfinst: Option<String>,
    nfset: Option<String>,
    nfservinst: Option<String>,
    nfserviceset: Option<String>,
}

impl ParsedBinding {
    fn parse(value: &str) -> Self {
        let mut b = Self::default();
        for token in value.split(';') {
            if let Some((k, v)) = token.split_once('=') {
                let val = v.trim().to_string();
                match k.trim().to_ascii_lowercase().as_str() {
                    "bl" => b.bl = Some(val.to_ascii_lowercase()),
                    "nfinst" => b.nfinst = Some(val),
                    "nfset" => b.nfset = Some(val),
                    "nfservinst" => b.nfservinst = Some(val),
                    "nfserviceset" => b.nfserviceset = Some(val),
                    _ => {}
                }
            }
        }
        b
    }

    /// True when this binding selects at the NF-set level, so the SCP may
    /// reselect any registered member of the set.
    fn is_set_level(&self) -> bool {
        self.bl.as_deref() == Some("nf-set")
    }
}

/// A producer selected by Model D delegated discovery, with the identifiers the
/// SCP surfaces to the consumer.
#[derive(Debug, Clone)]
struct DiscoveredProducer {
    target: ApiRoot,
    nf_instance_id: String,
    nf_set_id: Option<String>,
    nf_group_id: Option<String>,
}

/// The producer delegated discovery selected, plus the ordered alternates the SCP
/// may fail over to (scpd-#209, TS 29.500 §6.10.8.2).
///
/// Before this, the remainder of the `SearchResult` was parsed and then thrown
/// away, so a single restarting producer failed requests a registered, healthy
/// sibling could have served: with N replicas behind the NRF, availability was
/// that of one replica rather than of the set.
struct DiscoveryOutcome {
    primary: DiscoveredProducer,
    alternates: Vec<DiscoveredProducer>,
}

/// What the SCP decided about the target, carried into the response relay because
/// the fix-ups it owes the consumer depend on it (TS 29.500 §6.10.3.4 / §6.10.4).
#[derive(Debug, Default, Clone, Copy)]
struct RelayContext<'a> {
    /// The `3gpp-Sbi-Producer-Id` value to surface, when the SCP has one.
    producer_id: Option<&'a str>,
    /// The producer's NF group id for `3gpp-Sbi-Target-Nf-Group-Id`.
    group_id: Option<&'a str>,
    /// True when the **SCP** chose the producer (Model D, or a sticky binding
    /// resolved from its own cache) rather than the consumer naming it in
    /// `3gpp-Sbi-Target-apiRoot`.
    ///
    /// This is the §6.10.4 trigger: after retargeting, the consumer does not know
    /// which apiRoot the created resource lives on, so a relative `Location` it
    /// receives is unusable. In Model C the consumer picked the target itself and
    /// needs no help.
    retargeted: bool,
}

/// A forward that provably never reached the producer, so another candidate may
/// still serve it (scpd-#209).
struct Undeliverable {
    /// The producer apiRoot that could not be reached, for the error detail.
    target: String,
    /// The transport error, or `None` when the SCP's own circuit breaker for this
    /// producer was Open and nothing was sent at all.
    error: Option<SbiError>,
}

/// The result of forwarding to **one** producer (scpd-#209).
///
/// `Undeliverable` is separated from `Final` so the Model D path can tell "try
/// the next candidate" from "this is the answer" — the distinction the old
/// single-`SbiResponse` return could not express, which is why reselection was
/// impossible without this split.
enum ForwardOutcome {
    /// The producer answered, at any status. Relay it.
    Answered(SbiResponse),
    /// The request never reached this producer.
    Undeliverable(Undeliverable),
    /// An SCP-originated answer no other candidate could improve on: a delegated
    /// token the NRF refused (same for every instance of the target NF type), or
    /// a transport failure that may have delivered the request already.
    Final(SbiResponse),
}

/// True when `err` proves the request never left the SCP, so replaying it on
/// another producer cannot duplicate work (scpd-#209 idempotency decision).
///
/// **This is the whole idempotency argument, and it is deliberately narrow.** In
/// `nextgcore_sbi::client`, `ConnectionError` is produced only by the TCP connect
/// (`client.rs:452`) and the HTTP/2 handshake (`:514`, `:529`), and `TlsError`
/// only by server-name validation and the TLS handshake (`:457`, `:465`) — every
/// one of them before a single request byte is written. So reselecting after one
/// is safe even for a `POST`.
///
/// `Timeout` is excluded although it looks like a transport failure: the same
/// variant is produced by the connect phase (`:451`, `:464`) **and** by the
/// send/response phase (`:892`), so it cannot distinguish "never sent" from "sent
/// and the producer is still working on it". Replaying a non-idempotent request
/// on a timeout could duplicate a registration or a charging record.
/// `HyperError` (`:893`) is likewise post-send. Taking the conservative reading
/// means there is no exposure to document rather than an exposure documented.
fn is_provably_undelivered(err: &SbiError) -> bool {
    matches!(err, SbiError::ConnectionError(_) | SbiError::TlsError(_))
}

/// True for header names a proxy must not forward, in either direction:
/// HTTP/2 pseudo-headers and RFC 9110 hop-by-hop headers.
fn is_hop_by_hop(name: &str) -> bool {
    name.starts_with(':')
        || HOP_BY_HOP_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
}

/// True for request headers the SCP itself consumes and must strip before
/// forwarding to the producer (TS 29.500 §5.2.3.2.4 / §5.2.3.2.7 / §6.12).
fn is_scp_consumed(name: &str) -> bool {
    let lower_eq = |c: &str| name.eq_ignore_ascii_case(c);
    lower_eq(custom_header::TARGET_APIROOT)
        || lower_eq(custom_header::ROUTING_BINDING)
        || name
            .get(..discovery_header::PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(discovery_header::PREFIX))
}

/// Copy request headers for forwarding: drops pseudo/hop-by-hop headers and
/// the SCP-consumed routing headers; everything else (including
/// `3gpp-Sbi-Oci`, `3gpp-Sbi-Lci`, `3gpp-Sbi-Binding`, `Authorization`, ...)
/// passes through untouched.
pub fn forwardable_request_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !is_hop_by_hop(k) && !is_scp_consumed(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Copy response headers for relaying back to the consumer: drops only
/// pseudo/hop-by-hop headers; `3gpp-Sbi-Binding`, `3gpp-Sbi-Oci`,
/// `3gpp-Sbi-Lci` and all other end-to-end headers are relayed untouched.
pub fn relayable_response_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !is_hop_by_hop(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Build a ProblemDetails error response (`application/problem+json`,
/// TS 29.500 §5.2.7).
fn problem_response(status: u16, title: &str, detail: &str, cause: &str) -> SbiResponse {
    let problem = ProblemDetails::with_status(status as i32)
        .with_title(title)
        .with_detail(detail)
        .with_cause(cause);
    SbiResponse::with_status(status).with_problem(&problem)
}

/// Map an upstream client error to the proxy error response:
/// timeout → 504 Gateway Timeout, anything else → 502 Bad Gateway.
///
/// **`TARGET_NF_NOT_REACHABLE` is for the producer only** (scpd-#211). A failure
/// reaching the *NRF* goes through [`nrf_unreachable_response`] instead: naming
/// the target NF for an NRF outage sends the investigation to a producer that is
/// healthy (TS 29.500 §6.10.8.2).
fn upstream_error_response(target: &str, err: &SbiError) -> SbiResponse {
    match err {
        SbiError::Timeout => problem_response(
            504,
            "Gateway Timeout",
            &format!("Timeout forwarding request to {target}"),
            "TARGET_NF_NOT_REACHABLE",
        ),
        other => problem_response(
            502,
            "Bad Gateway",
            &format!("Failed to forward request to {target}: {other}"),
            "TARGET_NF_NOT_REACHABLE",
        ),
    }
}

/// Map a transport failure while querying the NRF for delegated discovery
/// (scpd-#211, TS 29.500 §6.10.8.2).
///
/// `504` + `NRF_NOT_REACHABLE`, and the two halves of that carry different
/// information. The **cause** names the node that actually failed: routing an NRF
/// outage through [`upstream_error_response`] reported
/// `TARGET_NF_NOT_REACHABLE`, which points the operator at a producer that is
/// up. The **status** is `504` for both a refused connection and a timeout,
/// because to the consumer they are the same actionable fact — infrastructure is
/// down and a retry may help — unlike an empty `SearchResult`, where the
/// consumer's own criteria matched nothing and retrying cannot help.
fn nrf_unreachable_response(nrf: &str, err: &SbiError) -> SbiResponse {
    problem_response(
        504,
        "Gateway Timeout",
        &format!("SCP could not reach the NRF at {nrf} for delegated discovery: {err}"),
        "NRF_NOT_REACHABLE",
    )
}

/// The service name and API major version the request is *for*, used to select
/// the producer's matching `NFService` endpoint (TS 29.510 §6.2.6.2).
///
/// **The request URI is authoritative**, because it is what the producer will be
/// asked for: `/nudm-uecm/v1/registrations` names service `nudm-uecm` at version
/// `v1`. `3gpp-Sbi-Discovery-service-names` is only a fallback for a URI with no
/// `{apiName}/{apiVersion}` pair, and only when it names exactly **one** service
/// — a list leaves the endpoint ambiguous, and picking an element of it would
/// reinstate the arbitrary choice this selection exists to remove.
fn requested_service_and_version(request: &SbiRequest) -> (Option<String>, Option<String>) {
    let parsed = UriComponents::parse(&request.header.uri);
    let single_named_service = || {
        request
            .http
            .get_header(discovery_header::SERVICE_NAMES)
            .and_then(|value| {
                let mut names = value.split(',').map(str::trim).filter(|s| !s.is_empty());
                let first = names.next()?;
                names.next().is_none().then(|| first.to_string())
            })
    };
    let service = parsed.api_name.clone().or_else(single_named_service);
    (service, parsed.api_version)
}

/// Map an endpoint-selection failure to the answer the consumer is owed
/// (TS 29.510 §6.2.6.2, TS 29.500 Table 5.2.7.2-1).
///
/// The version case is `400 INVALID_API` and not a discovery failure: the NRF
/// did its job and returned the producer, and it is the consumer's requested API
/// version that cannot be served — retrying will not help, so telling it
/// `NF_DISCOVERY_FAILURE` would send it looking in the wrong place.
fn endpoint_selection_error_response(
    err: EndpointSelectionError,
    service: Option<&str>,
    version: Option<&str>,
) -> SbiResponse {
    let service = service.unwrap_or("(unnamed)");
    match err {
        EndpointSelectionError::UnsupportedApiVersion => problem_response(
            400,
            "Bad Request",
            &format!(
                "No discovered producer serves service {service} at API version {}",
                version.unwrap_or("(unnamed)")
            ),
            "INVALID_API",
        ),
        // scpd-#211: an empty / unusable SearchResult is a 4xx, not a 502. The
        // consumer's own discovery criteria matched nothing, so this is its input
        // that is wrong and retrying cannot help — which is precisely what a 502
        // (a failure at or beyond the gateway, retry may help) told it instead.
        // 502 NF_DISCOVERY_FAILURE is now reserved for the NRF *erroring*.
        EndpointSelectionError::ServiceNotOffered => problem_response(
            404,
            "Not Found",
            &format!("NRF discovery returned no NF instance offering service {service}"),
            "NF_DISCOVERY_FAILURE",
        ),
        EndpointSelectionError::NoCandidate => problem_response(
            404,
            "Not Found",
            "NRF discovery returned no usable NF instance",
            "NF_DISCOVERY_FAILURE",
        ),
    }
}

/// Build the discovery-cache discriminator from the routing-relevant
/// 3gpp-Sbi-Discovery-* factors (TS 29.500 §6.10.3.2 / §6.10.3.4 NOTE 2):
/// S-NSSAI, DNN, GUAMI, TAI, target-PLMN-list and target-NF-instance-id.
/// Requests differing in any of these must not share a cached producer set, so
/// their values (empty when absent) are folded into the cache key. The unit
/// separator (0x1F) cannot appear in an HTTP header value, so it is an
/// unambiguous field delimiter.
fn discovery_cache_discriminator(http: &SbiHttpMessage) -> String {
    [
        discovery_header::SNSSAIS,
        discovery_header::DNN,
        discovery_header::GUAMI,
        discovery_header::TAI,
        discovery_header::TARGET_PLMN_LIST,
        discovery_header::TARGET_NF_INSTANCE_ID,
    ]
    .iter()
    .map(|h| http.get_header(h).map(String::as_str).unwrap_or(""))
    .collect::<Vec<_>>()
    .join("\u{1f}")
}

/// Map a delegated OAuth2 access-token acquisition failure to the mandated
/// SCP ProblemDetails (TS 29.500 §6.10.11.2.2 / §6.10.11.2.2A):
///
/// * the SCP cannot form a valid Access Token Request, or the NRF rejects it
///   with `MISSING_PARAMETER` (missing requester info) → 400 with cause
///   `MISSING_ACCESS_TOKEN_INFO`;
/// * any other NRF rejection / failure to obtain a token → 403 with cause
///   `ACCESS_TOKEN_DENIED`.
///
/// The NRF's own error body (carried in `SbiError::AuthorizationFailed`) is
/// inspected for the `MISSING_PARAMETER` OAuth2 error code to pick between them.
fn token_acquisition_failure_response(err: &SbiError) -> SbiResponse {
    let detail = err.to_string();
    if detail.to_ascii_uppercase().contains("MISSING_PARAMETER") {
        problem_response(
            400,
            "Bad Request",
            &format!("SCP could not issue the access token request: {detail}"),
            "MISSING_ACCESS_TOKEN_INFO",
        )
    } else {
        problem_response(
            403,
            "Forbidden",
            &format!("SCP could not obtain an access token for the producer: {detail}"),
            "ACCESS_TOKEN_DENIED",
        )
    }
}

/// Split an **absolute** request URI into its apiRoot and the origin-form path
/// the SCP must forward (scpd-#210).
///
/// A notification arrives addressed to the callback URI the consumer handed the
/// producer, which may be absolute. Forwarding an absolute URI as the HTTP/2
/// `:path` would be wrong, so the authority becomes the target and the remainder
/// (path plus any query, sliced from the original string so nothing is dropped)
/// becomes the forwarded URI.
///
/// The split is at the **first** `/` after the authority, so a deployment prefix
/// stays in the path rather than being parsed into `ApiRoot::prefix` — otherwise
/// `forward_once`, which prepends `target.prefix`, would emit it twice.
fn split_absolute_uri(uri: &str) -> Option<(String, String)> {
    let uri = uri.trim();
    let (scheme_len, rest) = if let Some(r) = uri.strip_prefix("http://") {
        ("http://".len(), r)
    } else if let Some(r) = uri.strip_prefix("https://") {
        ("https://".len(), r)
    } else {
        return None;
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    if authority_end == 0 {
        return None;
    }
    let api_root = uri[..scheme_len + authority_end].to_string();
    let path = if authority_end == rest.len() {
        "/".to_string()
    } else {
        rest[authority_end..].to_string()
    };
    Some((api_root, path))
}

/// How the proxy decided where to route a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteDecision {
    /// scpd-#210: `3gpp-Sbi-Callback` marks a notification/callback request
    /// (TS 29.500 §6.10.7). Routed straight to the callback URI with **no**
    /// discovery and **no** access-token acquisition.
    Callback {
        target: ApiRoot,
        /// Set when the callback URI was absolute and the forwarded URI must be
        /// rewritten to its origin form.
        forward_uri: Option<String>,
    },
    /// Model C: `3gpp-Sbi-Target-apiRoot` was present.
    TargetApiRoot(ApiRoot),
    /// §6.12 stickiness: `3gpp-Sbi-Routing-Binding` matched a cached binding.
    StickyBinding(ApiRoot),
    /// Model D: delegated discovery is required.
    Discover,
    /// Neither Target-apiRoot, usable Routing-Binding, nor Discovery headers.
    Reject,
}

/// The SCP proxy: per-request async forwarding engine.
pub struct ScpProxy {
    config: ScpProxyConfig,
    /// HTTP/2 client cache keyed by `scheme://host:port` (no OAuth2 — used for
    /// Model C / sticky-binding forwarding and NRF discovery). Bounded and
    /// TTL'd (scpd-#102) so idle producer connections are reclaimed.
    clients: BoundedCache<String, Arc<SbiClient>>,
    /// HTTP/2 client cache for OAuth2-attaching clients, keyed by
    /// `scheme://host:port|TARGET_NF_TYPE`. Used only on the Model D
    /// (delegated) path so the SCP, acting as the consumer's delegate,
    /// attaches a valid access token for the discovered producer.
    oauth_clients: BoundedCache<String, Arc<SbiClient>>,
    /// Binding stickiness cache: normalized `3gpp-Sbi-Binding` value →
    /// producer apiRoot it was returned from (TS 29.500 §6.12). Peer-influenced,
    /// so bounded and TTL'd (scpd-#102).
    bindings: BoundedCache<String, ApiRoot>,
    /// NF-set stickiness cache (scpd-11): lowercased `nfset` id → a learnt
    /// member apiRoot, so an `nf-set` Routing-Binding can reselect another set
    /// member when the originally-bound instance is gone (TS 29.500 §5.2.3.2.6).
    set_bindings: BoundedCache<String, ApiRoot>,
    /// Per-endpoint circuit breakers keyed by target authority
    /// `scheme://host:port` (scpd-#102). An Open circuit short-circuits
    /// `forward` to 503 so a flapping/down producer cannot amplify latency.
    circuit_breakers: BoundedCache<String, Arc<Mutex<CircuitBreaker>>>,
    /// Per-instance NF discovery cache (scpd-08): Model D SearchResults are
    /// cached with their `validityPeriod` TTL so repeated requests for the same
    /// target do not re-query the NRF (TS 29.500 §6.10.3). Per-instance (not the
    /// process-global cache) so each SCP — and each test — has an isolated view.
    discovery_cache: DiscoveryCache,
    /// Shared OAuth2 client (consumer-side, client-credentials grant against
    /// the NRF). `Some` only when an NRF URI is configured; `None` disables
    /// delegated token acquisition (Authorization is then left as received).
    oauth2: Option<Arc<OAuth2Client>>,
}

impl ScpProxy {
    pub fn new(config: ScpProxyConfig) -> Self {
        // The SCP is itself an OAuth2 client (NfType::Scp) when it knows its
        // NRF; tokens are acquired lazily per (target NF type, scope).
        let oauth2 = config.nrf_uri.as_deref().map(|nrf_uri| {
            let nf_instance_id = config
                .nf_instance_id
                .clone()
                .unwrap_or_else(|| DEFAULT_SCP_NF_INSTANCE_ID.to_string());
            Arc::new(OAuth2Client::new(nrf_uri, nf_instance_id, NfType::Scp))
        });
        let max = config.max_cache_entries;
        let ttl = config.cache_ttl;
        Self {
            clients: BoundedCache::new(max, ttl),
            oauth_clients: BoundedCache::new(max, ttl),
            bindings: BoundedCache::new(max, ttl),
            set_bindings: BoundedCache::new(max, ttl),
            circuit_breakers: BoundedCache::new(max, ttl),
            discovery_cache: DiscoveryCache::with_max_entries(max),
            oauth2,
            config,
        }
    }

    /// Sweep expired entries from every bounded cache. Called periodically from
    /// the SCP main loop (scpd-#102) so idle/expired entries are reclaimed
    /// without waiting for the next `insert` on that key.
    pub fn purge_expired_caches(&self) {
        self.clients.purge_expired();
        self.oauth_clients.purge_expired();
        self.bindings.purge_expired();
        self.set_bindings.purge_expired();
        self.circuit_breakers.purge_expired();
        self.discovery_cache.purge_expired();
    }

    /// Get or create the circuit breaker for a target authority key.
    fn circuit_breaker_for(&self, key: &str) -> Arc<Mutex<CircuitBreaker>> {
        if let Some(cb) = self.circuit_breakers.get(&key.to_string()) {
            return cb;
        }
        let cb = Arc::new(Mutex::new(CircuitBreaker::new(
            self.config.circuit_failure_threshold,
            self.config.circuit_open_timeout,
        )));
        self.circuit_breakers.insert(key.to_string(), cb.clone());
        cb
    }

    /// Whether the circuit for `target_key` admits a request. In Open this
    /// transitions to HalfOpen once the open timeout has elapsed. The breaker
    /// lock is taken and released here — never held across the forward await.
    fn circuit_allows(&self, target_key: &str) -> bool {
        let cb = self.circuit_breaker_for(target_key);
        let mut guard = cb.lock().unwrap_or_else(|p| p.into_inner());
        guard.allow_request()
    }

    /// Record the outcome of a forward against `target_key`'s circuit breaker.
    fn circuit_record(&self, target_key: &str, success: bool) {
        let cb = self.circuit_breaker_for(target_key);
        let mut guard = cb.lock().unwrap_or_else(|p| p.into_inner());
        if success {
            guard.record_success();
        } else {
            guard.record_failure();
        }
    }

    /// The SCP's own `Via`/`Server` identity token `SCP-<own-fqdn>`
    /// (TS 29.500 §6.10.8.2/§6.10.8.3/§6.10.10.3).
    fn scp_node_id(&self) -> String {
        format!("SCP-{}", self.config.own_fqdn)
    }

    /// Stamp the `Server` header with this SCP's identity on an SCP-originated
    /// error response (TS 29.500 §6.10.8.2). Never applied to relayed producer
    /// responses (those keep the producer's `Server`).
    fn stamp_server(&self, mut response: SbiResponse) -> SbiResponse {
        response.http.set_header(SERVER_HEADER, self.scp_node_id());
        response
    }

    /// Append this SCP's `Via` entry (`2.0 SCP-<fqdn>`) to an existing Via list,
    /// preserving any upstream tokens (comma-separated, RFC 9110 §7.6.3).
    fn append_via(&self, http: &mut SbiHttpMessage) {
        let entry = format!("2.0 {}", self.scp_node_id());
        let value = match http.get_header(VIA_HEADER) {
            Some(existing) if !existing.trim().is_empty() => format!("{existing}, {entry}"),
            _ => entry,
        };
        http.set_header(VIA_HEADER, value);
    }

    /// Like [`append_via`](Self::append_via) but on a bare forwardable-request
    /// header map.
    fn append_request_via(&self, headers: &mut HashMap<String, String>) {
        let entry = format!("2.0 {}", self.scp_node_id());
        let value = match header_get(headers, VIA_HEADER) {
            Some(existing) if !existing.trim().is_empty() => format!("{existing}, {entry}"),
            _ => entry,
        };
        header_set(headers, VIA_HEADER, value);
    }

    /// True when a received `Via` header lists this SCP's own identity
    /// (`SCP-<fqdn>`), indicating the request has already transited this SCP
    /// (TS 29.500 §6.10.10.3). `Via` is a comma-separated list of
    /// `received-protocol received-by [comment]` elements (RFC 9110 §7.6.3);
    /// loop detection is defined over those discrete tokens, NOT over a
    /// substring of the concatenated value. Each element is split on whitespace
    /// (a trailing `(comment)` dropped) and every token compared for exact
    /// case-insensitive equality — so a peer token that merely *contains* this
    /// SCP's identity as a substring (e.g. `SCP-scp.5gc.local2` vs
    /// `SCP-scp.5gc.local`) does not raise a false `MSG_LOOP_DETECTED`.
    fn via_lists_self(&self, via: &str) -> bool {
        let self_token = self.scp_node_id();
        via.split(',').any(|element| {
            let element = element.split('(').next().unwrap_or(element);
            element
                .split_whitespace()
                .any(|tok| tok.eq_ignore_ascii_case(&self_token))
        })
    }

    /// scpd-04: ingress loop / hop-exhaustion guard (TS 29.500 §6.10.10).
    /// Returns a Server-stamped error when the request must be rejected:
    /// - own `SCP-<FQDN>` already present in a received `Via` → 400
    ///   `MSG_LOOP_DETECTED` (§6.10.10.3);
    /// - an scp-typed `3gpp-Sbi-Max-Forward-Hops` of `0` → 502
    ///   `MAX_SCP_HOPS_REACHED` (§6.10.10.2).
    ///
    /// A normal single-hop request (no `Via`, no hop header) is never blocked.
    fn ingress_guard(&self, request: &SbiRequest) -> Option<SbiResponse> {
        if let Some(via) = request.http.get_header(VIA_HEADER) {
            if self.via_lists_self(via) {
                return Some(self.stamp_server(problem_response(
                    400,
                    "Bad Request",
                    "Request looped back to this SCP (own identity present in Via header)",
                    "MSG_LOOP_DETECTED",
                )));
            }
        }
        if let Some(mfh) = request.http.get_header(MAX_FORWARD_HOPS_HEADER) {
            if let Some((count, nodetype)) = parse_max_forward_hops(mfh) {
                let applies = nodetype
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case("scp"))
                    .unwrap_or(true);
                if applies && count == 0 {
                    return Some(self.stamp_server(problem_response(
                        502,
                        "Bad Gateway",
                        "Maximum number of SCP hops reached",
                        "MAX_SCP_HOPS_REACHED",
                    )));
                }
            }
        }
        None
    }

    /// scpd-04: on a forwarded request, decrement an scp-typed
    /// `3gpp-Sbi-Max-Forward-Hops` (only when present — never added when absent,
    /// to keep the single-hop wire unchanged) and insert this SCP's `Via`.
    fn apply_forward_loop_headers(&self, headers: &mut HashMap<String, String>) {
        if let Some(mfh) = header_get(headers, MAX_FORWARD_HOPS_HEADER).cloned() {
            if let Some((count, nodetype)) = parse_max_forward_hops(&mfh) {
                let applies = nodetype
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case("scp"))
                    .unwrap_or(true);
                if applies {
                    let dec = count.saturating_sub(1);
                    let nt = nodetype.unwrap_or_else(|| "scp".to_string());
                    header_set(
                        headers,
                        MAX_FORWARD_HOPS_HEADER,
                        format!("{dec}; nodetype={nt}"),
                    );
                }
            }
        }
        self.append_request_via(headers);
    }

    /// Look up a producer apiRoot previously learnt from a
    /// `3gpp-Sbi-Binding` response header.
    pub fn binding_lookup(&self, routing_binding: &str) -> Option<ApiRoot> {
        self.bindings.get(&normalize_binding(routing_binding))
    }

    /// Record a `3gpp-Sbi-Binding` value from a producer response so later
    /// requests carrying it in `3gpp-Sbi-Routing-Binding` stick to the same
    /// producer. When the binding names an `nfset`, the target is also indexed
    /// at the set level (scpd-11) so an `nf-set` Routing-Binding can reselect a
    /// set member after the originally-bound instance is gone.
    pub fn binding_store(&self, binding: &str, target: &ApiRoot) {
        self.bindings
            .insert(normalize_binding(binding), target.clone());
        if let Some(set) = ParsedBinding::parse(binding).nfset {
            self.set_bindings
                .insert(set.to_ascii_lowercase(), target.clone());
        }
    }

    /// Resolve a `3gpp-Sbi-Routing-Binding` to a cached producer, first by exact
    /// (normalized) match, then — for an `nf-set` binding — by reselecting a
    /// learnt member of the named set (scpd-11, TS 29.500 §5.2.3.2.6).
    fn binding_lookup_setaware(&self, routing_binding: &str) -> Option<ApiRoot> {
        if let Some(target) = self.binding_lookup(routing_binding) {
            return Some(target);
        }
        let parsed = ParsedBinding::parse(routing_binding);
        if parsed.is_set_level() {
            if let Some(set) = parsed.nfset {
                return self.set_bindings.get(&set.to_ascii_lowercase());
            }
        }
        None
    }

    /// Get or create a pooled HTTP/2 client for a target authority.
    fn client_for(&self, target: &ApiRoot) -> Arc<SbiClient> {
        let key = format!("{}://{}:{}", target.scheme, target.host, target.port);
        if let Some(client) = self.clients.get(&key) {
            return client;
        }
        let mut config = SbiClientConfig::new(target.host.clone(), target.port)
            .with_connect_timeout(self.config.connect_timeout)
            .with_request_timeout(self.config.request_timeout);
        config.scheme = target.scheme;
        let client = Arc::new(SbiClient::new(config));
        self.clients.insert(key, client.clone());
        client
    }

    /// Get or create a pooled HTTP/2 client that automatically attaches a
    /// delegated OAuth2 Bearer token for `target_nf_type` (TS 33.501 §13;
    /// TS 29.510 client-credentials grant). Returns `None` when the SCP has no
    /// OAuth2 client configured (no NRF), in which case the caller forwards
    /// without minting a token.
    ///
    /// The token is acquired by L1 (`SbiClient` + `OAuth2Client`) on send: it
    /// derives the scope from the request URI's service name and only attaches
    /// a token when the request carries no `Authorization` header — so the
    /// Model D path strips the consumer's opaque Authorization first.
    fn oauth_client_for(&self, target: &ApiRoot, target_nf_type: NfType) -> Option<Arc<SbiClient>> {
        let oauth2 = self.oauth2.clone()?;
        let key = format!(
            "{}://{}:{}|{}",
            target.scheme,
            target.host,
            target.port,
            target_nf_type.to_str()
        );
        if let Some(client) = self.oauth_clients.get(&key) {
            return Some(client);
        }
        let mut config = SbiClientConfig::new(target.host.clone(), target.port)
            .with_connect_timeout(self.config.connect_timeout)
            .with_request_timeout(self.config.request_timeout);
        config.scheme = target.scheme;
        let client = Arc::new(SbiClient::new(config).with_oauth2(oauth2, target_nf_type));
        self.oauth_clients.insert(key, client.clone());
        Some(client)
    }

    /// Resolve whose identity a delegated token request should assert
    /// (nextgcore #101 criterion 2, TS 33.501 §13.4.1.3.2).
    ///
    /// The governing rule is **never assert an identity you cannot attest**.
    /// Sending the consumer's `nfInstanceId` unconditionally would break the
    /// delegated path outright against our own NRF: after #64 that token
    /// endpoint requires a CCA keyed to the `nfInstanceId` in the body, and the
    /// SCP can only sign with its own key. Consumer identity and an
    /// SCP-signed CCA are therefore mutually exclusive, which is why a bare
    /// feature flag would just turn delegated discovery off.
    ///
    /// So, in order:
    ///
    /// 1. the consumer conveyed its own CCA in `3gpp-Sbi-Client-Credentials`
    ///    → assert the consumer's identity and forward that CCA, which the NRF
    ///    verifies against the consumer's registered key. This is the
    ///    conformant Model D case;
    /// 2. no consumer CCA, but the operator set `trust_requester_identity` for
    ///    an NRF that does not require client authentication → assert the
    ///    consumer's identity with no assertion attached;
    /// 3. otherwise → keep the SCP's own identity and log, so the token is
    ///    honestly SCP-attested rather than a forgery of the consumer's.
    ///
    /// Note the asymmetry with discovery: `requester-nf-type` is mandatory for
    /// delegated discovery (rejected with 400 in [`ScpProxy::discover`]) but
    /// `requester-nf-instance-id` is optional, so a consumer can be typed
    /// without being named. An unnamed consumer cannot be asserted at all, and
    /// falls to case 3 regardless of the other inputs.
    fn delegated_auth(&self, request: &SbiRequest, target_nf_type: NfType) -> DelegatedAuth {
        let requested_scope = request
            .http
            .get_header(custom_header::ACCESS_SCOPE)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let scp_consumer = || {
            self.oauth2
                .as_ref()
                .map(|o| o.self_consumer())
                .unwrap_or_else(|| {
                    TokenConsumer::new(
                        self.config
                            .nf_instance_id
                            .clone()
                            .unwrap_or_else(|| DEFAULT_SCP_NF_INSTANCE_ID.to_string()),
                        NfType::Scp,
                    )
                })
        };

        // The consumer must be both named and typed before it can be asserted.
        let requester = request
            .http
            .get_header(discovery_header::REQUESTER_NF_INSTANCE_ID)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .and_then(|id| {
                request
                    .http
                    .get_header(discovery_header::REQUESTER_NF_TYPE)
                    .and_then(|t| nf_type_from_str(t))
                    .map(|nf_type| (id.to_string(), nf_type))
            });

        let consumer_cca = request
            .http
            .get_header(custom_header::CLIENT_CREDENTIALS)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        match requester {
            Some((id, nf_type)) => match consumer_cca {
                // Case 1: attested by the consumer itself.
                Some(cca) => DelegatedAuth {
                    target_nf_type,
                    consumer: TokenConsumer::new(id, nf_type).with_cca(cca),
                    requested_scope,
                    consumer_attested: true,
                },
                // Case 2: attested by operator declaration.
                None if self.config.trust_requester_identity => DelegatedAuth {
                    target_nf_type,
                    consumer: TokenConsumer::new(id, nf_type),
                    requested_scope,
                    consumer_attested: true,
                },
                // Case 3: not attestable — stay honest about who we are.
                None => {
                    log::debug!(
                        "SCP Model D: consumer {id} sent no 3gpp-Sbi-Client-Credentials and \
                         trust_requester_identity is off; requesting an SCP-attested token \
                         instead of asserting an identity we cannot attest"
                    );
                    DelegatedAuth {
                        target_nf_type,
                        consumer: scp_consumer(),
                        requested_scope,
                        consumer_attested: false,
                    }
                }
            },
            None => DelegatedAuth {
                target_nf_type,
                consumer: scp_consumer(),
                requested_scope,
                consumer_attested: false,
            },
        }
    }

    /// Decide how to route an incoming request (TS 29.500 §6.10.2):
    /// a `3gpp-Sbi-Callback` notification first; then Target-apiRoot; otherwise a
    /// Routing-Binding that matches a cached Binding; otherwise delegated
    /// discovery when Discovery headers are present; otherwise the request is
    /// malformed.
    ///
    /// **Precedence of `3gpp-Sbi-Callback`** (scpd-#210, TS 29.500 §6.10.7). It is
    /// checked **first**, and it is not in competition with `Target-apiRoot`: the
    /// callback header decides the *mode* (no discovery, no token) while
    /// `Target-apiRoot` supplies the *address*, so a callback carrying one is
    /// routed there. With no `Target-apiRoot`, the address comes from an absolute
    /// request URI — the normal callback case, since the callback URI is already
    /// known and needs no discovery.
    ///
    /// It outranks `Routing-Binding` and the `Discovery-*` headers because a
    /// notification's destination is fixed by the consumer that registered the
    /// callback; discovering a producer for it would address the wrong node
    /// entirely, and minting a token for a discovered producer is an NRF
    /// round-trip for a credential the callback target never asked for.
    ///
    /// If the header is present but **no** callback URI can be determined (no
    /// `Target-apiRoot`, relative request URI), the marker is logged and ignored
    /// and routing falls through to the ordinary precedence. Rejecting instead
    /// would regress a deployment whose callbacks currently reach their target via
    /// the Discovery headers — badly, but successfully.
    fn route(&self, request: &SbiRequest) -> RouteDecision {
        if request.http.get_header(custom_header::CALLBACK).is_some() {
            match self.callback_target(request) {
                Some((target, forward_uri)) => {
                    return RouteDecision::Callback {
                        target,
                        forward_uri,
                    }
                }
                None => log::warn!(
                    "SCP: request carries {} but names no callback URI (no {} and a relative \
                     request URI); ignoring the marker and routing normally",
                    custom_header::CALLBACK,
                    custom_header::TARGET_APIROOT
                ),
            }
        }

        if let Some(api_root) = request.http.target_apiroot() {
            return match ApiRoot::parse(api_root) {
                Ok(target) => RouteDecision::TargetApiRoot(target),
                Err(_) => RouteDecision::Reject,
            };
        }

        if let Some(routing_binding) = request.http.routing_binding() {
            if let Some(target) = self.binding_lookup_setaware(routing_binding) {
                return RouteDecision::StickyBinding(target);
            }
        }

        let has_discovery = request.http.headers.keys().any(|k| {
            k.get(..discovery_header::PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(discovery_header::PREFIX))
        });
        if has_discovery {
            RouteDecision::Discover
        } else {
            RouteDecision::Reject
        }
    }

    /// Resolve where a `3gpp-Sbi-Callback` request should go (scpd-#210): the
    /// `3gpp-Sbi-Target-apiRoot` when the producer supplied one, otherwise the
    /// authority of an absolute request URI. Returns the target and, for the
    /// absolute case, the origin-form URI to forward.
    ///
    /// **In practice `Target-apiRoot` is the only conveyance that survives the
    /// wire.** The shared SBI server records only the path
    /// (`libs/nextgcore-sbi/src/server.rs:563`, `req.uri().path()`), and over
    /// HTTP/2 the authority is the SCP's own, so a producer sending a notification
    /// *through* this SCP must name the callback apiRoot in the header — which is
    /// the same convention Model C already uses. The absolute-URI arm is retained
    /// for in-process callers of the public [`ScpProxy::handle`] and would become
    /// wire-reachable if the ingress ever preserved the authority; it is not
    /// claimed as wire behaviour, and its test says so.
    fn callback_target(&self, request: &SbiRequest) -> Option<(ApiRoot, Option<String>)> {
        if let Some(api_root) = request.http.target_apiroot() {
            // A malformed Target-apiRoot is NOT silently ignored in favour of the
            // request URI: the producer named a destination and got it wrong, and
            // quietly routing somewhere else would hide that.
            return ApiRoot::parse(api_root).ok().map(|t| (t, None));
        }
        let (api_root, path) = split_absolute_uri(&request.header.uri)?;
        ApiRoot::parse(&api_root).ok().map(|t| (t, Some(path)))
    }

    /// Model D delegated discovery (TS 29.500 §6.10.3, TS 29.510 §5.3.2):
    /// query the NRF's `nnrf-disc` service with the parameters carried in
    /// the `3gpp-Sbi-Discovery-*` request headers, parse the SearchResult,
    /// and select a producer. The requester identity comes from
    /// `3gpp-Sbi-Discovery-requester-nf-type` (NOT User-Agent).
    ///
    /// Returns the selected producer **and the ordered alternates** (scpd-#209),
    /// so a forward that never reached the selected one can fail over instead of
    /// discarding a candidate set the SCP already holds.
    async fn discover(&self, request: &SbiRequest) -> Result<DiscoveryOutcome, SbiResponse> {
        let target_nf_type = request
            .http
            .get_header(discovery_header::TARGET_NF_TYPE)
            .cloned()
            .ok_or_else(|| {
                problem_response(
                    400,
                    "Bad Request",
                    "3gpp-Sbi-Discovery-target-nf-type header is required for delegated discovery",
                    "MANDATORY_IE_MISSING",
                )
            })?;
        let requester_nf_type = request
            .http
            .get_header(discovery_header::REQUESTER_NF_TYPE)
            .cloned()
            .ok_or_else(|| {
                problem_response(
                    400,
                    "Bad Request",
                    "3gpp-Sbi-Discovery-requester-nf-type header is required for delegated discovery",
                    "MANDATORY_IE_MISSING",
                )
            })?;

        // scpd-08: serve un-expired SearchResults from the per-instance cache,
        // keyed on (target-nf-type, service-names, discriminator) without
        // re-querying the NRF. The discriminator folds in every routing-relevant
        // Discovery-* factor (TS 29.500 §6.10.3.2 / §6.10.3.4 NOTE 2) so a
        // different slice / DNN / area / pinned instance never reuses another
        // request's cached producer set.
        let service_key = request
            .http
            .get_header(discovery_header::SERVICE_NAMES)
            .cloned()
            .unwrap_or_default();
        let cache_discriminator = discovery_cache_discriminator(&request.http);

        // scpd-#207: the endpoint is selected by matching the requested service
        // name AND the API major version in the URI, and taken from the matching
        // `NFService` (TS 29.510 §6.2.6.2) — not from `nfServices[0]`.
        let (requested_service, requested_version) = requested_service_and_version(request);
        if let Some(cached) =
            self.discovery_cache
                .get(&target_nf_type, &service_key, &cache_discriminator)
        {
            if let Ok(ranked) = rank_nf_service_endpoints(
                &cached,
                requested_service.as_deref(),
                requested_version.as_deref(),
            ) {
                // scpd-#209: the cached set supplies alternates too, so a producer
                // that restarted since the SearchResult was cached is exactly the
                // case failover exists for.
                //
                // scpd-#208: nf_set_id / nf_group_id come off the CANDIDATE, so
                // this arm and the fresh-query arm below build an identical
                // DiscoveredProducer. They used to differ — the fresh path read
                // them from the raw SearchResult and this one had nothing to read,
                // so it hardcoded None and the consumer's Producer-Id silently
                // lost its `nfset=` on every cache hit.
                let mut producers = ranked.into_iter().map(|selected| DiscoveredProducer {
                    target: ApiRoot {
                        scheme: selected.scheme,
                        host: selected.candidate.host.clone(),
                        port: selected.port,
                        prefix: selected.prefix,
                    },
                    nf_instance_id: selected.candidate.nf_instance_id.clone(),
                    nf_set_id: selected.candidate.nf_set_id.clone(),
                    nf_group_id: selected.candidate.nf_group_id.clone(),
                });
                if let Some(primary) = producers.next() {
                    return Ok(DiscoveryOutcome {
                        primary,
                        alternates: producers.collect(),
                    });
                }
            }
            // A cached set that cannot serve THIS request falls through to a
            // fresh NRF query rather than erroring from stale data: the cache TTL
            // is the SearchResult's `validityPeriod` (up to an hour), and a
            // producer offering the requested service/version may have registered
            // since. The error, if any, is then raised against current data.
        }

        let nrf_uri = self.config.nrf_uri.as_deref().ok_or_else(|| {
            problem_response(
                503,
                "Service Unavailable",
                "SCP has no NRF configured for delegated discovery",
                "NRF_NOT_AVAILABLE",
            )
        })?;
        let nrf = ApiRoot::parse(nrf_uri).map_err(|e| {
            problem_response(
                503,
                "Service Unavailable",
                &format!("SCP NRF URI is invalid: {e}"),
                "NRF_NOT_AVAILABLE",
            )
        })?;

        let mut disc = SbiRequest::get(format!("{}/nnrf-disc/v1/nf-instances", nrf.prefix))
            .with_param("target-nf-type", target_nf_type.clone())
            .with_param("requester-nf-type", requester_nf_type);
        // scpd-06: forward every other 3gpp-Sbi-Discovery-* factor the consumer
        // conveyed as its corresponding nnrf-disc query parameter
        // (TS 29.500 §6.10.3.2 ↔ TS 29.510 §6.2.3.2.3).
        for (name, value) in &request.http.headers {
            if let Some(param) = nnrf_disc_param_from_discovery_header(name) {
                disc = disc.with_param(param, value.clone());
            }
        }

        // scpd-#211: an NRF that cannot be reached is reported as the NRF, not as
        // the target NF (TS 29.500 §6.10.8.2).
        let response = self
            .client_for(&nrf)
            .send_request(disc)
            .await
            .map_err(|e| nrf_unreachable_response(&nrf.to_uri(), &e))?;

        // scpd-#211: the NRF answered, and answered badly — an infrastructure
        // fault at the gateway's upstream, which is what 502 means. This is the
        // ONE condition that keeps 502 NF_DISCOVERY_FAILURE; the empty-result case
        // moved to 404 and the unreachable case to 504.
        if response.status != 200 {
            return Err(problem_response(
                502,
                "Bad Gateway",
                &format!("NRF discovery failed with status {}", response.status),
                "NF_DISCOVERY_FAILURE",
            ));
        }

        let body = response.http.content.as_deref().unwrap_or("");
        let value: serde_json::Value =
            serde_json::from_slice(body.as_bytes()).unwrap_or(serde_json::Value::Null);
        let candidates = parse_search_result(body.as_bytes());

        // scpd-08: cache the parsed candidates with the SearchResult
        // `validityPeriod` (seconds) as TTL (default 3600 when absent). Cached
        // BEFORE selection (scpd-#207): the cache holds what the NRF answered,
        // which is still valid for other requests even when it cannot serve this
        // one's API version.
        if !candidates.is_empty() {
            let validity = value
                .get("validityPeriod")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600);
            self.discovery_cache.put(
                &target_nf_type,
                &service_key,
                &cache_discriminator,
                candidates.clone(),
                Duration::from_secs(validity),
            );
        }

        // scpd-#209: the whole ranked set, not just the head. Every entry is
        // resolved here so the failover path holds no reference back into the
        // SearchResult.
        let ranked = rank_nf_service_endpoints(
            &candidates,
            requested_service.as_deref(),
            requested_version.as_deref(),
        )
        .map_err(|e| {
            endpoint_selection_error_response(
                e,
                requested_service.as_deref(),
                requested_version.as_deref(),
            )
        })?;

        let mut producers = ranked.into_iter().map(|selected| {
            // Build the producer ApiRoot from the NF profile fields parsed out of
            // the SearchResult: scheme, port and prefix come from the MATCHED
            // `nfServices` entry (scpd-#207); host is ipv4→fqdn→ipv6(bracketed).
            // `client_for`/`oauth_client_for` already honour the scheme field, so
            // an `https` producer is now contacted over TLS automatically.
            DiscoveredProducer {
                target: ApiRoot {
                    scheme: selected.scheme,
                    host: selected.candidate.host.clone(),
                    port: selected.port,
                    prefix: selected.prefix,
                },
                nf_instance_id: selected.candidate.nf_instance_id.clone(),
                // scpd-02/scpd-12/#208: each producer's own set id / group id,
                // parsed onto the candidate so a CACHE HIT reports the same
                // identifiers as the miss that populated it.
                nf_set_id: selected.candidate.nf_set_id.clone(),
                nf_group_id: selected.candidate.nf_group_id.clone(),
            }
        });
        let primary = producers.next().ok_or_else(|| {
            endpoint_selection_error_response(
                EndpointSelectionError::NoCandidate,
                requested_service.as_deref(),
                requested_version.as_deref(),
            )
        })?;
        Ok(DiscoveryOutcome {
            primary,
            alternates: producers.collect(),
        })
    }

    /// Forward a request to the selected producer and relay its response.
    ///
    /// Success and error (4xx/5xx) producer responses are both relayed
    /// verbatim — status, end-to-end headers, and body — so upstream
    /// ProblemDetails bodies reach the consumer unmodified. Only transport
    /// failures synthesize a 502/504 at the SCP.
    ///
    /// `delegated_nf_type` is `Some` only on the Model D (delegated discovery)
    /// path: the SCP then acts as the consumer's delegate and acquires a valid
    /// OAuth2 access token for the discovered producer (TS 33.501 §13). Model C
    /// and binding-stickiness forwarding leave any `Authorization` header
    /// untouched (the consumer remains the OAuth2 client).
    async fn forward(
        &self,
        request: &SbiRequest,
        target: &ApiRoot,
        relay: RelayContext<'_>,
        delegated: Option<DelegatedAuth>,
    ) -> SbiResponse {
        match self.forward_once(request, target, relay, delegated).await {
            ForwardOutcome::Answered(response) | ForwardOutcome::Final(response) => response,
            // A single pinned target has no alternates, so "undeliverable" is the
            // final answer here and keeps its pre-#209 mapping exactly.
            ForwardOutcome::Undeliverable(u) => self.stamp_server(self.undeliverable_response(&u)),
        }
    }

    /// The single-target error response for an undelivered forward: the
    /// pre-scpd-#209 mapping, unchanged — `503` when our own circuit breaker shed
    /// the request, otherwise the `502`/`504` `TARGET_NF_NOT_REACHABLE` of
    /// [`upstream_error_response`].
    fn undeliverable_response(&self, u: &Undeliverable) -> SbiResponse {
        match &u.error {
            Some(err) => upstream_error_response(&u.target, err),
            None => problem_response(
                503,
                "Service Unavailable",
                &format!(
                    "SCP circuit breaker is open for {} (recent failures)",
                    u.target
                ),
                "TARGET_NF_NOT_REACHABLE",
            ),
        }
    }

    /// scpd-#208: on a 2xx carrying a **relative** `Location` after the SCP
    /// retargeted the request, convey the producer's apiRoot in
    /// `3gpp-Sbi-Target-apiRoot` (TS 29.500 §6.10.4).
    ///
    /// **§6.10.4 permits either adding `3gpp-Sbi-Target-apiRoot` or absolutising
    /// the `Location`. This SCP adds the header**, for three reasons:
    ///
    /// 1. It is **additive**. Absolutising rewrites a header the producer set,
    ///    destroying what it said; adding leaves the producer's `Location` intact
    ///    so a consumer that does not understand the fix-up is no worse off.
    /// 2. It keeps the follow-up request flowing **through the SCP**. An absolute
    ///    `Location` pointing at the producer invites the consumer to address it
    ///    directly, which silently abandons the binding stickiness, producer
    ///    selection and delegated token acquisition the SCP exists to provide.
    /// 3. It round-trips through code that already exists: `route()` reads
    ///    `3gpp-Sbi-Target-apiRoot` on a request, so a consumer echoing this value
    ///    back with the relative `Location` path takes the Model C path to the
    ///    same producer with no new handling. That is testable end to end, which
    ///    an absolute `Location` is not — nothing in this tree would consume it.
    ///
    /// Narrow by design: an **absolute** `Location` is already addressable, so it
    /// is left alone rather than annotated, and a 2xx with no `Location` gets
    /// nothing because there is no resource URI to follow up on.
    fn add_target_apiroot_for_location(&self, relayed: &mut SbiResponse, target: &ApiRoot) {
        let Some(location) = relayed.http.get_header("Location") else {
            return;
        };
        let location = location.trim();
        if location.is_empty()
            || location.starts_with("http://")
            || location.starts_with("https://")
        {
            return;
        }
        let api_root = target.to_uri();
        log::debug!(
            "SCP relay: relative Location {location} after retargeting; conveying producer \
             apiRoot {api_root} in {}",
            custom_header::TARGET_APIROOT
        );
        relayed
            .http
            .set_header(custom_header::TARGET_APIROOT, api_root);
    }

    /// Forward to exactly **one** producer, reporting whether the request was
    /// delivered (scpd-#209). See [`ForwardOutcome`]; callers with alternates use
    /// [`Self::forward_with_reselection`], callers without use [`Self::forward`].
    async fn forward_once(
        &self,
        request: &SbiRequest,
        target: &ApiRoot,
        relay: RelayContext<'_>,
        delegated: Option<DelegatedAuth>,
    ) -> ForwardOutcome {
        // scpd-#102: consult this producer's circuit breaker before forwarding.
        // An Open circuit short-circuits without contacting the producer, so a
        // flapping/down backend cannot amplify latency across consumers.
        //
        // scpd-#209: this is reported as Undeliverable rather than as a finished
        // 503, so the Model D path can try a DIFFERENT producer. That is the exact
        // gap #209 names: the breaker stopped us hammering a dead producer but did
        // not send us to a live one, so the first request after the circuit opened
        // still failed.
        let target_key = format!("{}://{}:{}", target.scheme, target.host, target.port);
        if !self.circuit_allows(&target_key) {
            return ForwardOutcome::Undeliverable(Undeliverable {
                target: target.to_uri(),
                error: None,
            });
        }

        let mut fwd = SbiRequest::default();
        fwd.header.method = request.header.method.clone();
        fwd.header.uri = format!("{}{}", target.prefix, request.header.uri);
        fwd.http.params = request.http.params.clone();
        // scpd-05: never leak the SCP cache-key (`ck`) or any other SCP-internal
        // query parameter to the producer (TS 29.500 §6.10.2.6).
        fwd.http.params.retain(|k, _| !is_scp_internal_param(k));
        fwd.http.headers = forwardable_request_headers(&request.http.headers);
        fwd.http.content = request.http.content.clone();
        fwd.http.parts = request.http.parts.clone();

        // scpd-04: loop protection — decrement an scp-typed Max-Forward-Hops and
        // insert this SCP's Via on the forwarded request (TS 29.500 §6.10.10).
        self.apply_forward_loop_headers(&mut fwd.http.headers);

        // scpd-10: when the next hop is another SCP, convey the selected
        // producer apiRoot in 3gpp-Sbi-Target-apiRoot instead of stripping it
        // (TS 29.500 §6.10.2.5). Default deployment (next hop = producer) strips.
        if self.config.next_hop_scp {
            header_set(
                &mut fwd.http.headers,
                custom_header::TARGET_APIROOT,
                target.to_uri(),
            );
        }

        // Model D: if the SCP can mint a delegated token, drop whatever
        // Authorization the consumer sent (it was scoped to the consumer, not
        // to this producer) so the delegated Bearer token replaces it. If no
        // OAuth2 client is configured, fall back to forwarding the request
        // as-is (Authorization, if any, passes through).
        let (client, delegated) = match delegated
            .as_ref()
            .and_then(|d| self.oauth_client_for(target, d.target_nf_type))
        {
            Some(oauth_client) => {
                strip_authorization(&mut fwd.http.headers);
                (oauth_client, delegated)
            }
            None => (self.client_for(target), None),
        };

        // The consumer's CCA authenticates it to the NRF's token endpoint; it is
        // not a producer-facing credential and must not travel onward
        // (TS 29.500 §5.2.3.2: it is consumed by the token request we make on
        // the consumer's behalf, below).
        fwd.http
            .headers
            .retain(|k, _| !k.eq_ignore_ascii_case(custom_header::CLIENT_CREDENTIALS));

        // scpd: on the Model D delegated path the SCP must obtain a valid OAuth2
        // access token for the producer *before* forwarding (TS 33.501 §13). If
        // the token cannot be acquired — the NRF rejects the Access Token Request
        // or is unreachable — surface the mandated 400 MISSING_ACCESS_TOKEN_INFO /
        // 403 ACCESS_TOKEN_DENIED ProblemDetails instead of silently forwarding
        // tokenless (TS 29.500 §6.10.11.2.2 / §6.10.11.2.2A).
        //
        // #101 criterion 2: the token is minted for the CONSUMER, so this path
        // attaches the Bearer header ITSELF rather than leaving it to L1.
        // `SbiClient::with_oauth2` has no per-request hook — it would re-derive
        // the token from the SCP's own identity — but it only attaches when the
        // request carries no `Authorization`, so setting the header here makes
        // its attach step a no-op by construction rather than by ordering luck.
        //
        // A no-scope request (no service name and no Access-Scope) needs no token.
        let token_scope = delegated.as_ref().map(|d| {
            d.requested_scope.clone().unwrap_or_else(|| {
                UriComponents::parse(&request.header.uri)
                    .api_name
                    .unwrap_or_default()
            })
        });

        // scpd-07: keep a pristine (pre-token) copy for a single refresh-and-
        // retry on a delegated 401/403 Bearer challenge. Cloned BEFORE the
        // Bearer header is set, so the retry cannot replay the token the
        // producer just refused.
        let retry_fwd = if delegated.is_some() {
            Some(fwd.clone())
        } else {
            None
        };

        if let (Some(oauth2), Some(d), Some(scope)) = (
            self.oauth2.as_ref(),
            delegated.as_ref(),
            token_scope.as_ref(),
        ) {
            if !scope.is_empty() {
                match oauth2
                    .get_token_on_behalf_of(&d.consumer, d.target_nf_type, scope)
                    .await
                {
                    Ok(token) => {
                        fwd.http
                            .set_header("Authorization", format!("Bearer {token}"));
                        if !d.consumer_attested {
                            log::debug!(
                                "SCP Model D: forwarding an SCP-attested token for scope {scope}"
                            );
                        }
                    }
                    Err(e) => {
                        // scpd-#209: Final, not Undeliverable. The token is minted
                        // for (consumer, target NF TYPE, scope), so every instance
                        // of that type would get the same refusal — reselecting
                        // would just repeat the NRF round-trip.
                        return ForwardOutcome::Final(
                            self.stamp_server(token_acquisition_failure_response(&e)),
                        );
                    }
                }
            }
        }

        let mut upstream = match client.send_request(fwd).await {
            Ok(response) => response,
            Err(e) => {
                // scpd-#102: a transport failure (connect refused / timeout) is
                // a circuit failure.
                self.circuit_record(&target_key, false);
                // scpd-#209: only a provably-undelivered failure may be replayed
                // on another producer; see `is_provably_undelivered`.
                return if is_provably_undelivered(&e) {
                    ForwardOutcome::Undeliverable(Undeliverable {
                        target: target.to_uri(),
                        error: Some(e),
                    })
                } else {
                    ForwardOutcome::Final(
                        self.stamp_server(upstream_error_response(&target.to_uri(), &e)),
                    )
                };
            }
        };

        // scpd-07: on a delegated forward that the producer rejects with
        // 401/403 + a Bearer `WWW-Authenticate`, the cached token was refused —
        // invalidate it, mint a fresh one, and retry exactly once
        // (TS 29.500 §6.10.11.2.3). If it still fails, the response is relayed.
        if delegated.is_some()
            && matches!(upstream.status, 401 | 403)
            && www_authenticate_is_bearer(&upstream)
        {
            if let (Some(oauth2), Some(d), Some(scope), Some(mut retry)) = (
                self.oauth2.as_ref(),
                delegated.as_ref(),
                token_scope.as_ref(),
                retry_fwd,
            ) {
                // #101 criterion 4: evict only THIS consumer's token. The
                // producer refused a token minted for this consumer, which says
                // nothing about any other consumer's — and clearing the whole
                // cache would make one consumer's 401 re-mint the entire
                // fleet's tokens.
                oauth2
                    .invalidate_token(&d.consumer, d.target_nf_type, scope)
                    .await;
                if !scope.is_empty() {
                    if let Ok(token) = oauth2
                        .get_token_on_behalf_of(&d.consumer, d.target_nf_type, scope)
                        .await
                    {
                        retry
                            .http
                            .set_header("Authorization", format!("Bearer {token}"));
                    }
                }
                if let Ok(retried) = client.send_request(retry).await {
                    upstream = retried;
                }
            }
        }

        // scpd-#102: record the forward outcome against the circuit breaker.
        // A producer 5xx counts as a failure (the backend is unhealthy); a 4xx
        // is a client error, so the producer is up and it counts as a success.
        self.circuit_record(&target_key, upstream.status < 500);

        // §6.12: learn the producer's Binding for later Routing-Binding
        // stickiness, and still relay the header to the consumer.
        if let Some(binding) = upstream.http.binding() {
            self.binding_store(binding, target);
        }

        let mut relayed = SbiResponse::with_status(upstream.status);
        relayed.http.headers = relayable_response_headers(&upstream.http.headers);
        relayed.http.content = upstream.http.content.clone();
        relayed.http.parts = upstream.http.parts.clone();

        // scpd-02/scpd-12: tell the consumer which producer the SCP (re)selected,
        // in `nfinst=<uuid>[; nfset=<set>]` ABNF form, plus its NF group id —
        // gated to success responses (TS 29.500 §5.2.3.2.8 / §6.10.3.4).
        if (200..=299).contains(&upstream.status) {
            // scpd-#208: PRESERVE a Producer-Id the producer or a downstream SCP
            // already supplied instead of overwriting it (§6.10.3.4). `set_header`
            // replaced it, which discarded the more authoritative value: a
            // downstream SCP's is derived from the profile of the instance IT
            // selected, and a producer naming itself is first-hand. Ours is
            // second-hand by comparison, so it belongs only where there is nothing.
            let downstream_producer_id = relayed
                .http
                .get_header(custom_header::PRODUCER_ID)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());
            match downstream_producer_id {
                Some(existing) => log::debug!(
                    "SCP relay: keeping downstream 3gpp-Sbi-Producer-Id {existing} rather than \
                     replacing it with our own"
                ),
                None => {
                    if let Some(id) = relay.producer_id.filter(|s| !s.is_empty()) {
                        relayed.http.set_header(custom_header::PRODUCER_ID, id);
                    }
                }
            }
            if let Some(g) = relay.group_id.filter(|s| !s.is_empty()) {
                relayed
                    .http
                    .set_header(custom_header::TARGET_NF_GROUP_ID, g);
            }

            // scpd-#208: after retargeting, a RELATIVE `Location` is unusable by
            // the consumer — it names a resource without naming the producer that
            // holds it, and the consumer never chose that producer. TS 29.500
            // §6.10.4 allows either absolutising the `Location` or adding
            // `3gpp-Sbi-Target-apiRoot`; see `add_target_apiroot_for_location`
            // for which this SCP emits and why.
            if relay.retargeted {
                self.add_target_apiroot_for_location(&mut relayed, target);
            }
        }

        // scpd-03: a relayed producer error (4xx/5xx) carries this SCP's Via
        // (TS 29.500 §6.10.8.3); its body/status stay verbatim.
        if upstream.status >= 400 {
            self.append_via(&mut relayed.http);
        }

        // scpd-#209: the producer ANSWERED, so this is the answer even at 4xx/5xx.
        // Reselecting on a producer-generated error would be wrong twice: the
        // producer is up (so the set is not the problem), and a 409 or a 404 is
        // frequently the semantically correct answer that a sibling instance would
        // have no business overriding.
        ForwardOutcome::Answered(relayed)
    }

    /// Forward a Model D request, failing over to the next-best discovered
    /// producer when one provably never received it (scpd-#209,
    /// TS 29.500 §6.10.8.2).
    ///
    /// Bounded by `max_producer_attempts`, and the bound is **logged** when it
    /// truncates the list: silently trying 3 of 9 candidates and then reporting
    /// "no producer was reachable" would overstate what the SCP actually did.
    async fn forward_with_reselection(
        &self,
        request: &SbiRequest,
        outcome: DiscoveryOutcome,
        delegated: Option<DelegatedAuth>,
    ) -> SbiResponse {
        let max_attempts = self.config.max_producer_attempts.max(1);
        let total_candidates = 1 + outcome.alternates.len();
        let producers = std::iter::once(outcome.primary).chain(outcome.alternates);

        let mut attempted = 0usize;
        let mut last_undeliverable: Option<Undeliverable> = None;
        let mut any_transport_failure = false;

        for producer in producers {
            if attempted >= max_attempts {
                break;
            }
            attempted += 1;
            let producer_id =
                build_producer_id(&producer.nf_instance_id, producer.nf_set_id.as_deref());
            if attempted > 1 {
                log::debug!(
                    "SCP Model D reselection: attempt {attempted}/{max_attempts} -> {} \
                     (producer {})",
                    producer.target.to_uri(),
                    producer.nf_instance_id
                );
            }
            match self
                .forward_once(
                    request,
                    &producer.target,
                    RelayContext {
                        producer_id: producer_id.as_deref(),
                        group_id: producer.nf_group_id.as_deref(),
                        retargeted: true,
                    },
                    delegated.clone(),
                )
                .await
            {
                ForwardOutcome::Answered(response) | ForwardOutcome::Final(response) => {
                    return response
                }
                ForwardOutcome::Undeliverable(u) => {
                    any_transport_failure |= u.error.is_some();
                    last_undeliverable = Some(u);
                }
            }
        }

        let untried = total_candidates.saturating_sub(attempted);
        if untried > 0 {
            log::warn!(
                "SCP Model D: gave up after {attempted} producer(s); {untried} discovered \
                 candidate(s) left untried because max_producer_attempts is {max_attempts}"
            );
        }

        match last_undeliverable {
            // At least one producer was actually unreachable on the wire. The SCP
            // owns selection in Model D, so exhausting the whole candidate set
            // means its upstream is not answering — 504, per TS 29.500 §6.10.8.2,
            // rather than the 502 a single refused connection used to give. Model C
            // keeps 502: there the CONSUMER pinned the target, so the failure is
            // that one hop and not an exhausted set.
            Some(u) if any_transport_failure => self.stamp_server(problem_response(
                504,
                "Gateway Timeout",
                &format!(
                    "SCP could not reach any of {attempted} discovered producer(s); \
                     last was {} ({})",
                    u.target,
                    u.error
                        .as_ref()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "circuit open".to_string())
                ),
                "TARGET_NF_NOT_REACHABLE",
            )),
            // Every candidate was shed by its own circuit breaker, so nothing was
            // ever put on the wire. That is load shedding, not unreachability, and
            // 503 says "retry shortly" — which is exactly right, since the breakers
            // will half-open.
            Some(u) => self.stamp_server(self.undeliverable_response(&u)),
            // Unreachable in practice: `attempted` is at least 1 and every arm
            // either returns or sets `last_undeliverable`.
            None => self.stamp_server(problem_response(
                502,
                "Bad Gateway",
                "SCP selected no producer to forward to",
                "TARGET_NF_NOT_REACHABLE",
            )),
        }
    }

    /// Handle one inbound SBI request end-to-end (the server handler entry
    /// point).
    pub async fn handle(&self, mut request: SbiRequest) -> SbiResponse {
        // scpd-04: reject looped / hop-exhausted requests before any forwarding.
        if let Some(rejection) = self.ingress_guard(&request) {
            return rejection;
        }

        match self.route(&request) {
            // scpd-#210: a notification goes straight to its callback URI — no
            // discovery query, and no delegated token (`delegated: None`), because
            // the callback target is not a discovered producer and never asked for
            // one (TS 29.500 §6.10.7).
            //
            // `3gpp-Sbi-Callback` itself is deliberately **not** added to
            // `is_scp_consumed`: it identifies the message as a notification to the
            // receiver, so stripping it would remove information the SCP merely
            // read. Nor is this retargeting — the producer was given the callback
            // URI by the consumer, so `RelayContext::default()` is right.
            RouteDecision::Callback {
                target,
                forward_uri,
            } => {
                if let Some(uri) = forward_uri {
                    request.header.uri = uri;
                }
                log::debug!(
                    "SCP callback: {} {} -> {} (no discovery, no token)",
                    request.header.method,
                    request.header.uri,
                    target.to_uri()
                );
                self.forward(&request, &target, RelayContext::default(), None)
                    .await
            }
            RouteDecision::TargetApiRoot(target) => {
                log::debug!(
                    "SCP Model C: {} {} -> {}",
                    request.header.method,
                    request.header.uri,
                    target.to_uri()
                );
                // Model C: the consumer named the target, so nothing is
                // retargeted and no response fix-up is owed.
                self.forward(&request, &target, RelayContext::default(), None)
                    .await
            }
            RouteDecision::StickyBinding(target) => {
                // scpd-12: a sticky / set-level reselection still reports the
                // (re)selected producer to the consumer. The bound instance id
                // is carried in the consumer's Routing-Binding `nfinst=`.
                let producer_id = request
                    .http
                    .routing_binding()
                    .and_then(|b| ParsedBinding::parse(b).nfinst)
                    .map(|inst| format!("nfinst={inst}"));
                log::debug!(
                    "SCP binding stickiness: {} {} -> {}",
                    request.header.method,
                    request.header.uri,
                    target.to_uri()
                );
                self.forward(
                    &request,
                    &target,
                    RelayContext {
                        producer_id: producer_id.as_deref(),
                        group_id: None,
                        // The SCP resolved this from its own binding cache, so the
                        // consumer does not know the apiRoot either.
                        retargeted: true,
                    },
                    None,
                )
                .await
            }
            RouteDecision::Discover => match self.discover(&request).await {
                Ok(outcome) => {
                    // The producer NF type comes from the delegated-discovery
                    // header; used to scope the OAuth2 token the SCP attaches.
                    // #101 criterion 2: the token is minted for the requesting
                    // consumer when its identity can be attested.
                    let delegated_auth = request
                        .http
                        .get_header(discovery_header::TARGET_NF_TYPE)
                        .and_then(|s| nf_type_from_str(s))
                        .map(|nf| self.delegated_auth(&request, nf));
                    log::debug!(
                        "SCP Model D: {} {} -> {} (producer {}, {} alternate(s))",
                        request.header.method,
                        request.header.uri,
                        outcome.primary.target.to_uri(),
                        outcome.primary.nf_instance_id,
                        outcome.alternates.len()
                    );
                    // scpd-#209: fails over to the next-best discovered producer
                    // when a forward provably never arrived.
                    self.forward_with_reselection(&request, outcome, delegated_auth)
                        .await
                }
                // scpd-03: SCP-originated discovery errors carry our `Server`.
                Err(error_response) => self.stamp_server(error_response),
            },
            // scpd-03: SCP-originated routing rejection carries our `Server`.
            RouteDecision::Reject => self.stamp_server(problem_response(
                400,
                "Bad Request",
                "Request carries neither a valid 3gpp-Sbi-Target-apiRoot, a known \
                 3gpp-Sbi-Routing-Binding, nor 3gpp-Sbi-Discovery-* headers",
                "MANDATORY_IE_MISSING",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    // ------------------------------------------------------------------
    // Unit tests: parsing, header stripping, binding normalization
    // ------------------------------------------------------------------

    #[test]
    fn test_token_acquisition_failure_mapping() {
        // NRF MISSING_PARAMETER (or the SCP lacking requester info) -> 400
        // MISSING_ACCESS_TOKEN_INFO (TS 29.500 §6.10.11.2.2).
        let missing = token_acquisition_failure_response(&SbiError::AuthorizationFailed(
            "NRF token request failed (HTTP 400): {\"error\":\"MISSING_PARAMETER\"}".into(),
        ));
        assert_eq!(missing.status, 400);
        assert!(missing
            .http
            .content
            .as_deref()
            .unwrap_or_default()
            .contains("MISSING_ACCESS_TOKEN_INFO"));

        // Any other rejection / unreachable NRF -> 403 ACCESS_TOKEN_DENIED.
        for e in [
            SbiError::AuthorizationFailed(
                "NRF token request failed (HTTP 403): {\"error\":\"invalid_client\"}".into(),
            ),
            SbiError::Timeout,
        ] {
            let denied = token_acquisition_failure_response(&e);
            assert_eq!(denied.status, 403);
            assert!(denied
                .http
                .content
                .as_deref()
                .unwrap_or_default()
                .contains("ACCESS_TOKEN_DENIED"));
        }
    }

    #[test]
    fn test_apiroot_parse_variants() {
        let r = ApiRoot::parse("http://10.0.0.1:7778").unwrap();
        assert_eq!(r.scheme, UriScheme::Http);
        assert_eq!(r.host, "10.0.0.1");
        assert_eq!(r.port, 7778);
        assert_eq!(r.prefix, "");

        let r = ApiRoot::parse("https://udm.5gc.example.org").unwrap();
        assert_eq!(r.scheme, UriScheme::Https);
        assert_eq!(r.port, 443);

        let r = ApiRoot::parse("http://smf.local").unwrap();
        assert_eq!(r.port, 80);

        let r = ApiRoot::parse("http://nrf:7777/prefix/a/").unwrap();
        assert_eq!(r.prefix, "/prefix/a");
        assert_eq!(r.to_uri(), "http://nrf:7777/prefix/a");

        assert!(ApiRoot::parse("ftp://x:21").is_err());
        assert!(ApiRoot::parse("no-scheme").is_err());
        assert!(ApiRoot::parse("http://").is_err());
        // A numeric port that overflows u16 is rejected; a non-numeric
        // ":suffix" is treated as part of the (opaque) host, default port.
        assert!(ApiRoot::parse("http://h:99999").is_err());
        assert_eq!(ApiRoot::parse("http://h:notaport").unwrap().port, 80);
    }

    #[test]
    fn test_forwardable_request_headers_strip() {
        let mut headers = HashMap::new();
        headers.insert(":authority".to_string(), "scp:7777".to_string());
        headers.insert("connection".to_string(), "keep-alive".to_string());
        headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
        headers.insert("content-length".to_string(), "42".to_string());
        headers.insert(
            "3gpp-sbi-target-apiroot".to_string(),
            "http://udm:7777".to_string(),
        );
        // Case-variant SCP-consumed headers must also be stripped
        // (hyper lowercases on the wire, but in-process casing varies).
        headers.insert(
            "3GPP-SBI-DISCOVERY-TARGET-NF-TYPE".to_string(),
            "UDM".to_string(),
        );
        headers.insert(
            "3gpp-Sbi-Routing-Binding".to_string(),
            "bl=nf-instance; nfinst=x".to_string(),
        );
        // End-to-end headers must pass through untouched.
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("3gpp-sbi-oci".to_string(), "Timestamp: x; oci".to_string());
        headers.insert("3gpp-Sbi-Lci".to_string(), "Timestamp: y; lci".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());

        let fwd = forwardable_request_headers(&headers);
        assert!(!fwd.keys().any(|k| k.starts_with(':')));
        assert!(!fwd.contains_key("connection"));
        assert!(!fwd.contains_key("Transfer-Encoding"));
        assert!(!fwd.contains_key("content-length"));
        assert!(!fwd.contains_key("3gpp-sbi-target-apiroot"));
        assert!(!fwd.contains_key("3GPP-SBI-DISCOVERY-TARGET-NF-TYPE"));
        assert!(!fwd.contains_key("3gpp-Sbi-Routing-Binding"));
        assert_eq!(
            fwd.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            fwd.get("3gpp-sbi-oci").map(String::as_str),
            Some("Timestamp: x; oci")
        );
        assert_eq!(
            fwd.get("3gpp-Sbi-Lci").map(String::as_str),
            Some("Timestamp: y; lci")
        );
        assert_eq!(
            fwd.get("authorization").map(String::as_str),
            Some("Bearer tok")
        );
    }

    #[test]
    fn test_relayable_response_headers_keep_sbi_custom() {
        let mut headers = HashMap::new();
        headers.insert("connection".to_string(), "close".to_string());
        headers.insert("content-length".to_string(), "10".to_string());
        headers.insert(
            "3gpp-sbi-binding".to_string(),
            "bl=nf-instance; nfinst=abc".to_string(),
        );
        headers.insert("3gpp-sbi-oci".to_string(), "oci-val".to_string());
        headers.insert("3gpp-sbi-lci".to_string(), "lci-val".to_string());

        let relayed = relayable_response_headers(&headers);
        assert!(!relayed.contains_key("connection"));
        assert!(!relayed.contains_key("content-length"));
        // Binding/Oci/Lci are end-to-end: relayed untouched.
        assert_eq!(
            relayed.get("3gpp-sbi-binding").map(String::as_str),
            Some("bl=nf-instance; nfinst=abc")
        );
        assert_eq!(
            relayed.get("3gpp-sbi-oci").map(String::as_str),
            Some("oci-val")
        );
        assert_eq!(
            relayed.get("3gpp-sbi-lci").map(String::as_str),
            Some("lci-val")
        );
    }

    #[test]
    fn test_normalize_binding_and_cache() {
        assert_eq!(
            normalize_binding("BL=NF-Instance; NFINST=54804518"),
            "bl=nf-instance;nfinst=54804518"
        );

        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let target = ApiRoot::parse("http://smf1:7778").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=54804518", &target);
        // Lookup with different casing/whitespace still hits.
        let hit = proxy
            .binding_lookup("BL=nf-instance;NFINST=54804518")
            .unwrap();
        assert_eq!(hit, target);
        assert!(proxy.binding_lookup("bl=nf-set;nfset=other").is_none());
    }

    #[test]
    fn test_route_decision_priority() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());

        // Target-apiRoot wins even when discovery headers are present.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("http://udm:7777");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        assert!(matches!(proxy.route(&req), RouteDecision::TargetApiRoot(_)));

        // Discovery headers alone -> Discover.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        assert_eq!(proxy.route(&req), RouteDecision::Discover);

        // Unknown Routing-Binding with no discovery headers -> Reject.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_routing_binding("bl=nf-instance; nfinst=unknown");
        assert_eq!(proxy.route(&req), RouteDecision::Reject);

        // Known Routing-Binding -> StickyBinding.
        let target = ApiRoot::parse("http://udm2:7777").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=known", &target);
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_routing_binding("bl=nf-instance; nfinst=known");
        assert!(matches!(proxy.route(&req), RouteDecision::StickyBinding(t) if t == target));

        // Nothing at all -> Reject.
        let req = SbiRequest::get("/nudm-sdm/v1/x");
        assert_eq!(proxy.route(&req), RouteDecision::Reject);
    }

    // ------------------------------------------------------------------
    // Strict-peer tests: missing mandatory headers -> 400 ProblemDetails
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_reject_without_routing_headers_is_400_problem() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let response = proxy.handle(SbiRequest::get("/nudm-sdm/v1/x")).await;
        assert_eq!(response.status, 400);
        assert_eq!(
            response.http.get_header("content-type").map(String::as_str),
            Some("application/problem+json")
        );
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.status, Some(400));
        assert_eq!(problem.cause.as_deref(), Some("MANDATORY_IE_MISSING"));
    }

    #[tokio::test]
    async fn test_discovery_missing_requester_nf_type_is_400() {
        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some("http://127.0.0.1:1".into()),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 400);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("MANDATORY_IE_MISSING"));
        assert!(problem
            .detail
            .as_deref()
            .unwrap()
            .contains("requester-nf-type"));
    }

    #[tokio::test]
    async fn test_discovery_without_nrf_configured_is_503() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        req.http
            .set_header(discovery_header::REQUESTER_NF_TYPE, "AMF");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 503);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("NRF_NOT_AVAILABLE"));
    }

    #[tokio::test]
    async fn test_invalid_target_apiroot_is_400() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("not-a-uri");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 400);
    }

    // ------------------------------------------------------------------
    // HTTP-level integration tests: real HTTP/2 hops through the SCP
    // (ephemeral ports, bounded timeouts, fully async — no blocking threads)
    // ------------------------------------------------------------------

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper. This crate previously carried its own
    /// process-wide dedup (PR #138); that logic now lives in one place so all
    /// 21 crates share it and there is a single site to harden further.
    fn ephemeral_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    /// Start a mock producer that echoes the request (method, uri, body and
    /// selected headers) as JSON and returns Binding/Oci headers.
    async fn start_mock_producer(port: u16) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(|request: SbiRequest| async move {
                let echoed = serde_json::json!({
                    "method": request.header.method,
                    "uri": request.header.uri,
                    "body": request.http.content,
                    "sawTargetApiroot": request.http.target_apiroot().is_some(),
                    "targetApiroot": request.http.target_apiroot(),
                    "sawDiscovery": request.http.headers.keys()
                        .any(|k| k.to_ascii_lowercase().starts_with("3gpp-sbi-discovery-")),
                    "sawRoutingBinding": request.http.routing_binding().is_some(),
                    "oci": request.http.get_header("3gpp-Sbi-Oci"),
                    "lci": request.http.get_header("3gpp-Sbi-Lci"),
                    "param": request.http.get_param("k"),
                    // scpd-05/scpd-04 observability: the producer surfaces the
                    // (forbidden) ck cache-key param, our inserted Via, and the
                    // decremented Max-Forward-Hops so tests can assert them.
                    "ck": request.http.get_param("ck"),
                    "via": request.http.get_header("Via"),
                    "maxHops": request.http.get_header("3gpp-Sbi-Max-Forward-Hops"),
                });
                SbiResponse::ok()
                    .with_body(echoed.to_string(), "application/json")
                    .with_header("3gpp-Sbi-Binding", "bl=nf-instance; nfinst=producer-1")
                    .with_header("3gpp-Sbi-Oci", "producer-oci")
                    .with_header("3gpp-Sbi-Lci", "producer-lci")
            })
            .await
            .expect("producer start");
        server
    }

    /// Start the SCP itself: an SbiServer fronting a ScpProxy.
    async fn start_scp(port: u16, config: ScpProxyConfig) -> nextgcore_sbi::server::SbiServer {
        let proxy = Arc::new(ScpProxy::new(config));
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let proxy = proxy.clone();
                async move { proxy.handle(request).await }
            })
            .await
            .expect("scp start");
        server
    }

    fn fast_client(port: u16) -> SbiClient {
        SbiClient::new(
            SbiClientConfig::new("127.0.0.1", port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(5)),
        )
    }

    #[tokio::test]
    async fn test_model_c_forwarding_end_to_end() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_mock_producer(producer_port).await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"hello":"world"}"#, "application/json")
            .with_param("k", "v")
            .with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            )
            .with_header("3gpp-Sbi-Oci", "consumer-oci")
            .with_header("3gpp-Sbi-Lci", "consumer-lci");

        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("model C roundtrip");

        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        // Method, path, query and body all relayed.
        assert_eq!(echoed["method"], "POST");
        assert_eq!(echoed["uri"], "/nudm-uecm/v1/registrations");
        assert_eq!(echoed["body"], r#"{"hello":"world"}"#);
        assert_eq!(echoed["param"], "v");
        // SCP-consumed header stripped before the producer saw it.
        assert_eq!(echoed["sawTargetApiroot"], false);
        // Oci/Lci propagated untouched to the producer...
        assert_eq!(echoed["oci"], "consumer-oci");
        assert_eq!(echoed["lci"], "consumer-lci");
        // ...and from the producer back to the consumer.
        assert_eq!(
            response.http.get_header("3gpp-Sbi-Oci").map(String::as_str),
            Some("producer-oci")
        );
        assert_eq!(
            response.http.get_header("3gpp-Sbi-Lci").map(String::as_str),
            Some("producer-lci")
        );
        // The producer's Binding header is relayed to the consumer.
        assert_eq!(
            response.http.binding().map(String::as_str),
            Some("bl=nf-instance; nfinst=producer-1")
        );
        // Model C adds no Producer-Id.
        assert!(response.http.producer_id().is_none());

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// Start a mock NRF whose nnrf-disc answers with a single-producer
    /// SearchResult, counting how many discovery queries it served.
    async fn start_mock_nrf(
        port: u16,
        producer_port: u16,
        hits: Arc<AtomicU64>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let hits = hits.clone();
                async move {
                    // A real NRF serves both nnrf-disc and nnrf-oauth2; the SCP
                    // acquires a delegated token before forwarding (TS 33.501 §13).
                    if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                        return SbiResponse::ok().with_body(
                            r#"{"access_token":"scp-test-token","token_type":"Bearer","expires_in":3600}"#.to_string(),
                            "application/json",
                        );
                    }
                    assert_eq!(request.header.uri, "/nnrf-disc/v1/nf-instances");
                    // The SCP must put the requester identity from the
                    // Discovery-requester-nf-type header into the query.
                    assert_eq!(
                        request.http.get_param("target-nf-type").map(String::as_str),
                        Some("UDM")
                    );
                    assert_eq!(
                        request
                            .http
                            .get_param("requester-nf-type")
                            .map(String::as_str),
                        Some("AMF")
                    );
                    hits.fetch_add(1, Ordering::SeqCst);
                    let search_result = serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [{
                            "nfInstanceId": "udm-instance-1",
                            "nfType": "UDM",
                            "nfStatus": "REGISTERED",
                            "ipv4Addresses": ["127.0.0.1"],
                            "priority": 1,
                            "capacity": 100,
                            "load": 0,
                            "nfServices": [{
                                "serviceInstanceId": "nudm-uecm-1",
                                "serviceName": "nudm-uecm",
                                "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                            }]
                        }]
                    });
                    SbiResponse::ok().with_body(search_result.to_string(), "application/json")
                }
            })
            .await
            .expect("nrf start");
        server
    }

    #[tokio::test]
    async fn test_model_d_discovery_forwarding_and_binding_stickiness() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let nrf_hits = Arc::new(AtomicU64::new(0));

        let producer = start_mock_producer(producer_port).await;
        let nrf = start_mock_nrf(nrf_port, producer_port, nrf_hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        // --- Model D: delegated discovery ---
        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"amf":"reg"}"#, "application/json")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");

        let client = fast_client(scp_port);
        let response = client
            .send_request(request)
            .await
            .expect("model D roundtrip");

        assert_eq!(response.status, 200);
        assert_eq!(nrf_hits.load(Ordering::SeqCst), 1);
        // scpd-02: Producer-Id is returned in the TS 29.500 §5.2.3.2.8 ABNF
        // `nfinst=<id>` form (not the bare instance id), gated on a 2xx.
        assert_eq!(
            response.http.producer_id().map(String::as_str),
            Some("nfinst=udm-instance-1")
        );
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["body"], r#"{"amf":"reg"}"#);
        // Discovery headers were consumed by the SCP, not forwarded.
        assert_eq!(echoed["sawDiscovery"], false);
        // Producer announced its Binding; SCP relays it.
        let binding = response.http.binding().cloned().expect("binding relayed");

        // --- §6.12 stickiness: Routing-Binding routes without rediscovery ---
        let sticky = SbiRequest::get("/nudm-uecm/v1/registrations/1")
            .with_header("3gpp-Sbi-Routing-Binding", binding);
        let response = client.send_request(sticky).await.expect("sticky roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["uri"], "/nudm-uecm/v1/registrations/1");
        // Routing-Binding was consumed by the SCP, not forwarded.
        assert_eq!(echoed["sawRoutingBinding"], false);
        // No new NRF discovery happened.
        assert_eq!(nrf_hits.load(Ordering::SeqCst), 1);

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    #[tokio::test]
    async fn test_upstream_error_body_is_preserved() {
        // A producer that always answers 409 with a ProblemDetails body:
        // the SCP must relay it verbatim, not replace it.
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], producer_port)),
            ));
        server
            .start(|_request: SbiRequest| async move {
                SbiResponse::with_status(409).with_body(
                    r#"{"status":409,"cause":"DUPLICATE_REGISTRATION"}"#,
                    "application/problem+json",
                )
            })
            .await
            .expect("producer start");
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations").with_header(
            "3gpp-Sbi-Target-apiRoot",
            format!("http://127.0.0.1:{producer_port}"),
        );
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("error relay roundtrip");

        assert_eq!(response.status, 409);
        assert!(response
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("DUPLICATE_REGISTRATION"));

        scp.stop().await.expect("scp stop");
        server.stop().await.expect("producer stop");
    }

    #[tokio::test]
    async fn test_unreachable_target_is_502_problem() {
        // Port 1 on localhost refuses connections immediately.
        let proxy = ScpProxy::new(ScpProxyConfig {
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("http://127.0.0.1:1");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 502);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("TARGET_NF_NOT_REACHABLE"));
    }

    #[tokio::test]
    async fn test_slow_producer_is_504_within_bounded_timeout() {
        // A producer that never answers within the SCP's request timeout.
        let producer_port = ephemeral_port();
        let server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], producer_port)),
            ));
        server
            .start(|_request: SbiRequest| async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                SbiResponse::ok()
            })
            .await
            .expect("producer start");

        let proxy = ScpProxy::new(ScpProxyConfig {
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(300),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http
            .set_target_apiroot(format!("http://127.0.0.1:{producer_port}"));

        let started = std::time::Instant::now();
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 504);
        // Bounded: the proxy gave up at its request timeout, not the
        // producer's sleep.
        assert!(started.elapsed() < Duration::from_secs(3));
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("TARGET_NF_NOT_REACHABLE"));

        server.stop().await.expect("producer stop");
    }

    /// scpd-#211: an empty `SearchResult` is `404 NF_DISCOVERY_FAILURE`.
    ///
    /// **This assertion was inverted** (was `502`), and the old one pinned the
    /// defect rather than the requirement: it made "your criteria matched nothing"
    /// indistinguishable from "the NRF is down" and from "the producer is
    /// unreachable", which is the whole of #211. A `502` tells the consumer the
    /// fault is at or beyond the gateway and a retry may help; here it is the
    /// consumer's own discovery criteria that matched nothing, and no retry will
    /// change that.
    #[tokio::test]
    async fn test_nrf_returning_no_candidates_is_404_discovery_failure() {
        let nrf_port = ephemeral_port();
        let server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], nrf_port)),
            ));
        server
            .start(|_request: SbiRequest| async move {
                SbiResponse::ok().with_body(r#"{"nfInstances":[]}"#, "application/json")
            })
            .await
            .expect("nrf start");

        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        req.http
            .set_header(discovery_header::REQUESTER_NF_TYPE, "AMF");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 404);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("NF_DISCOVERY_FAILURE"));

        server.stop().await.expect("nrf stop");
    }

    // ------------------------------------------------------------------
    // scpd-#211: the three delegated-discovery failure conditions are
    // reported distinctly (TS 29.500 §6.10.8.2)
    // ------------------------------------------------------------------

    /// Drive one Model D request against `proxy` and return its
    /// `(status, cause)`.
    async fn discovery_failure_of(proxy: &ScpProxy) -> (u16, String) {
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        req.http
            .set_header(discovery_header::REQUESTER_NF_TYPE, "AMF");
        let response = proxy.handle(req).await;
        let problem: ProblemDetails = response
            .json_body()
            .expect("a ProblemDetails body on every SCP-originated discovery error");
        (
            response.status,
            problem.cause.unwrap_or_else(|| "(no cause)".to_string()),
        )
    }

    /// A ScpProxy pointed at `nrf_uri`, with short timeouts.
    fn proxy_with_nrf(nrf_uri: String) -> ScpProxy {
        ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(nrf_uri),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        })
    }

    /// scpd-#211 acceptance: an unreachable NRF is `504 NRF_NOT_REACHABLE` — and
    /// explicitly **not** `TARGET_NF_NOT_REACHABLE`, which named the wrong node
    /// and sent the investigation to a healthy producer. The negative assertion is
    /// paired with the positive one on purpose: asserting only "cause is
    /// NRF_NOT_REACHABLE" would still pass if some other path also started
    /// claiming the target NF was at fault.
    #[tokio::test]
    async fn test_unreachable_nrf_is_504_nrf_not_reachable() {
        // Port 1 on loopback refuses connections immediately.
        let proxy = proxy_with_nrf("http://127.0.0.1:1".to_string());
        let (status, cause) = discovery_failure_of(&proxy).await;
        assert_eq!(status, 504);
        assert_eq!(cause, "NRF_NOT_REACHABLE");
        assert_ne!(
            cause, "TARGET_NF_NOT_REACHABLE",
            "the NRF is not the target NF; naming it sends the operator to the wrong node"
        );
    }

    /// scpd-#211 acceptance: an NRF that answers non-200 keeps
    /// `502 NF_DISCOVERY_FAILURE` — the one condition for which 502 is right,
    /// since the NRF answered and answered badly.
    #[tokio::test]
    async fn test_nrf_error_response_is_502_discovery_failure() {
        let nrf_port = ephemeral_port();
        let server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], nrf_port)),
            ));
        server
            .start(|_request: SbiRequest| async move {
                SbiResponse::with_status(500)
                    .with_body(r#"{"cause":"NRF_BROKE"}"#, "application/json")
            })
            .await
            .expect("nrf start");

        let proxy = proxy_with_nrf(format!("http://127.0.0.1:{nrf_port}"));
        let (status, cause) = discovery_failure_of(&proxy).await;
        assert_eq!(status, 502);
        assert_eq!(cause, "NF_DISCOVERY_FAILURE");

        server.stop().await.expect("nrf stop");
    }

    /// scpd-#211 acceptance, the load-bearing one: the three conditions must be
    /// distinguishable **from each other**, not merely each "not 200".
    ///
    /// All three are driven here and their `(status, cause)` pairs asserted
    /// pairwise distinct, so collapsing any two of them back together fails this
    /// test even if each individual test above were adjusted to match.
    #[tokio::test]
    async fn test_three_discovery_failures_are_pairwise_distinct() {
        // 1. NRF unreachable.
        let unreachable =
            discovery_failure_of(&proxy_with_nrf("http://127.0.0.1:1".to_string())).await;

        // 2. NRF answers non-200.
        let erroring_port = ephemeral_port();
        let erroring =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], erroring_port)),
            ));
        erroring
            .start(|_request: SbiRequest| async move { SbiResponse::with_status(503) })
            .await
            .expect("erroring nrf start");
        let nrf_error =
            discovery_failure_of(&proxy_with_nrf(format!("http://127.0.0.1:{erroring_port}")))
                .await;

        // 3. NRF answers 200 with an empty SearchResult.
        let empty_port = ephemeral_port();
        let empty =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], empty_port)),
            ));
        empty
            .start(|_request: SbiRequest| async move {
                SbiResponse::ok().with_body(r#"{"nfInstances":[]}"#, "application/json")
            })
            .await
            .expect("empty nrf start");
        let empty_result =
            discovery_failure_of(&proxy_with_nrf(format!("http://127.0.0.1:{empty_port}"))).await;

        assert_eq!(unreachable, (504, "NRF_NOT_REACHABLE".to_string()));
        assert_eq!(nrf_error, (502, "NF_DISCOVERY_FAILURE".to_string()));
        assert_eq!(empty_result, (404, "NF_DISCOVERY_FAILURE".to_string()));

        assert_ne!(unreachable, nrf_error, "NRF down vs NRF erroring");
        assert_ne!(
            unreachable, empty_result,
            "NRF down vs criteria matched none"
        );
        assert_ne!(
            nrf_error, empty_result,
            "NRF erroring vs criteria matched none"
        );

        erroring.stop().await.expect("erroring nrf stop");
        empty.stop().await.expect("empty nrf stop");
    }

    /// scpd-#211 acceptance: `TARGET_NF_NOT_REACHABLE` is reserved for the
    /// **producer**. The Model C path (no NRF involved at all) must still report
    /// it, so the reservation is a narrowing rather than a removal.
    #[tokio::test]
    async fn test_target_nf_not_reachable_is_still_used_for_the_producer() {
        let proxy = ScpProxy::new(ScpProxyConfig {
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_target_apiroot("http://127.0.0.1:1");
        let response = proxy.handle(req).await;
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(
            (response.status, problem.cause.as_deref()),
            (502, Some("TARGET_NF_NOT_REACHABLE"))
        );
    }

    // ------------------------------------------------------------------
    // T1.6: delegated (Model D) OAuth2 token attachment
    // ------------------------------------------------------------------

    #[test]
    fn test_nf_type_from_str_mapping() {
        assert_eq!(nf_type_from_str("UDM"), Some(NfType::Udm));
        // Case-insensitive and whitespace-tolerant.
        assert_eq!(nf_type_from_str("  udm "), Some(NfType::Udm));
        assert_eq!(nf_type_from_str("5G_EIR"), Some(NfType::FiveGEir));
        assert_eq!(nf_type_from_str("SCP"), Some(NfType::Scp));
        // Unknown -> None (the SCP then forwards without minting a token).
        assert_eq!(nf_type_from_str("NOT_A_NF"), None);
    }

    #[test]
    fn test_strip_authorization_case_insensitive() {
        let mut h = HashMap::new();
        h.insert("Authorization".to_string(), "Bearer consumer".to_string());
        h.insert("content-type".to_string(), "application/json".to_string());
        strip_authorization(&mut h);
        assert!(!h.keys().any(|k| k.eq_ignore_ascii_case("authorization")));
        assert!(h.contains_key("content-type"));

        // Lowercased (as hyper delivers it) is also removed.
        let mut h2 = HashMap::new();
        h2.insert("authorization".to_string(), "Bearer x".to_string());
        strip_authorization(&mut h2);
        assert!(h2.is_empty());
    }

    /// A mock NRF that serves BOTH nnrf-disc (one-producer SearchResult) and
    /// the nnrf-oauth2 access-token endpoint, so the SCP can perform delegated
    /// discovery and then acquire an OAuth2 token. Counts token requests.
    async fn start_mock_nrf_with_oauth2(
        port: u16,
        producer_port: u16,
        token: &'static str,
        token_hits: Arc<AtomicU64>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let token_hits = token_hits.clone();
                async move {
                    if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                        // The SCP is the OAuth2 client: it must identify itself
                        // as an SCP and request a token for the producer (UDM).
                        let body = request.http.content.clone().unwrap_or_default();
                        assert!(
                            body.contains("nfType=SCP"),
                            "SCP must claim nfType=SCP in the token request, got: {body}"
                        );
                        assert!(
                            body.contains("targetNfType=UDM"),
                            "token request must target UDM, got: {body}"
                        );
                        token_hits.fetch_add(1, Ordering::SeqCst);
                        let resp = format!(
                            r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#
                        );
                        return SbiResponse::ok().with_body(resp, "application/json");
                    }
                    // Otherwise: delegated discovery.
                    assert_eq!(request.header.uri, "/nnrf-disc/v1/nf-instances");
                    let search_result = serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [{
                            "nfInstanceId": "udm-instance-1",
                            "nfType": "UDM",
                            "nfStatus": "REGISTERED",
                            "ipv4Addresses": ["127.0.0.1"],
                            "priority": 1,
                            "capacity": 100,
                            "load": 0,
                            "nfServices": [{
                                "serviceInstanceId": "nudm-uecm-1",
                                "serviceName": "nudm-uecm",
                                "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                            }]
                        }]
                    });
                    SbiResponse::ok().with_body(search_result.to_string(), "application/json")
                }
            })
            .await
            .expect("nrf start");
        server
    }

    /// A producer that echoes back the Authorization header it received, so a
    /// test can assert the SCP attached a delegated Bearer token.
    async fn start_auth_echo_producer(port: u16) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(|request: SbiRequest| async move {
                let auth = request
                    .http
                    .get_header("Authorization")
                    .cloned()
                    .unwrap_or_default();
                let echoed = serde_json::json!({ "authorization": auth });
                SbiResponse::ok().with_body(echoed.to_string(), "application/json")
            })
            .await
            .expect("producer start");
        server
    }

    /// T1.6: a delegated (Model D) forward must attach a valid OAuth2 Bearer
    /// token acquired by the SCP from the NRF — replacing any opaque
    /// Authorization the consumer sent.
    #[tokio::test]
    async fn test_model_d_attaches_delegated_bearer_token() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let token_hits = Arc::new(AtomicU64::new(0));

        let producer = start_auth_echo_producer(producer_port).await;
        let nrf = start_mock_nrf_with_oauth2(
            nrf_port,
            producer_port,
            "scp-delegated-token",
            token_hits.clone(),
        )
        .await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        // Delegated request carrying the consumer's own (now-irrelevant) token.
        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"amf":"reg"}"#, "application/json")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm")
            .with_header("Authorization", "Bearer consumer-supplied-stale");

        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("model D roundtrip");
        assert_eq!(response.status, 200);

        let echoed: serde_json::Value = response.json_body().unwrap();
        // The producer saw the SCP's freshly minted delegated token, NOT the
        // consumer's stale opaque one.
        assert_eq!(
            echoed["authorization"], "Bearer scp-delegated-token",
            "SCP must attach the delegated OAuth2 token on Model D forwards"
        );
        // The SCP actually went to the NRF's token endpoint.
        assert_eq!(token_hits.load(Ordering::SeqCst), 1);

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    // ------------------------------------------------------------------
    // #101 criteria 2-4: delegated token identity, scope and per-consumer cache
    // ------------------------------------------------------------------

    /// A mock NRF that RECORDS each token-request body rather than asserting on
    /// it, so each test states its own expectation about the identity the SCP
    /// asserted.
    async fn start_recording_nrf(
        port: u16,
        producer_port: u16,
        token: &'static str,
        token_bodies: Arc<tokio::sync::Mutex<Vec<String>>>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let token_bodies = token_bodies.clone();
                async move {
                    if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                        let body = request.http.content.clone().unwrap_or_default();
                        token_bodies.lock().await.push(body);
                        let resp = format!(
                            r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#
                        );
                        return SbiResponse::ok().with_body(resp, "application/json");
                    }
                    assert_eq!(request.header.uri, "/nnrf-disc/v1/nf-instances");
                    let search_result = serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [{
                            "nfInstanceId": "udm-instance-1",
                            "nfType": "UDM",
                            "nfStatus": "REGISTERED",
                            "ipv4Addresses": ["127.0.0.1"],
                            "priority": 1,
                            "capacity": 100,
                            "load": 0,
                            "nfServices": [{
                                "serviceInstanceId": "nudm-uecm-1",
                                "serviceName": "nudm-uecm",
                                "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                            }]
                        }]
                    });
                    SbiResponse::ok().with_body(search_result.to_string(), "application/json")
                }
            })
            .await
            .expect("nrf start");
        server
    }

    /// A producer that echoes the Authorization it received AND whether the
    /// consumer's CCA header leaked through to it.
    async fn start_header_echo_producer(port: u16) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(|request: SbiRequest| async move {
                let echoed = serde_json::json!({
                    "authorization": request
                        .http
                        .get_header("Authorization")
                        .cloned()
                        .unwrap_or_default(),
                    "cca_leaked": request
                        .http
                        .get_header(custom_header::CLIENT_CREDENTIALS)
                        .is_some(),
                });
                SbiResponse::ok().with_body(echoed.to_string(), "application/json")
            })
            .await
            .expect("producer start");
        server
    }

    /// A Model D request from consumer `amf-instance-7`, optionally attesting
    /// itself with its own CCA and optionally naming an explicit access scope.
    fn model_d_request(cca: Option<&str>, access_scope: Option<&str>) -> SbiRequest {
        let mut request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"amf":"reg"}"#, "application/json")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::REQUESTER_NF_INSTANCE_ID, "amf-instance-7")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm");
        if let Some(cca) = cca {
            request = request.with_header(custom_header::CLIENT_CREDENTIALS, cca);
        }
        if let Some(scope) = access_scope {
            request = request.with_header(custom_header::ACCESS_SCOPE, scope);
        }
        request
    }

    /// A CCA-shaped value. Only its opacity matters here: the SCP must forward
    /// it verbatim to the NRF, not interpret it.
    const CONSUMER_CCA: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbWYtaW5zdGFuY2UtNyJ9.c2lnbmF0dXJl";

    /// #101 criterion 2: when the consumer attests itself with its own CCA, the
    /// delegated token request must name the CONSUMER — not `nextgcore-scp` /
    /// `NfType::Scp` — and must forward that CCA so the NRF can verify it
    /// against the consumer's registered key (TS 33.501 §13.4.1.3.2).
    #[tokio::test]
    async fn delegated_token_asserts_the_consumer_identity_when_the_consumer_attests_it() {
        let (producer_port, nrf_port, scp_port) =
            (ephemeral_port(), ephemeral_port(), ephemeral_port());
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let producer = start_header_echo_producer(producer_port).await;
        let nrf =
            start_recording_nrf(nrf_port, producer_port, "consumer-token", bodies.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_request(Some(CONSUMER_CCA), None))
            .await
            .expect("model D roundtrip");
        assert_eq!(response.status, 200);

        let bodies = bodies.lock().await;
        assert_eq!(bodies.len(), 1, "exactly one token request");
        let body = &bodies[0];
        assert!(
            body.contains("nfInstanceId=amf-instance-7"),
            "token must be minted for the consumer, got: {body}"
        );
        assert!(
            body.contains("nfType=AMF"),
            "token nfType must be the consumer's, got: {body}"
        );
        assert!(
            !body.contains("scp-instance-1") && !body.contains("nfType=SCP"),
            "the SCP must not name itself once the consumer is attested, got: {body}"
        );
        // The consumer's assertion is forwarded verbatim (percent-encoded).
        assert!(
            body.contains("cca=eyJhbGciOiJFUzI1NiJ9"),
            "the consumer's CCA must be forwarded, got: {body}"
        );

        // The CCA authenticates to the NRF only; it must not reach the producer.
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["authorization"], "Bearer consumer-token");
        assert_eq!(
            echoed["cca_leaked"], false,
            "3gpp-Sbi-Client-Credentials must not be relayed to the producer"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// The other half of the rule, and the reason a blind feature flag would be
    /// wrong: with no consumer CCA the SCP cannot attest the consumer's
    /// identity, so it must name ITSELF rather than assert an identity it
    /// cannot prove. Naming the consumer here would be rejected by our own NRF
    /// after #64, because the CCA we can sign has `sub` = the SCP.
    #[tokio::test]
    async fn delegated_token_stays_scp_attested_without_a_consumer_cca() {
        let (producer_port, nrf_port, scp_port) =
            (ephemeral_port(), ephemeral_port(), ephemeral_port());
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let producer = start_header_echo_producer(producer_port).await;
        let nrf = start_recording_nrf(nrf_port, producer_port, "scp-token", bodies.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_request(None, None))
            .await
            .expect("model D roundtrip");
        assert_eq!(response.status, 200);

        let bodies = bodies.lock().await;
        let body = &bodies[0];
        assert!(
            body.contains("nfInstanceId=scp-instance-1") && body.contains("nfType=SCP"),
            "an unattestable consumer must leave the token SCP-attested, got: {body}"
        );
        assert!(
            !body.contains("amf-instance-7"),
            "the consumer's identity must not be asserted unattested, got: {body}"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// The operator escape hatch for an NRF that does not require client
    /// authentication: assert the consumer's identity with no assertion.
    #[tokio::test]
    async fn trust_requester_identity_asserts_the_consumer_without_a_cca() {
        let (producer_port, nrf_port, scp_port) =
            (ephemeral_port(), ephemeral_port(), ephemeral_port());
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let producer = start_header_echo_producer(producer_port).await;
        let nrf = start_recording_nrf(nrf_port, producer_port, "tok", bodies.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                trust_requester_identity: true,
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_request(None, None))
            .await
            .expect("model D roundtrip");
        assert_eq!(response.status, 200);

        let bodies = bodies.lock().await;
        let body = &bodies[0];
        assert!(
            body.contains("nfInstanceId=amf-instance-7") && body.contains("nfType=AMF"),
            "the declared-trust path must assert the consumer, got: {body}"
        );
        assert!(
            !body.contains("cca="),
            "no assertion exists to send, so none must be fabricated, got: {body}"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// #101 criterion 3: `3gpp-Sbi-Access-Scope` names the scope the consumer
    /// needs, and it must win over the scope derived from the request URI's
    /// service name. Here the URI says `nudm-uecm` and the header says
    /// `nudm-sdm`, so only reading the header can produce the right token.
    #[tokio::test]
    async fn access_scope_header_sets_the_delegated_token_scope() {
        let (producer_port, nrf_port, scp_port) =
            (ephemeral_port(), ephemeral_port(), ephemeral_port());
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let producer = start_header_echo_producer(producer_port).await;
        let nrf = start_recording_nrf(nrf_port, producer_port, "tok", bodies.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_request(Some(CONSUMER_CCA), Some("nudm-sdm")))
            .await
            .expect("model D roundtrip");
        assert_eq!(response.status, 200);

        let bodies = bodies.lock().await;
        let body = &bodies[0];
        assert!(
            body.contains("scope=nudm-sdm"),
            "Access-Scope must set the token scope, got: {body}"
        );
        assert!(
            !body.contains("scope=nudm-uecm"),
            "the URI-derived scope must not win over an explicit Access-Scope, got: {body}"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// #101 criterion 4, end to end: two different consumers of the SAME
    /// (target, scope) must each cause their OWN token request. Before the
    /// cache key gained its consumer component the second consumer silently
    /// reused the first's token — one consumer receiving another's
    /// authorisation at the producer.
    #[tokio::test]
    async fn two_consumers_of_one_target_scope_each_get_their_own_token() {
        let (producer_port, nrf_port, scp_port) =
            (ephemeral_port(), ephemeral_port(), ephemeral_port());
        let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let producer = start_header_echo_producer(producer_port).await;
        let nrf = start_recording_nrf(nrf_port, producer_port, "tok", bodies.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);
        // Consumer A, attested.
        let first = model_d_request(Some(CONSUMER_CCA), None);
        assert_eq!(client.send_request(first).await.expect("A").status, 200);
        // Consumer B: same target and scope, different identity and assertion.
        let second = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"smf":"reg"}"#, "application/json")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "SMF")
            .with_header(discovery_header::REQUESTER_NF_INSTANCE_ID, "smf-instance-9")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm")
            .with_header(
                custom_header::CLIENT_CREDENTIALS,
                "eyJhbGciOiJFUzI1NiJ9.c21m.c2ln",
            );
        assert_eq!(client.send_request(second).await.expect("B").status, 200);

        let bodies = bodies.lock().await;
        assert_eq!(
            bodies.len(),
            2,
            "each consumer must trigger its own token request, got: {bodies:?}"
        );
        assert!(bodies
            .iter()
            .any(|b| b.contains("nfInstanceId=amf-instance-7")));
        assert!(bodies
            .iter()
            .any(|b| b.contains("nfInstanceId=smf-instance-9")));

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    // ------------------------------------------------------------------
    // scpd-01: Model D ApiRoot derivation honours producer NF profile
    // ------------------------------------------------------------------

    /// scpd-01 acceptance: a SearchResult with `scheme:"https"`, an IPv6
    /// address, and `apiPrefix` produces `ApiRoot` `https://[v6]:port/prefix`.
    /// The existing http/ipv4 path is unchanged.
    #[test]
    fn test_discover_builds_apiroot_from_https_ipv6_apiprefix_profile() {
        let https_ipv6_result = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-tls-v6",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv6Addresses": ["2001:db8::cafe"],
                "priority": 1,
                "capacity": 100,
                "load": 0,
                "nfServices": [{
                    "serviceName": "nudm-sdm",
                    "scheme": "https",
                    "apiPrefix": "/5g/v1",
                    "ipEndPoints": [{"transport": "TCP", "port": 8443}]
                }]
            }]
        });
        let body = serde_json::to_vec(&https_ipv6_result).unwrap();
        let candidates = parse_search_result(&body);
        let selected =
            crate::sbi_path::select_nf_service_endpoint(&candidates, Some("nudm-sdm"), Some("v1"))
                .expect("candidate selected");

        // Simulate what discover() now does.
        let target = ApiRoot {
            scheme: selected.scheme,
            host: selected.candidate.host.clone(),
            port: selected.port,
            prefix: selected.prefix.clone(),
        };

        assert_eq!(target.scheme, UriScheme::Https);
        assert_eq!(target.host, "[2001:db8::cafe]");
        assert_eq!(target.port, 8443);
        assert_eq!(target.prefix, "/5g/v1");
        assert_eq!(target.to_uri(), "https://[2001:db8::cafe]:8443/5g/v1");
    }

    /// scpd-01 acceptance: a plain http/ipv4 profile (no scheme or apiPrefix
    /// in the SearchResult) still yields the existing `http://ipv4:port` root
    /// — backward-compat is preserved, so the matched-sim Model D path is
    /// unchanged.
    #[test]
    fn test_discover_builds_apiroot_from_http_ipv4_profile_unchanged() {
        let http_ipv4_result = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-plain",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["10.0.0.1"],
                "priority": 1,
                "capacity": 100,
                "load": 0,
                "nfServices": [{
                    "serviceName": "nudm-uecm",
                    "ipEndPoints": [{"port": 7777}]
                }]
            }]
        });
        let body = serde_json::to_vec(&http_ipv4_result).unwrap();
        let candidates = parse_search_result(&body);
        let selected =
            crate::sbi_path::select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v1"))
                .expect("candidate selected");

        let target = ApiRoot {
            scheme: selected.scheme,
            host: selected.candidate.host.clone(),
            port: selected.port,
            prefix: selected.prefix.clone(),
        };

        assert_eq!(target.scheme, UriScheme::Http);
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 7777);
        assert_eq!(target.prefix, "");
        assert_eq!(target.to_uri(), "http://10.0.0.1:7777");
    }

    // ------------------------------------------------------------------
    // scpd-#207: Model D endpoint selection matches serviceName + API version
    // (TS 29.510 §6.2.6.2)
    // ------------------------------------------------------------------

    /// A producer that answers 200 with `{"servedBy":"<name>"}` and counts its
    /// hits, so a test can assert **which** endpoint served a request — and that
    /// a live producer was *not* contacted.
    async fn start_named_producer(
        port: u16,
        name: &'static str,
        hits: Arc<AtomicU64>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    SbiResponse::ok().with_body(
                        serde_json::json!({"servedBy": name, "uri": request.header.uri})
                            .to_string(),
                        "application/json",
                    )
                }
            })
            .await
            .expect("producer start");
        server
    }

    /// A mock NRF that answers every `nnrf-disc` query with `search_result`, and
    /// serves the token endpoint the Model D path needs.
    async fn start_nrf_serving(
        port: u16,
        search_result: serde_json::Value,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let search_result = search_result.clone();
                async move {
                    if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                        return SbiResponse::ok().with_body(
                            r#"{"access_token":"scp-test-token","token_type":"Bearer","expires_in":3600}"#.to_string(),
                            "application/json",
                        );
                    }
                    SbiResponse::ok().with_body(search_result.to_string(), "application/json")
                }
            })
            .await
            .expect("nrf start");
        server
    }

    /// scpd-#207 acceptance: a two-service producer on differing ports is
    /// addressed on the **requested** service's port.
    ///
    /// `nudm-sdm` is deliberately `nfServices[0]`, so the pre-fix code — which
    /// took the endpoint from the first service unconditionally — would send this
    /// `nudm-uecm` request to the sdm port and the assertion would name the wrong
    /// producer. Asserting on `servedBy` rather than on a 200 is what makes that
    /// visible: the sdm producer is live and would have answered 200 too.
    #[tokio::test]
    async fn test_model_d_addresses_the_requested_services_endpoint() {
        let sdm_port = ephemeral_port();
        let uecm_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let sdm_hits = Arc::new(AtomicU64::new(0));
        let uecm_hits = Arc::new(AtomicU64::new(0));

        let sdm = start_named_producer(sdm_port, "sdm", sdm_hits.clone()).await;
        let uecm = start_named_producer(uecm_port, "uecm", uecm_hits.clone()).await;
        let nrf = start_nrf_serving(
            nrf_port,
            serde_json::json!({
                "validityPeriod": 3600,
                "nfInstances": [{
                    "nfInstanceId": "udm-multi-service",
                    "nfType": "UDM",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["127.0.0.1"],
                    "priority": 1,
                    "nfServices": [
                        {
                            "serviceName": "nudm-sdm",
                            "versions": [{"apiVersionInUri": "v1"}],
                            "ipEndPoints": [{"transport": "TCP", "port": sdm_port}]
                        },
                        {
                            "serviceName": "nudm-uecm",
                            "versions": [{"apiVersionInUri": "v1"}],
                            "ipEndPoints": [{"transport": "TCP", "port": uecm_port}]
                        }
                    ]
                }]
            }),
        )
        .await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(
            body["servedBy"], "uecm",
            "the requested service's endpoint must serve the request, not nfServices[0]'s"
        );
        assert_eq!(uecm_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            sdm_hits.load(Ordering::SeqCst),
            0,
            "the unrequested service's endpoint must not be contacted"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        uecm.stop().await.expect("uecm stop");
        sdm.stop().await.expect("sdm stop");
    }

    /// scpd-#207 acceptance: an API version no discovered producer serves is
    /// `400 INVALID_API` (TS 29.500 Table 5.2.7.2-1) and the request is **not**
    /// forwarded — asserted against a live producer, so a zero hit count means
    /// the SCP declined rather than that the forward happened to fail.
    #[tokio::test]
    async fn test_model_d_unsupported_api_version_is_400_invalid_api() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let hits = Arc::new(AtomicU64::new(0));

        let producer = start_named_producer(producer_port, "uecm-v1", hits.clone()).await;
        let nrf = start_nrf_serving(
            nrf_port,
            serde_json::json!({
                "validityPeriod": 3600,
                "nfInstances": [{
                    "nfInstanceId": "udm-v1-only",
                    "nfType": "UDM",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["127.0.0.1"],
                    "priority": 1,
                    "nfServices": [{
                        "serviceName": "nudm-uecm",
                        "versions": [{"apiVersionInUri": "v1"}],
                        "ipEndPoints": [{"transport": "TCP", "port": producer_port}]
                    }]
                }]
            }),
        )
        .await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);

        // v2 is not registered: 400 INVALID_API, nothing forwarded.
        let v2 = SbiRequest::post("/nudm-uecm/v2/registrations")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm");
        let response = client.send_request(v2).await.expect("roundtrip");
        assert_eq!(response.status, 400);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("INVALID_API"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "an unsupported API version must not be forwarded"
        );

        // The same producer still serves v1, so the rejection is version-specific
        // rather than the SCP having broken this profile outright.
        let v1 = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm");
        let response = client.send_request(v1).await.expect("roundtrip");
        assert_eq!(response.status, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    // ------------------------------------------------------------------
    // scpd-#209: alternate-producer reselection on an undelivered forward
    // (TS 29.500 §6.10.8.2)
    // ------------------------------------------------------------------

    /// A `SearchResult` naming `ports` as separate UDM instances serving
    /// `nudm-uecm`, in ascending `priority` — so the FIRST port listed is the one
    /// selection picks first and reselection walks the rest in order.
    fn uecm_instances(ports: &[u16]) -> serde_json::Value {
        let instances: Vec<serde_json::Value> = ports
            .iter()
            .enumerate()
            .map(|(i, port)| {
                serde_json::json!({
                    "nfInstanceId": format!("udm-{i}"),
                    "nfType": "UDM",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["127.0.0.1"],
                    "priority": (i as u64) + 1,
                    "capacity": 100,
                    "load": 0,
                    "nfServices": [{
                        "serviceName": "nudm-uecm",
                        "ipEndPoints": [{"transport": "TCP", "port": port}]
                    }]
                })
            })
            .collect();
        serde_json::json!({"validityPeriod": 3600, "nfInstances": instances})
    }

    fn model_d_uecm_request() -> SbiRequest {
        SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm")
    }

    /// scpd-#209 acceptance: with two candidates where the first refuses
    /// connections, the **second** serves the request.
    ///
    /// Two candidates is the minimum that can distinguish reselection from a
    /// retry, which is why the issue asks for it: a single-candidate test would
    /// pass against code that merely dialled the same dead producer twice.
    #[tokio::test]
    async fn test_model_d_reselects_the_next_candidate_when_the_first_refuses() {
        // Port 1 on loopback refuses immediately (privileged, nothing listening).
        const DEAD_PORT: u16 = 1;
        let live_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let live_hits = Arc::new(AtomicU64::new(0));

        let live = start_named_producer(live_port, "second", live_hits.clone()).await;
        let nrf = start_nrf_serving(nrf_port, uecm_instances(&[DEAD_PORT, live_port])).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                connect_timeout: Duration::from_millis(500),
                request_timeout: Duration::from_millis(500),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_uecm_request())
            .await
            .expect("roundtrip");
        assert_eq!(
            response.status, 200,
            "a registered healthy sibling must serve a request the first candidate could not"
        );
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(body["servedBy"], "second");
        assert_eq!(live_hits.load(Ordering::SeqCst), 1);
        // scpd-02/#209: the reselected producer reports ITS OWN instance id, not
        // the one originally selected.
        assert_eq!(
            response.http.producer_id().map(String::as_str),
            Some("nfinst=udm-1"),
            "Producer-Id must name the producer that actually served the request"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        live.stop().await.expect("live stop");
    }

    /// scpd-#209 acceptance: exhausting the candidate list on connection-refused
    /// is `504`, and is distinguishable from the `502 NF_DISCOVERY_FAILURE` a
    /// genuine discovery error gives.
    ///
    /// Both are driven here so the distinction is asserted rather than assumed —
    /// and note the pair `(504, TARGET_NF_NOT_REACHABLE)` does not collide with
    /// #211's `(504, NRF_NOT_REACHABLE)`: the cause still names which node failed.
    #[tokio::test]
    async fn test_model_d_exhausted_candidates_is_504_distinct_from_discovery_failure() {
        let nrf_port = ephemeral_port();
        // Two candidates, both refusing.
        let nrf = start_nrf_serving(nrf_port, uecm_instances(&[1, 2])).await;
        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let exhausted = proxy.handle(model_d_uecm_request()).await;
        let problem: ProblemDetails = exhausted.json_body().unwrap();
        let exhausted = (exhausted.status, problem.cause.unwrap_or_default());
        assert_eq!(exhausted, (504, "TARGET_NF_NOT_REACHABLE".to_string()));

        // A genuine discovery error: the NRF answers non-200.
        let broken_port = ephemeral_port();
        let broken =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], broken_port)),
            ));
        broken
            .start(|_r: SbiRequest| async move { SbiResponse::with_status(500) })
            .await
            .expect("broken nrf start");
        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{broken_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });
        let discovery_error = proxy.handle(model_d_uecm_request()).await;
        let problem: ProblemDetails = discovery_error.json_body().unwrap();
        let discovery_error = (discovery_error.status, problem.cause.unwrap_or_default());
        assert_eq!(discovery_error, (502, "NF_DISCOVERY_FAILURE".to_string()));

        assert_ne!(
            exhausted, discovery_error,
            "an exhausted producer set and a discovery error must not read alike"
        );

        nrf.stop().await.expect("nrf stop");
        broken.stop().await.expect("broken nrf stop");
    }

    /// scpd-#209 acceptance: a producer-generated 5xx is **relayed**, not
    /// reselected. The producer answered, so the set is not the problem — and a
    /// sibling has no business overriding a 409 or a 404 the first one returned.
    ///
    /// The second candidate is live and counted, so the assertion distinguishes
    /// "did not reselect" from "reselected and the second also failed".
    #[tokio::test]
    async fn test_model_d_does_not_reselect_on_a_producer_error() {
        let erroring_port = ephemeral_port();
        let live_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let erroring_hits = Arc::new(AtomicU64::new(0));
        let live_hits = Arc::new(AtomicU64::new(0));

        let erroring = start_counting_500_producer(erroring_port, erroring_hits.clone()).await;
        let live = start_named_producer(live_port, "second", live_hits.clone()).await;
        let nrf = start_nrf_serving(nrf_port, uecm_instances(&[erroring_port, live_port])).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                connect_timeout: Duration::from_millis(500),
                request_timeout: Duration::from_millis(500),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_uecm_request())
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 500, "the producer's answer is relayed");
        assert_eq!(erroring_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            live_hits.load(Ordering::SeqCst),
            0,
            "a producer that ANSWERED must not trigger failover to a sibling"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        live.stop().await.expect("live stop");
        erroring.stop().await.expect("erroring stop");
    }

    /// scpd-#209: `max_producer_attempts` really bounds the walk.
    ///
    /// Three candidates, the first two refusing and the third live, with the bound
    /// set to 2: the request must FAIL even though a healthy producer was in the
    /// set and one more attempt would have reached it. Asserting the failure is
    /// how the bound is observed — counting connects to a dead port is not
    /// possible.
    #[tokio::test]
    async fn test_max_producer_attempts_bounds_the_reselection_walk() {
        let live_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let live_hits = Arc::new(AtomicU64::new(0));

        let live = start_named_producer(live_port, "third", live_hits.clone()).await;
        let nrf = start_nrf_serving(nrf_port, uecm_instances(&[1, 2, live_port])).await;

        let bounded = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            max_producer_attempts: 2,
            ..Default::default()
        });
        let response = bounded.handle(model_d_uecm_request()).await;
        assert_eq!(response.status, 504, "the bound stopped the walk short");
        assert_eq!(
            live_hits.load(Ordering::SeqCst),
            0,
            "the third candidate was never tried"
        );

        // Raising the bound reaches it, so the failure above is the bound and not
        // a broken third candidate.
        let unbounded = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            max_producer_attempts: 3,
            ..Default::default()
        });
        let response = unbounded.handle(model_d_uecm_request()).await;
        assert_eq!(response.status, 200);
        assert_eq!(live_hits.load(Ordering::SeqCst), 1);

        nrf.stop().await.expect("nrf stop");
        live.stop().await.expect("live stop");
    }

    /// scpd-#209 + scpd-#102: **an open circuit reselects instead of shedding.**
    ///
    /// This is the interaction the issue names in as many words: the breaker
    /// stopped the SCP hammering a dead producer but never sent it to a live one,
    /// so "the first request after the circuit opens still fails". Here the first
    /// candidate answers 500 twice to trip its own breaker; the third request must
    /// be served by the sibling rather than shed with a 503.
    #[tokio::test]
    async fn test_an_open_circuit_reselects_rather_than_shedding() {
        let flapping_port = ephemeral_port();
        let live_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let flapping_hits = Arc::new(AtomicU64::new(0));
        let live_hits = Arc::new(AtomicU64::new(0));

        let flapping = start_counting_500_producer(flapping_port, flapping_hits.clone()).await;
        let live = start_named_producer(live_port, "sibling", live_hits.clone()).await;
        let nrf = start_nrf_serving(nrf_port, uecm_instances(&[flapping_port, live_port])).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                connect_timeout: Duration::from_millis(500),
                request_timeout: Duration::from_millis(500),
                circuit_failure_threshold: 2,
                circuit_open_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);

        // Two 5xx answers trip the first candidate's breaker. Both are relayed —
        // a producer that answers is not reselected.
        for _ in 0..2 {
            let response = client
                .send_request(model_d_uecm_request())
                .await
                .expect("roundtrip");
            assert_eq!(response.status, 500);
        }
        assert_eq!(flapping_hits.load(Ordering::SeqCst), 2);
        assert_eq!(live_hits.load(Ordering::SeqCst), 0);

        // The breaker for the first candidate is now Open. Pre-#209 this request
        // was shed with 503; it must now be served by the sibling.
        let response = client
            .send_request(model_d_uecm_request())
            .await
            .expect("roundtrip");
        assert_eq!(
            response.status, 200,
            "an open circuit must send the request to a sibling, not shed it"
        );
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(body["servedBy"], "sibling");
        assert_eq!(live_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            flapping_hits.load(Ordering::SeqCst),
            2,
            "the open circuit still protects the failing producer from more traffic"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        live.stop().await.expect("live stop");
        flapping.stop().await.expect("flapping stop");
    }

    /// scpd-#209 unit: the idempotency rule. `ConnectionError` and `TlsError` are
    /// produced only before any request byte is written, so replaying them is
    /// safe; `Timeout` and `HyperError` can both occur *after* the request was
    /// sent, so replaying a `POST` on one could duplicate work.
    #[test]
    fn test_only_pre_send_failures_are_replayable() {
        assert!(is_provably_undelivered(&SbiError::ConnectionError(
            "Connection refused (os error 111)".to_string()
        )));
        assert!(is_provably_undelivered(&SbiError::TlsError(
            "TLS handshake failed".to_string()
        )));
        // The load-bearing negatives: a timeout may mean the producer received the
        // request and is still working on it.
        assert!(!is_provably_undelivered(&SbiError::Timeout));
        assert!(!is_provably_undelivered(&SbiError::HyperError(
            "stream closed".to_string()
        )));
        assert!(!is_provably_undelivered(&SbiError::InvalidResponse(
            "garbage".to_string()
        )));
    }

    /// scpd-#209: a timeout on the FIRST candidate is not replayed on the second,
    /// because the request may already have been delivered. The live sibling stays
    /// untouched and the consumer gets the 504 the slow producer earned.
    #[tokio::test]
    async fn test_a_timeout_does_not_reselect() {
        let slow_port = ephemeral_port();
        let live_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let live_hits = Arc::new(AtomicU64::new(0));

        let slow =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], slow_port)),
            ));
        slow.start(|_r: SbiRequest| async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            SbiResponse::ok()
        })
        .await
        .expect("slow producer start");
        let live = start_named_producer(live_port, "second", live_hits.clone()).await;
        let nrf = start_nrf_serving(nrf_port, uecm_instances(&[slow_port, live_port])).await;

        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(300),
            ..Default::default()
        });
        let response = proxy.handle(model_d_uecm_request()).await;
        assert_eq!(response.status, 504);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("TARGET_NF_NOT_REACHABLE"));
        assert_eq!(
            live_hits.load(Ordering::SeqCst),
            0,
            "a possibly-delivered request must not be replayed on a sibling"
        );

        nrf.stop().await.expect("nrf stop");
        live.stop().await.expect("live stop");
        slow.stop().await.expect("slow stop");
    }

    // ------------------------------------------------------------------
    // scpd-#208: response-relay metadata and retargeting fix-ups
    // (TS 29.500 §6.10.3.4 / §6.10.4)
    // ------------------------------------------------------------------

    /// A producer answering `201` with `Location: <location>`, optionally naming
    /// itself in `3gpp-Sbi-Producer-Id`, and echoing the URI it was asked for.
    async fn start_location_producer(
        port: u16,
        location: Option<&'static str>,
        own_producer_id: Option<&'static str>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| async move {
                let mut response = SbiResponse::with_status(201).with_body(
                    serde_json::json!({"uri": request.header.uri}).to_string(),
                    "application/json",
                );
                if let Some(loc) = location {
                    response.http.set_header("Location", loc);
                }
                if let Some(pid) = own_producer_id {
                    response.http.set_header(custom_header::PRODUCER_ID, pid);
                }
                response
            })
            .await
            .expect("producer start");
        server
    }

    /// A UDM profile on `port` declaring an NF set and a UDM group.
    fn udm_with_set_and_group(port: u16) -> serde_json::Value {
        serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-in-a-set",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["127.0.0.1"],
                "priority": 1,
                "nfSetIdList": ["set1.udmset.5gc.mnc012.mcc345"],
                "udmInfo": {"groupId": "udm-group-7"},
                "nfServices": [{
                    "serviceName": "nudm-uecm",
                    "ipEndPoints": [{"transport": "TCP", "port": port}]
                }]
            }]
        })
    }

    /// scpd-#208 acceptance, the load-bearing one: the relayed `Producer-Id` is
    /// **identical** on a discovery-cache miss and on the following hit.
    ///
    /// The bug was that `nfSetId`/`nfGroupId` were read from the raw SearchResult,
    /// which the cache does not store — so `nfset=` was present on the miss and
    /// gone on the hit, making producer routing metadata depend on SCP cache state
    /// and look intermittent. Asserting only the miss path is exactly what hid it,
    /// so this drives both and compares them.
    #[tokio::test]
    async fn test_producer_id_is_identical_on_a_cache_miss_and_the_following_hit() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let hits = Arc::new(AtomicU64::new(0));

        let producer = start_named_producer(producer_port, "udm", hits.clone()).await;
        let nrf = start_nrf_serving(nrf_port, udm_with_set_and_group(producer_port)).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);
        let mut seen = Vec::new();
        for _ in 0..2 {
            let response = client
                .send_request(model_d_uecm_request())
                .await
                .expect("roundtrip");
            assert_eq!(response.status, 200);
            seen.push((
                response.http.producer_id().cloned(),
                response
                    .http
                    .get_header(custom_header::TARGET_NF_GROUP_ID)
                    .cloned(),
            ));
        }
        // The second request was served from the discovery cache.
        assert_eq!(hits.load(Ordering::SeqCst), 2, "both reached the producer");

        let expected = (
            Some("nfinst=udm-in-a-set; nfset=set1.udmset.5gc.mnc012.mcc345".to_string()),
            Some("udm-group-7".to_string()),
        );
        assert_eq!(seen[0], expected, "cache miss carries set and group");
        assert_eq!(
            seen[1], expected,
            "cache HIT carries the same set and group"
        );
        assert_eq!(
            seen[0], seen[1],
            "producer routing metadata must not depend on SCP cache state"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-#208 acceptance: a `3gpp-Sbi-Producer-Id` the producer (or a downstream
    /// SCP) already supplied is **preserved**, not overwritten.
    ///
    /// The SCP's own value is second-hand — derived from the profile it read — so
    /// where a first-hand one exists it wins. The assertion names the producer's
    /// value explicitly rather than merely checking the header is present, which
    /// would pass against the overwriting code.
    #[tokio::test]
    async fn test_a_downstream_producer_id_is_not_overwritten() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer =
            start_location_producer(producer_port, None, Some("nfinst=downstream-chosen")).await;
        let nrf = start_nrf_serving(nrf_port, udm_with_set_and_group(producer_port)).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_uecm_request())
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 201);
        assert_eq!(
            response.http.producer_id().map(String::as_str),
            Some("nfinst=downstream-chosen"),
            "the downstream value must survive; ours would have been nfinst=udm-in-a-set"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-#208 acceptance: a **relative** `Location` on a 2xx after retargeting
    /// gains `3gpp-Sbi-Target-apiRoot`, and the follow-up the consumer builds from
    /// it **reaches the same producer**.
    ///
    /// The round-trip is the point. Asserting only that the header appears would
    /// pass against a value the consumer cannot use; feeding it back through
    /// `route()`'s Model C path proves it is actionable.
    #[tokio::test]
    async fn test_relative_location_after_retargeting_gains_a_usable_target_apiroot() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer =
            start_location_producer(producer_port, Some("/nudm-uecm/v1/registrations/42"), None)
                .await;
        let nrf = start_nrf_serving(nrf_port, udm_with_set_and_group(producer_port)).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);
        let created = client
            .send_request(model_d_uecm_request())
            .await
            .expect("roundtrip");
        assert_eq!(created.status, 201);
        // The producer's Location is left INTACT — the fix-up is additive.
        assert_eq!(
            created.http.get_header("Location").map(String::as_str),
            Some("/nudm-uecm/v1/registrations/42")
        );
        let api_root = created
            .http
            .get_header(custom_header::TARGET_APIROOT)
            .cloned()
            .expect("a retargeted 2xx with a relative Location conveys the producer apiRoot");
        assert_eq!(api_root, format!("http://127.0.0.1:{producer_port}"));

        // The consumer's follow-up: the relative Location plus the conveyed
        // apiRoot, which is Model C and must reach the same producer.
        let follow_up = SbiRequest::get("/nudm-uecm/v1/registrations/42")
            .with_header(custom_header::TARGET_APIROOT, api_root);
        let response = client
            .send_request(follow_up)
            .await
            .expect("follow-up roundtrip");
        assert_eq!(response.status, 201);
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(
            body["uri"], "/nudm-uecm/v1/registrations/42",
            "the follow-up reached the producer holding the created resource"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-#208: an **absolute** `Location` is already addressable, so it is left
    /// alone and no `Target-apiRoot` is added — the fix-up is narrow rather than
    /// applied to every 2xx.
    #[tokio::test]
    async fn test_absolute_location_gets_no_target_apiroot() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer = start_location_producer(
            producer_port,
            Some("http://udm.example.org:8080/nudm-uecm/v1/registrations/42"),
            None,
        )
        .await;
        let nrf = start_nrf_serving(nrf_port, udm_with_set_and_group(producer_port)).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let response = fast_client(scp_port)
            .send_request(model_d_uecm_request())
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 201);
        assert_eq!(
            response.http.get_header("Location").map(String::as_str),
            Some("http://udm.example.org:8080/nudm-uecm/v1/registrations/42")
        );
        assert!(
            response
                .http
                .get_header(custom_header::TARGET_APIROOT)
                .is_none(),
            "an absolute Location needs no apiRoot annotation"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-#208: Model C gets **no** fix-up even with a relative `Location`. The
    /// consumer named the target itself, so it can already resolve the URI — and
    /// echoing its own apiRoot back at it would be noise.
    #[tokio::test]
    async fn test_model_c_relative_location_is_not_annotated() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer =
            start_location_producer(producer_port, Some("/nudm-uecm/v1/registrations/42"), None)
                .await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations").with_header(
            custom_header::TARGET_APIROOT,
            format!("http://127.0.0.1:{producer_port}"),
        );
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 201);
        assert!(
            response
                .http
                .get_header(custom_header::TARGET_APIROOT)
                .is_none(),
            "Model C is not retargeting: the consumer already knows the apiRoot"
        );

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    // ------------------------------------------------------------------
    // scpd-#210: 3gpp-Sbi-Callback routes without a discovery or OAuth gate
    // (TS 29.500 §6.10.7)
    // ------------------------------------------------------------------

    /// An NRF that **counts every request it receives**, split by endpoint, and
    /// answers discovery with a profile pointing at `producer_port`.
    ///
    /// The counters are the point: the callback path must not touch either
    /// endpoint, and asserting a 200 alone would pass while a token was minted.
    async fn start_counting_nrf(
        port: u16,
        producer_port: u16,
        disc_hits: Arc<AtomicU64>,
        token_hits: Arc<AtomicU64>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let disc_hits = disc_hits.clone();
                let token_hits = token_hits.clone();
                async move {
                    if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                        token_hits.fetch_add(1, Ordering::SeqCst);
                        return SbiResponse::ok().with_body(
                            r#"{"access_token":"scp-test-token","token_type":"Bearer","expires_in":3600}"#.to_string(),
                            "application/json",
                        );
                    }
                    disc_hits.fetch_add(1, Ordering::SeqCst);
                    SbiResponse::ok().with_body(
                        uecm_instances(&[producer_port]).to_string(),
                        "application/json",
                    )
                }
            })
            .await
            .expect("nrf start");
        server
    }

    /// scpd-#210, **the discriminating test**: a callback carrying Discovery
    /// headers and **no** `Target-apiRoot` must go to its callback URI, not take
    /// the delegated path. This is the case the issue names, and it is the only one
    /// where the callback rule changes an outcome.
    ///
    /// With the rule removed, this request routes to `Discover`: the SCP queries
    /// the NRF, mints a token, and delivers the notification to a *discovered
    /// producer* — the wrong node entirely. All three are asserted at zero against
    /// live counters, so none of them can pass by accident.
    ///
    /// In process, necessarily: the destination here comes from the absolute
    /// request URI, which the SBI server discards (see
    /// `test_callback_with_an_absolute_uri_is_routed_in_process`).
    #[tokio::test]
    async fn test_callback_with_discovery_headers_is_not_discovery_gated() {
        let callback_port = ephemeral_port();
        let decoy_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let callback_hits = Arc::new(AtomicU64::new(0));
        let decoy_hits = Arc::new(AtomicU64::new(0));
        let disc_hits = Arc::new(AtomicU64::new(0));
        let token_hits = Arc::new(AtomicU64::new(0));

        let callback_target =
            start_named_producer(callback_port, "callback-target", callback_hits.clone()).await;
        let decoy = start_named_producer(decoy_port, "decoy", decoy_hits.clone()).await;
        let nrf =
            start_counting_nrf(nrf_port, decoy_port, disc_hits.clone(), token_hits.clone()).await;
        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });

        let request = SbiRequest::post(format!(
            "http://127.0.0.1:{callback_port}/namf-comm/v1/subscriptions/1/notify"
        ))
        .with_body(r#"{"event":"ping"}"#, "application/json")
        .with_header(custom_header::CALLBACK, "Namf_Communication_N1N2Notify")
        .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
        .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF");

        let response = proxy.handle(request).await;
        assert_eq!(response.status, 200);
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(body["servedBy"], "callback-target");
        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);

        assert_eq!(
            disc_hits.load(Ordering::SeqCst),
            0,
            "a callback must not trigger a discovery query"
        );
        assert_eq!(
            token_hits.load(Ordering::SeqCst),
            0,
            "a callback must not trigger an access-token request"
        );
        assert_eq!(
            decoy_hits.load(Ordering::SeqCst),
            0,
            "the notification must not be delivered to a discovered producer"
        );

        nrf.stop().await.expect("nrf stop");
        decoy.stop().await.expect("decoy stop");
        callback_target.stop().await.expect("callback stop");
    }

    /// scpd-#210 over the wire: a callback addressed by `3gpp-Sbi-Target-apiRoot`
    /// reaches its target with no discovery and no token.
    ///
    /// **Honest scope: this was already true before the change**, because
    /// `Target-apiRoot` outranks the Discovery headers and the Model C path passes
    /// `delegated: None`. It is kept as a *regression* guard — the callback rule now
    /// runs ahead of that precedence, and this pins that it did not disturb the
    /// outcome — not as evidence the rule does anything here. The test that
    /// discriminates is `test_callback_with_discovery_headers_is_not_discovery_gated`.
    #[tokio::test]
    async fn test_callback_routes_without_discovery_or_token() {
        let callback_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let callback_hits = Arc::new(AtomicU64::new(0));
        let disc_hits = Arc::new(AtomicU64::new(0));
        let token_hits = Arc::new(AtomicU64::new(0));
        // A producer the SCP would have discovered had it taken the delegated path.
        let decoy_port = ephemeral_port();
        let decoy_hits = Arc::new(AtomicU64::new(0));

        let callback_target =
            start_named_producer(callback_port, "callback-target", callback_hits.clone()).await;
        let decoy = start_named_producer(decoy_port, "decoy", decoy_hits.clone()).await;
        let nrf =
            start_counting_nrf(nrf_port, decoy_port, disc_hits.clone(), token_hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        // A notification, marked as a callback, addressed by Target-apiRoot, and
        // carrying Discovery headers the SCP must now ignore.
        let request = SbiRequest::post("/namf-comm/v1/subscriptions/1/notify")
            .with_body(r#"{"event":"ping"}"#, "application/json")
            .with_header(custom_header::CALLBACK, "Namf_Communication_N1N2Notify")
            .with_header(
                custom_header::TARGET_APIROOT,
                format!("http://127.0.0.1:{callback_port}"),
            )
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF");

        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("callback roundtrip");
        assert_eq!(response.status, 200);
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(body["servedBy"], "callback-target");
        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);

        // The load-bearing assertions.
        assert_eq!(
            disc_hits.load(Ordering::SeqCst),
            0,
            "a callback must not trigger a discovery query"
        );
        assert_eq!(
            token_hits.load(Ordering::SeqCst),
            0,
            "a callback must not trigger an access-token request"
        );
        assert_eq!(
            decoy_hits.load(Ordering::SeqCst),
            0,
            "the notification must not reach a discovered producer"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        decoy.stop().await.expect("decoy stop");
        callback_target.stop().await.expect("callback stop");
    }

    /// scpd-#210: a callback whose destination comes from an **absolute request
    /// URI** rather than `Target-apiRoot`, with no Discovery headers at all.
    ///
    /// **This test drives `handle()` in process, deliberately, and that is a
    /// statement about reachability rather than convenience.** The shared SBI
    /// server keeps only the path — `libs/nextgcore-sbi/src/server.rs:563` is
    /// `req.uri().path().to_string()` — and over HTTP/2 the authority a consumer
    /// dialled is the SCP's own. So an absolute callback URI **cannot** survive
    /// the wire hop into `route()`, and an end-to-end test asserting this would be
    /// asserting something the transport makes impossible. The branch is kept
    /// because `handle` is public and because it is the correct handling if the
    /// ingress ever preserves the authority; it is not claimed as wire behaviour.
    ///
    /// Also pins the URI rewrite: the target receives the origin-form path with
    /// its query intact, not the absolute URI.
    #[tokio::test]
    async fn test_callback_with_an_absolute_uri_is_routed_in_process() {
        let callback_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let callback_hits = Arc::new(AtomicU64::new(0));
        let disc_hits = Arc::new(AtomicU64::new(0));
        let token_hits = Arc::new(AtomicU64::new(0));

        let callback_target =
            start_named_producer(callback_port, "callback-target", callback_hits.clone()).await;
        let nrf = start_counting_nrf(
            nrf_port,
            callback_port,
            disc_hits.clone(),
            token_hits.clone(),
        )
        .await;
        let proxy = ScpProxy::new(ScpProxyConfig {
            nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
            connect_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            ..Default::default()
        });

        let request = SbiRequest::post(format!(
            "http://127.0.0.1:{callback_port}/namf-comm/v1/subscriptions/1/notify"
        ))
        .with_body(r#"{"event":"ping"}"#, "application/json")
        .with_header(custom_header::CALLBACK, "Namf_Communication_N1N2Notify");

        let response = proxy.handle(request).await;
        assert_eq!(
            response.status, 200,
            "a fully-specified callback must not be rejected for want of Discovery headers"
        );
        let body: serde_json::Value = response.json_body().unwrap();
        assert_eq!(body["servedBy"], "callback-target");
        assert_eq!(
            body["uri"], "/namf-comm/v1/subscriptions/1/notify",
            "the callback target receives the origin-form path, not the absolute URI"
        );
        assert_eq!(disc_hits.load(Ordering::SeqCst), 0);
        assert_eq!(token_hits.load(Ordering::SeqCst), 0);
        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);

        nrf.stop().await.expect("nrf stop");
        callback_target.stop().await.expect("callback stop");
    }

    /// scpd-#210 unit: `3gpp-Sbi-Callback` outranks Routing-Binding and the
    /// Discovery headers, takes its address from `Target-apiRoot` when present, and
    /// falls through to ordinary routing when it names no destination at all.
    #[test]
    fn test_callback_route_precedence() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());

        // Callback + Target-apiRoot + Discovery headers -> Callback, addressed by
        // the Target-apiRoot, with no URI rewrite (the request URI is relative).
        let mut req = SbiRequest::get("/namf-comm/v1/x");
        req.http.set_header(custom_header::CALLBACK, "Notify");
        req.http.set_target_apiroot("http://amf:8080");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        assert_eq!(
            proxy.route(&req),
            RouteDecision::Callback {
                target: ApiRoot::parse("http://amf:8080").unwrap(),
                forward_uri: None,
            }
        );

        // Callback + absolute URI, nothing else -> Callback, with the path split out.
        let mut req = SbiRequest::get("http://amf:8080/namf-comm/v1/x?y=1");
        req.http.set_header(custom_header::CALLBACK, "Notify");
        assert_eq!(
            proxy.route(&req),
            RouteDecision::Callback {
                target: ApiRoot::parse("http://amf:8080").unwrap(),
                forward_uri: Some("/namf-comm/v1/x?y=1".to_string()),
            }
        );

        // Callback beats a KNOWN Routing-Binding, which would otherwise win.
        let bound = ApiRoot::parse("http://udm2:7777").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=cb-known", &bound);
        let mut req = SbiRequest::get("http://amf:8080/namf-comm/v1/x");
        req.http.set_header(custom_header::CALLBACK, "Notify");
        req.http
            .set_routing_binding("bl=nf-instance; nfinst=cb-known");
        assert!(matches!(
            proxy.route(&req),
            RouteDecision::Callback { target, .. } if target != bound
        ));

        // Callback naming no destination falls THROUGH rather than rejecting, so a
        // deployment whose callbacks currently reach their target via Discovery
        // headers is not regressed.
        let mut req = SbiRequest::get("/namf-comm/v1/x");
        req.http.set_header(custom_header::CALLBACK, "Notify");
        req.http.set_header(discovery_header::TARGET_NF_TYPE, "UDM");
        assert_eq!(proxy.route(&req), RouteDecision::Discover);

        // ...and with nothing to fall through to, it is still a Reject.
        let mut req = SbiRequest::get("/namf-comm/v1/x");
        req.http.set_header(custom_header::CALLBACK, "Notify");
        assert_eq!(proxy.route(&req), RouteDecision::Reject);
    }

    /// scpd-#210 unit: `split_absolute_uri`.
    #[test]
    fn test_split_absolute_uri_unit() {
        assert_eq!(
            split_absolute_uri("http://h:1/a/b?q=1"),
            Some(("http://h:1".to_string(), "/a/b?q=1".to_string()))
        );
        assert_eq!(
            split_absolute_uri("https://h/a"),
            Some(("https://h".to_string(), "/a".to_string()))
        );
        // No path at all still yields a forwardable origin-form root.
        assert_eq!(
            split_absolute_uri("http://h:1"),
            Some(("http://h:1".to_string(), "/".to_string()))
        );
        // A deployment prefix stays in the PATH, so `forward_once` prepending
        // `target.prefix` cannot emit it twice.
        assert_eq!(
            split_absolute_uri("http://h:1/deploy/namf-comm/v1/x"),
            Some((
                "http://h:1".to_string(),
                "/deploy/namf-comm/v1/x".to_string()
            ))
        );
        // Relative URIs and empty authorities are not callback destinations.
        assert_eq!(split_absolute_uri("/namf-comm/v1/x"), None);
        assert_eq!(split_absolute_uri("http:///a"), None);
        assert_eq!(split_absolute_uri("ftp://h/a"), None);
    }

    /// When no NRF (and thus no OAuth2 client) is configured, a Model C forward
    /// leaves the consumer's Authorization untouched (the consumer remains the
    /// OAuth2 client; the SCP does not strip or replace it).
    #[tokio::test]
    async fn test_model_c_preserves_consumer_authorization() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_auth_echo_producer(producer_port).await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            )
            .with_header("Authorization", "Bearer consumer-token");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("model C roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["authorization"], "Bearer consumer-token");

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    // ------------------------------------------------------------------
    // scpd-03/04/05/06/07/08/09/10/11/12: relaying obligations, loop
    // protection, ck-stripping, full discovery factors, token retry,
    // discovery cache, apiPrefix, next-hop-SCP, set-aware stickiness,
    // producer-id / group-id.
    // ------------------------------------------------------------------

    /// A producer that always answers a fixed error status with a small body.
    async fn start_status_producer(port: u16, status: u16) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |_request: SbiRequest| async move {
                SbiResponse::with_status(status).with_body(
                    format!(r#"{{"status":{status},"cause":"PRODUCER_ERROR"}}"#),
                    "application/problem+json",
                )
            })
            .await
            .expect("producer start");
        server
    }

    /// A producer that 401s (Bearer challenge) for its first `fail_count`
    /// requests, then answers 200 — used to drive the scpd-07 token retry.
    async fn start_token_gated_producer(
        port: u16,
        fail_count: u64,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        let calls = Arc::new(AtomicU64::new(0));
        server
            .start(move |_request: SbiRequest| {
                let calls = calls.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    if n < fail_count {
                        SbiResponse::with_status(401)
                            .with_body(
                                r#"{"status":401,"cause":"UNAUTHORIZED"}"#,
                                "application/problem+json",
                            )
                            .with_header(
                                "WWW-Authenticate",
                                r#"Bearer realm="5gc", error="invalid_token""#,
                            )
                    } else {
                        SbiResponse::ok().with_body(r#"{"ok":true}"#, "application/json")
                    }
                }
            })
            .await
            .expect("producer start");
        server
    }

    /// An NRF whose nnrf-disc records every query parameter it received into
    /// `captured`, then returns a one-producer SearchResult.
    async fn start_mock_nrf_capturing(
        port: u16,
        producer_port: u16,
        captured: Arc<std::sync::Mutex<HashMap<String, String>>>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |request: SbiRequest| {
                let captured = captured.clone();
                async move {
                    // Serve the SCP's delegated OAuth2 token before discovery
                    // capture, so the token request is not recorded as a factor.
                    if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                        return SbiResponse::ok().with_body(
                            r#"{"access_token":"scp-test-token","token_type":"Bearer","expires_in":3600}"#.to_string(),
                            "application/json",
                        );
                    }
                    if let Ok(mut map) = captured.lock() {
                        for (k, v) in &request.http.params {
                            map.insert(k.clone(), v.clone());
                        }
                    }
                    let search_result = serde_json::json!({
                        "validityPeriod": 3600,
                        "nfInstances": [{
                            "nfInstanceId": "udm-instance-1",
                            "nfType": "UDM",
                            "nfStatus": "REGISTERED",
                            "ipv4Addresses": ["127.0.0.1"],
                            "nfServices": [{
                                "serviceName": "nudm-uecm",
                                "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                            }]
                        }]
                    });
                    SbiResponse::ok().with_body(search_result.to_string(), "application/json")
                }
            })
            .await
            .expect("nrf start");
        server
    }

    /// scpd-03: an SCP-originated error (here a routing Reject) carries the
    /// SCP's own identity in the `Server` header.
    #[tokio::test]
    async fn test_scp_originated_error_carries_server_header() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let response = proxy.handle(SbiRequest::get("/nudm-sdm/v1/x")).await;
        assert_eq!(response.status, 400);
        assert_eq!(
            response.http.get_header(SERVER_HEADER).map(String::as_str),
            Some("SCP-scp.5gc.local")
        );
    }

    /// scpd-03: a relayed producer 4xx/5xx gains the SCP's `Via` while the
    /// body and status stay verbatim; the SCP does not stamp `Server` on it.
    #[tokio::test]
    async fn test_relayed_error_gains_via_verbatim_body() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_status_producer(producer_port, 409).await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations").with_header(
            "3gpp-Sbi-Target-apiRoot",
            format!("http://127.0.0.1:{producer_port}"),
        );
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("error relay roundtrip");

        assert_eq!(response.status, 409);
        assert!(response
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("PRODUCER_ERROR"));
        // Via appended on the relayed error (TS 29.500 §6.10.8.3).
        assert_eq!(
            response.http.get_header(VIA_HEADER).map(String::as_str),
            Some("2.0 SCP-scp.5gc.local")
        );
        // Relayed (not SCP-originated) → no Server header added by the SCP.
        assert!(response.http.get_header(SERVER_HEADER).is_none());

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-04: a request whose `Via` already lists this SCP loops → 400
    /// MSG_LOOP_DETECTED before any forwarding.
    #[tokio::test]
    async fn test_ingress_via_loop_detected() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let req = SbiRequest::get("/nudm-sdm/v1/x")
            .with_header("Via", "2.0 SCP-scp.5gc.local")
            .with_header("3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:1");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 400);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("MSG_LOOP_DETECTED"));
        assert_eq!(
            response.http.get_header(SERVER_HEADER).map(String::as_str),
            Some("SCP-scp.5gc.local")
        );
    }

    /// scpd-04: an exhausted scp-typed Max-Forward-Hops → 502
    /// MAX_SCP_HOPS_REACHED.
    #[tokio::test]
    async fn test_ingress_max_hops_reached() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let req = SbiRequest::get("/nudm-sdm/v1/x")
            .with_header(MAX_FORWARD_HOPS_HEADER, "0; nodetype=scp")
            .with_header("3gpp-Sbi-Target-apiRoot", "http://127.0.0.1:1");
        let response = proxy.handle(req).await;
        assert_eq!(response.status, 502);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("MAX_SCP_HOPS_REACHED"));
    }

    /// scpd-04: a normal forward decrements the scp-typed hop count and inserts
    /// the SCP's own Via on the request seen by the producer.
    #[tokio::test]
    async fn test_forward_decrements_hops_and_inserts_via() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_mock_producer(producer_port).await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::get("/nudm-uecm/v1/registrations")
            .with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            )
            .with_header("3gpp-Sbi-Max-Forward-Hops", "5; nodetype=scp");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["maxHops"], "4; nodetype=scp");
        assert_eq!(
            echoed["via"].as_str(),
            Some("2.0 SCP-scp.5gc.local"),
            "the producer must see the SCP's inserted Via"
        );

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-05: the `ck` cache-key param is stripped before forwarding; other
    /// params pass through (TS 29.500 §6.10.2.6).
    #[tokio::test]
    async fn test_ck_cache_key_param_is_stripped() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_mock_producer(producer_port).await;
        let scp = start_scp(scp_port, ScpProxyConfig::default()).await;

        let request = SbiRequest::get("/nudm-uecm/v1/registrations")
            .with_param("ck", "cache-key-abc")
            .with_param("k", "v")
            .with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            );
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["param"], "v");
        assert!(
            echoed["ck"].is_null(),
            "ck must not reach the producer, got: {}",
            echoed["ck"]
        );

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-06: every conveyed `3gpp-Sbi-Discovery-*` factor is forwarded to the
    /// NRF as its nnrf-disc query parameter.
    #[tokio::test]
    async fn test_all_discovery_factors_forwarded_to_nrf() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let captured = Arc::new(std::sync::Mutex::new(HashMap::new()));

        let producer = start_mock_producer(producer_port).await;
        let nrf = start_mock_nrf_capturing(nrf_port, producer_port, captured.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        // NOTE: the factor *values* here are query-safe tokens, which keeps this
        // test about the header→param *mapping* (scpd-06) and nothing else. The
        // lib gap this note used to cite is closed: the client percent-encodes
        // query values (#101) and the server percent-decodes them (#65), so a
        // reserved-character factor now survives the proxy hop too — see
        // `server_percent_decodes_query_parameters` in nextgcore-sbi.
        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm")
            .with_header("3gpp-Sbi-Discovery-guami", "001-01-cafe00")
            .with_header("3gpp-Sbi-Discovery-tai", "001-01-000001")
            .with_header("3gpp-Sbi-Discovery-target-plmn-list", "001-01")
            .with_header("3gpp-Sbi-Discovery-requester-features", "2b");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);

        // Snapshot the captured params (releasing the lock) before any await.
        let params: HashMap<String, String> = captured.lock().unwrap().clone();
        assert_eq!(
            params.get("target-nf-type").map(String::as_str),
            Some("UDM")
        );
        assert_eq!(
            params.get("requester-nf-type").map(String::as_str),
            Some("AMF")
        );
        assert_eq!(
            params.get("service-names").map(String::as_str),
            Some("nudm-uecm")
        );
        assert!(params.contains_key("guami"), "guami factor forwarded");
        assert!(params.contains_key("tai"), "tai factor forwarded");
        assert!(
            params.contains_key("target-plmn-list"),
            "target-plmn-list factor forwarded"
        );
        assert_eq!(
            params.get("requester-features").map(String::as_str),
            Some("2b")
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-07: a delegated forward that the producer 401s with a Bearer
    /// challenge invalidates the cached token, mints a fresh one and retries
    /// once — the consumer sees 200 and the NRF served ≥2 token requests.
    #[tokio::test]
    async fn test_delegated_401_refreshes_token_and_retries_once() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let token_hits = Arc::new(AtomicU64::new(0));

        let producer = start_token_gated_producer(producer_port, 1).await;
        let nrf = start_mock_nrf_with_oauth2(
            nrf_port,
            producer_port,
            "scp-delegated-token",
            token_hits.clone(),
        )
        .await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_body(r#"{"amf":"reg"}"#, "application/json")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");

        assert_eq!(response.status, 200, "retry with fresh token succeeds");
        assert!(
            token_hits.load(Ordering::SeqCst) >= 2,
            "the SCP must mint a second token after the 401, got {}",
            token_hits.load(Ordering::SeqCst)
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-07: a producer that keeps returning 401 → the response is relayed
    /// to the consumer after the single retry.
    #[tokio::test]
    async fn test_delegated_persistent_401_is_relayed() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let token_hits = Arc::new(AtomicU64::new(0));

        let producer = start_token_gated_producer(producer_port, u64::MAX).await;
        let nrf = start_mock_nrf_with_oauth2(
            nrf_port,
            producer_port,
            "scp-delegated-token",
            token_hits.clone(),
        )
        .await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                nf_instance_id: Some("scp-instance-1".into()),
                ..Default::default()
            },
        )
        .await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header(discovery_header::TARGET_NF_TYPE, "UDM")
            .with_header(discovery_header::REQUESTER_NF_TYPE, "AMF")
            .with_header(discovery_header::SERVICE_NAMES, "nudm-uecm");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 401, "persistent 401 is relayed verbatim");

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-08: two consecutive Model D requests for the same target produce a
    /// single NRF discovery hit (the second is served from the cache).
    #[tokio::test]
    async fn test_discovery_cache_serves_second_request() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let nrf_hits = Arc::new(AtomicU64::new(0));

        let producer = start_mock_producer(producer_port).await;
        let nrf = start_mock_nrf(nrf_port, producer_port, nrf_hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);
        for _ in 0..2 {
            let request = SbiRequest::post("/nudm-uecm/v1/registrations")
                .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
                .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
                .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");
            let response = client.send_request(request).await.expect("roundtrip");
            assert_eq!(response.status, 200);
        }
        assert_eq!(
            nrf_hits.load(Ordering::SeqCst),
            1,
            "second Model D request must be served from the discovery cache"
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd (TS 29.500 §6.10.11.2.2A): on the Model D delegated path, if the NRF
    /// rejects the SCP's access-token request, the SCP must surface 403 with
    /// cause ACCESS_TOKEN_DENIED rather than forwarding tokenless.
    #[tokio::test]
    async fn test_delegated_token_rejection_maps_to_403() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer = start_mock_producer(producer_port).await;
        // NRF answers discovery but rejects the access-token request (not with
        // MISSING_PARAMETER) — the SCP must map this to 403 ACCESS_TOKEN_DENIED.
        let nrf_server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], nrf_port)),
            ));
        nrf_server
            .start(move |request: SbiRequest| async move {
                if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                    return SbiResponse::with_status(403).with_body(
                        r#"{"error":"invalid_client"}"#.to_string(),
                        "application/json",
                    );
                }
                let search_result = serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "udm-instance-1",
                        "nfType": "UDM",
                        "nfStatus": "REGISTERED",
                        "ipv4Addresses": ["127.0.0.1"],
                        "nfServices": [{
                            "serviceName": "nudm-uecm",
                            "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                        }]
                    }]
                });
                SbiResponse::ok().with_body(search_result.to_string(), "application/json")
            })
            .await
            .expect("nrf start");

        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);
        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");
        let response = client.send_request(request).await.expect("roundtrip");
        assert_eq!(response.status, 403);
        assert!(response
            .http
            .content
            .as_deref()
            .unwrap_or_default()
            .contains("ACCESS_TOKEN_DENIED"));

        scp.stop().await.expect("scp stop");
        nrf_server.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-09: a discovered `apiPrefix` is prepended to the forwarded request
    /// URI seen by the producer.
    #[tokio::test]
    async fn test_apiprefix_propagates_into_forwarded_uri() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer = start_mock_producer(producer_port).await;
        let nrf_server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], nrf_port)),
            ));
        nrf_server
            .start(move |request: SbiRequest| async move {
                // A real NRF serves both nnrf-disc and nnrf-oauth2; the SCP
                // acquires a delegated token before forwarding (TS 33.501 §13).
                if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                    return SbiResponse::ok().with_body(
                        r#"{"access_token":"scp-test-token","token_type":"Bearer","expires_in":3600}"#.to_string(),
                        "application/json",
                    );
                }
                let search_result = serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "udm-prefixed",
                        "nfType": "UDM",
                        "nfStatus": "REGISTERED",
                        "ipv4Addresses": ["127.0.0.1"],
                        "nfServices": [{
                            "serviceName": "nudm-uecm",
                            "apiPrefix": "/deploy",
                            "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                        }]
                    }]
                });
                SbiResponse::ok().with_body(search_result.to_string(), "application/json")
            })
            .await
            .expect("nrf start");
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["uri"], "/deploy/nudm-uecm/v1/registrations");

        scp.stop().await.expect("scp stop");
        nrf_server.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-10: with next-hop-SCP enabled, the forwarded request carries the
    /// selected producer apiRoot in `3gpp-Sbi-Target-apiRoot` (instead of being
    /// stripped as in the default next-hop-producer deployment).
    #[tokio::test]
    async fn test_next_hop_scp_reinserts_target_apiroot() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_mock_producer(producer_port).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                next_hop_scp: true,
                ..Default::default()
            },
        )
        .await;

        let producer_apiroot = format!("http://127.0.0.1:{producer_port}");
        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Target-apiRoot", producer_apiroot.clone());
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);
        let echoed: serde_json::Value = response.json_body().unwrap();
        assert_eq!(echoed["sawTargetApiroot"], true);
        assert_eq!(
            echoed["targetApiroot"].as_str(),
            Some(producer_apiroot.as_str())
        );

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-11: an `nf-set` Routing-Binding reselects another learnt set member
    /// when the originally-bound instance is gone; an `nf-instance` binding to
    /// an unknown instance does not fall through to a set.
    #[test]
    fn test_set_aware_binding_reselection() {
        let proxy = ScpProxy::new(ScpProxyConfig::default());
        let member = ApiRoot::parse("http://smf-setmember:7778").unwrap();
        let pinned = ApiRoot::parse("http://smf-pinned:7778").unwrap();

        // Learn a set member (via a producer Binding) and a pinned instance.
        proxy.binding_store("bl=nf-set; nfset=setA.smfset.5gc; nfinst=i-orig", &member);
        proxy.binding_store("bl=nf-instance; nfinst=i-pinned", &pinned);

        // Exact instance binding still pins to the exact instance.
        let mut pin_req = SbiRequest::get("/nsmf-pdusession/v1/x");
        pin_req
            .http
            .set_routing_binding("bl=nf-instance; nfinst=i-pinned");
        assert!(matches!(proxy.route(&pin_req), RouteDecision::StickyBinding(t) if t == pinned));

        // Set-level binding naming a now-gone instance reselects a set member.
        let mut set_req = SbiRequest::get("/nsmf-pdusession/v1/x");
        set_req
            .http
            .set_routing_binding("bl=nf-set; nfset=setA.smfset.5gc; nfinst=i-gone");
        assert!(matches!(proxy.route(&set_req), RouteDecision::StickyBinding(t) if t == member));

        // An nf-instance binding to an unknown instance does NOT match a set.
        let mut unknown = SbiRequest::get("/nsmf-pdusession/v1/x");
        unknown
            .http
            .set_routing_binding("bl=nf-instance; nfinst=i-unknown");
        assert_eq!(proxy.route(&unknown), RouteDecision::Reject);
    }

    /// scpd-12: a sticky (non-delegated) reselection still reports the bound
    /// producer to the consumer via `3gpp-Sbi-Producer-Id` in `nfinst=` form.
    #[tokio::test]
    async fn test_sticky_reselection_reports_producer_id() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let nrf_hits = Arc::new(AtomicU64::new(0));

        let producer = start_mock_producer(producer_port).await;
        let nrf = start_mock_nrf(nrf_port, producer_port, nrf_hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;
        let client = fast_client(scp_port);

        // Model D to learn the producer's Binding (bl=nf-instance; nfinst=producer-1).
        let model_d = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");
        let resp = client.send_request(model_d).await.expect("model D");
        let binding = resp.http.binding().cloned().expect("binding");

        // Sticky request: the response carries the bound producer id in nfinst= form.
        let sticky = SbiRequest::get("/nudm-uecm/v1/registrations/1")
            .with_header("3gpp-Sbi-Routing-Binding", binding);
        let resp = client.send_request(sticky).await.expect("sticky");
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.http.producer_id().map(String::as_str),
            Some("nfinst=producer-1")
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-12: a Model D selection of a group-member producer carries
    /// `3gpp-Sbi-Target-Nf-Group-Id`; scpd-02: also a `nfinst=...; nfset=...`
    /// Producer-Id when the profile declares an NF set.
    #[tokio::test]
    async fn test_group_and_set_member_selection_reports_ids() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer = start_mock_producer(producer_port).await;
        let nrf_server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                SocketAddr::from(([127, 0, 0, 1], nrf_port)),
            ));
        nrf_server
            .start(move |request: SbiRequest| async move {
                // A real NRF serves both nnrf-disc and nnrf-oauth2; the SCP
                // acquires a delegated token before forwarding (TS 33.501 §13).
                if request.header.uri == "/nnrf-oauth2/v1/access-token" {
                    return SbiResponse::ok().with_body(
                        r#"{"access_token":"scp-test-token","token_type":"Bearer","expires_in":3600}"#.to_string(),
                        "application/json",
                    );
                }
                let search_result = serde_json::json!({
                    "validityPeriod": 3600,
                    "nfInstances": [{
                        "nfInstanceId": "udm-grouped",
                        "nfType": "UDM",
                        "nfStatus": "REGISTERED",
                        "ipv4Addresses": ["127.0.0.1"],
                        "nfSetIdList": ["set1.udmset.5gc.mnc012.mcc345"],
                        "udmInfo": {"groupId": "udm-group-1"},
                        "nfServices": [{
                            "serviceName": "nudm-uecm",
                            "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
                        }]
                    }]
                });
                SbiResponse::ok().with_body(search_result.to_string(), "application/json")
            })
            .await
            .expect("nrf start");
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 200);
        // scpd-02: Producer-Id carries both nfinst and nfset.
        assert_eq!(
            response.http.producer_id().map(String::as_str),
            Some("nfinst=udm-grouped; nfset=set1.udmset.5gc.mnc012.mcc345")
        );
        // scpd-12: group membership surfaced as Target-Nf-Group-Id.
        assert_eq!(
            response
                .http
                .get_header(custom_header::TARGET_NF_GROUP_ID)
                .map(String::as_str),
            Some("udm-group-1")
        );

        scp.stop().await.expect("scp stop");
        nrf_server.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-02: a relayed producer error (no reselection) carries NO
    /// Producer-Id (status-gated to 2xx), but still gains the relay Via.
    #[tokio::test]
    async fn test_relayed_500_carries_no_producer_id() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let nrf_hits = Arc::new(AtomicU64::new(0));

        let producer = start_status_producer(producer_port, 500).await;
        let nrf = start_mock_nrf(nrf_port, producer_port, nrf_hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                nrf_uri: Some(format!("http://127.0.0.1:{nrf_port}")),
                ..Default::default()
            },
        )
        .await;

        let request = SbiRequest::post("/nudm-uecm/v1/registrations")
            .with_header("3gpp-Sbi-Discovery-target-nf-type", "UDM")
            .with_header("3gpp-Sbi-Discovery-requester-nf-type", "AMF")
            .with_header("3gpp-Sbi-Discovery-service-names", "nudm-uecm");
        let response = fast_client(scp_port)
            .send_request(request)
            .await
            .expect("roundtrip");
        assert_eq!(response.status, 500);
        assert!(
            response.http.producer_id().is_none(),
            "no Producer-Id on a relayed error without reselection"
        );
        assert_eq!(
            response.http.get_header(VIA_HEADER).map(String::as_str),
            Some("2.0 SCP-scp.5gc.local")
        );

        scp.stop().await.expect("scp stop");
        nrf.stop().await.expect("nrf stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-04 unit: Max-Forward-Hops parsing.
    #[test]
    fn test_parse_max_forward_hops_unit() {
        assert_eq!(
            parse_max_forward_hops("5; nodetype=scp"),
            Some((5, Some("scp".to_string())))
        );
        assert_eq!(parse_max_forward_hops("0"), Some((0, None)));
        assert_eq!(parse_max_forward_hops("notanumber"), None);
    }

    /// scpd-02 unit: Producer-Id ABNF builder.
    #[test]
    fn test_build_producer_id_unit() {
        assert_eq!(
            build_producer_id("uuid-1", None).as_deref(),
            Some("nfinst=uuid-1")
        );
        assert_eq!(
            build_producer_id("uuid-1", Some("setX")).as_deref(),
            Some("nfinst=uuid-1; nfset=setX")
        );
        assert_eq!(build_producer_id("", Some("setX")), None);
    }

    /// scpd-06 unit: discovery-header → nnrf-disc param mapping.
    #[test]
    fn test_nnrf_disc_param_mapping_unit() {
        assert_eq!(
            nnrf_disc_param_from_discovery_header("3gpp-Sbi-Discovery-guami").as_deref(),
            Some("guami")
        );
        // case-insensitive prefix, lowercased param
        assert_eq!(
            nnrf_disc_param_from_discovery_header("3GPP-SBI-DISCOVERY-Target-Plmn-List").as_deref(),
            Some("target-plmn-list")
        );
        // out-of-band / non-disc factors are skipped
        assert_eq!(
            nnrf_disc_param_from_discovery_header("3gpp-Sbi-Discovery-target-nf-type"),
            None
        );
        assert_eq!(
            nnrf_disc_param_from_discovery_header("3gpp-Sbi-Discovery-hnrf-uri"),
            None
        );
        assert_eq!(nnrf_disc_param_from_discovery_header("content-type"), None);
    }

    // ------------------------------------------------------------------
    // scpd-#102: tokenised Via, bounded caches, per-endpoint circuit breaker
    // ------------------------------------------------------------------

    /// scpd-#102: loop detection is over discrete `Via` tokens, not a substring
    /// of the concatenated value. A peer token that is a strict superstring of
    /// this SCP's identity must NOT be treated as a loop; an exact self-token
    /// must be.
    #[test]
    fn test_via_loop_detection_is_tokenised() {
        // Default identity is SCP-scp.5gc.local.
        let proxy = ScpProxy::new(ScpProxyConfig::default());

        // Exact self-token -> loop.
        assert!(proxy.via_lists_self("2.0 SCP-scp.5gc.local"));
        // Case-insensitive exact match -> loop.
        assert!(proxy.via_lists_self("2.0 scp-SCP.5GC.LOCAL"));
        // Strict superstring peer token -> NOT a loop (the substring-match bug).
        assert!(!proxy.via_lists_self("2.0 SCP-scp.5gc.local2"));
        // An exact self-token among several Via elements -> loop.
        assert!(proxy.via_lists_self("2.0 SCP-other.example, 2.0 SCP-scp.5gc.local"));
        // A trailing RFC 9110 comment is ignored around the token.
        assert!(proxy.via_lists_self("2.0 SCP-scp.5gc.local (nextgcore)"));
        // No self-token anywhere -> not a loop.
        assert!(!proxy.via_lists_self("2.0 SCP-a.example, 2.0 SCP-b.example"));
    }

    /// scpd-#102 end-to-end: a `Via` peer token that is a strict superstring of
    /// this SCP's identity is NOT rejected as a loop (it proceeds to forward),
    /// whereas the exact self-token IS rejected `MSG_LOOP_DETECTED`.
    #[tokio::test]
    async fn test_ingress_via_superstring_is_not_a_loop() {
        let proxy = ScpProxy::new(ScpProxyConfig {
            connect_timeout: Duration::from_millis(300),
            request_timeout: Duration::from_millis(300),
            ..Default::default()
        });

        // Superstring peer identity: not a loop, so it forwards and fails to
        // reach the (refused) port 1 -> 502, NOT 400 MSG_LOOP_DETECTED.
        let mut req = SbiRequest::get("/nudm-sdm/v1/x");
        req.http.set_header("Via", "2.0 SCP-scp.5gc.local2");
        req.http.set_target_apiroot("http://127.0.0.1:1");
        let response = proxy.handle(req).await;
        assert_ne!(
            response.status, 400,
            "a superstring peer Via token must not be treated as a loop"
        );

        // Exact self-token IS a loop.
        let mut looped = SbiRequest::get("/nudm-sdm/v1/x");
        looped.http.set_header("Via", "2.0 SCP-scp.5gc.local");
        looped.http.set_target_apiroot("http://127.0.0.1:1");
        let response = proxy.handle(looped).await;
        assert_eq!(response.status, 400);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("MSG_LOOP_DETECTED"));
    }

    /// scpd-#102: purge_expired_caches (called periodically from the main loop)
    /// reclaims expired entries so the bounded caches shrink between inserts.
    #[test]
    fn test_purge_expired_caches_shrinks() {
        // cache_ttl of zero => every entry is immediately expired.
        let proxy = ScpProxy::new(ScpProxyConfig {
            cache_ttl: Duration::ZERO,
            ..Default::default()
        });
        let target = ApiRoot::parse("http://smf1:7778").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=x", &target);
        assert_eq!(proxy.bindings.len(), 1, "entry present until purged");
        proxy.purge_expired_caches();
        assert_eq!(proxy.bindings.len(), 0, "purge reclaims the expired entry");
    }

    /// scpd-#102: the proxy caches are bounded — inserting past the ceiling
    /// evicts the oldest entry rather than growing without limit.
    #[test]
    fn test_binding_cache_is_bounded() {
        let proxy = ScpProxy::new(ScpProxyConfig {
            max_cache_entries: 2,
            ..Default::default()
        });
        let t = ApiRoot::parse("http://smf:7778").unwrap();
        proxy.binding_store("bl=nf-instance; nfinst=a", &t);
        proxy.binding_store("bl=nf-instance; nfinst=b", &t);
        proxy.binding_store("bl=nf-instance; nfinst=c", &t);
        assert_eq!(
            proxy.bindings.len(),
            2,
            "the binding cache honours its bound"
        );
    }

    /// A producer that always answers 500 and counts the requests that reach it.
    async fn start_counting_500_producer(
        port: u16,
        hits: Arc<AtomicU64>,
    ) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(
            nextgcore_sbi::server::SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
        );
        server
            .start(move |_request: SbiRequest| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    SbiResponse::with_status(500).with_body(
                        r#"{"status":500,"cause":"INTERNAL"}"#,
                        "application/problem+json",
                    )
                }
            })
            .await
            .expect("producer start");
        server
    }

    /// scpd-#102: repeated producer 5xx trips the per-endpoint circuit breaker;
    /// once Open the SCP sheds load with a 503 without contacting the producer,
    /// and after the open timeout admits a single half-open probe.
    #[tokio::test]
    async fn test_circuit_breaker_opens_sheds_load_then_probes() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let hits = Arc::new(AtomicU64::new(0));

        let producer = start_counting_500_producer(producer_port, hits.clone()).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                circuit_failure_threshold: 2,
                circuit_open_timeout: Duration::from_millis(200),
                ..Default::default()
            },
        )
        .await;

        let client = fast_client(scp_port);
        let make = || {
            SbiRequest::post("/nudm-uecm/v1/registrations").with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            )
        };

        // Two 5xx forwards reach the producer and trip the breaker.
        assert_eq!(client.send_request(make()).await.unwrap().status, 500);
        assert_eq!(client.send_request(make()).await.unwrap().status, 500);
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // Circuit now Open: the next request is shed with 503, producer untouched.
        let shed = client.send_request(make()).await.unwrap();
        assert_eq!(shed.status, 503);
        let problem: ProblemDetails = shed.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("TARGET_NF_NOT_REACHABLE"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "an open circuit must not contact the producer"
        );
        // SCP-originated 503 carries the SCP's Server identity.
        assert_eq!(
            shed.http.get_header(SERVER_HEADER).map(String::as_str),
            Some("SCP-scp.5gc.local")
        );

        // After the open timeout, one probe is admitted (HalfOpen) and reaches
        // the producer.
        tokio::time::sleep(Duration::from_millis(260)).await;
        let probe = client.send_request(make()).await.unwrap();
        assert_eq!(
            probe.status, 500,
            "half-open admits a probe to the producer"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "the half-open probe reached the producer"
        );

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }

    /// scpd-#102: a healthy producer (2xx) never trips the breaker even across
    /// many forwards — success resets the failure count.
    #[tokio::test]
    async fn test_circuit_breaker_stays_closed_on_success() {
        let producer_port = ephemeral_port();
        let scp_port = ephemeral_port();
        let producer = start_mock_producer(producer_port).await;
        let scp = start_scp(
            scp_port,
            ScpProxyConfig {
                circuit_failure_threshold: 2,
                ..Default::default()
            },
        )
        .await;
        let client = fast_client(scp_port);

        for _ in 0..5 {
            let req = SbiRequest::post("/nudm-uecm/v1/registrations").with_header(
                "3gpp-Sbi-Target-apiRoot",
                format!("http://127.0.0.1:{producer_port}"),
            );
            assert_eq!(client.send_request(req).await.unwrap().status, 200);
        }

        scp.stop().await.expect("scp stop");
        producer.stop().await.expect("producer stop");
    }
}
