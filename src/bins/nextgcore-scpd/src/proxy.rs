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
use std::sync::{Arc, RwLock};
use std::time::Duration;

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::constants::{custom_header, discovery_header};
use nextgcore_sbi::message::{ProblemDetails, SbiHttpMessage, SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::OAuth2Client;
use nextgcore_sbi::types::{NfType, UriScheme};
use nextgcore_sbi::SbiError;

use crate::sbi_path::{parse_search_result, select_nf_instance, DiscoveryCache};

/// Default upstream connect timeout (bounded per TS 29.500 §6.11 guidance).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Default upstream request timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
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
}

impl Default for ScpProxyConfig {
    fn default() -> Self {
        Self {
            nrf_uri: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            nf_instance_id: None,
            own_fqdn: DEFAULT_SCP_FQDN.to_string(),
            next_hop_scp: false,
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

/// Extract the producer's NF set id (`nfSetIdList[0]`) and NF group id
/// (`{udm,udr,ausf,pcf}Info.groupId`) for the selected instance from a parsed
/// SearchResult, used for `3gpp-Sbi-Producer-Id`/`3gpp-Sbi-Target-Nf-Group-Id`.
fn extract_set_and_group(
    value: &serde_json::Value,
    nf_instance_id: &str,
) -> (Option<String>, Option<String>) {
    let inst = value
        .get("nfInstances")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find(|i| {
                i.get("nfInstanceId").and_then(|x| x.as_str()) == Some(nf_instance_id)
            })
        });
    let set = inst
        .and_then(|i| i.get("nfSetIdList"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let group = inst.and_then(group_id_from_profile);
    (set, group)
}

/// Read the NF group id from whichever per-type info object the NF profile
/// carries (UDM/UDR/AUSF/PCF group membership, TS 29.510 §6.1.6.2.x).
fn group_id_from_profile(inst: &serde_json::Value) -> Option<String> {
    for key in ["udmInfo", "udrInfo", "ausfInfo", "pcfInfo"] {
        if let Some(g) = inst
            .get(key)
            .and_then(|x| x.get("groupId"))
            .and_then(|x| x.as_str())
        {
            return Some(g.to_string());
        }
    }
    None
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
struct DiscoveredProducer {
    target: ApiRoot,
    nf_instance_id: String,
    nf_set_id: Option<String>,
    nf_group_id: Option<String>,
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

/// How the proxy decided where to route a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteDecision {
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
    /// Model C / sticky-binding forwarding and NRF discovery).
    clients: RwLock<HashMap<String, Arc<SbiClient>>>,
    /// HTTP/2 client cache for OAuth2-attaching clients, keyed by
    /// `scheme://host:port|TARGET_NF_TYPE`. Used only on the Model D
    /// (delegated) path so the SCP, acting as the consumer's delegate,
    /// attaches a valid access token for the discovered producer.
    oauth_clients: RwLock<HashMap<String, Arc<SbiClient>>>,
    /// Binding stickiness cache: normalized `3gpp-Sbi-Binding` value →
    /// producer apiRoot it was returned from (TS 29.500 §6.12).
    bindings: RwLock<HashMap<String, ApiRoot>>,
    /// NF-set stickiness cache (scpd-11): lowercased `nfset` id → a learnt
    /// member apiRoot, so an `nf-set` Routing-Binding can reselect another set
    /// member when the originally-bound instance is gone (TS 29.500 §5.2.3.2.6).
    set_bindings: RwLock<HashMap<String, ApiRoot>>,
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
        Self {
            config,
            clients: RwLock::new(HashMap::new()),
            oauth_clients: RwLock::new(HashMap::new()),
            bindings: RwLock::new(HashMap::new()),
            set_bindings: RwLock::new(HashMap::new()),
            discovery_cache: DiscoveryCache::new(),
            oauth2,
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
        response
            .http
            .set_header(SERVER_HEADER, self.scp_node_id());
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

    /// scpd-04: ingress loop / hop-exhaustion guard (TS 29.500 §6.10.10).
    /// Returns a Server-stamped error when the request must be rejected:
    /// - own `SCP-<FQDN>` already present in a received `Via` → 400
    ///   `MSG_LOOP_DETECTED` (§6.10.10.3);
    /// - an scp-typed `3gpp-Sbi-Max-Forward-Hops` of `0` → 502
    ///   `MAX_SCP_HOPS_REACHED` (§6.10.10.2).
    ///
    /// A normal single-hop request (no `Via`, no hop header) is never blocked.
    fn ingress_guard(&self, request: &SbiRequest) -> Option<SbiResponse> {
        let self_token = self.scp_node_id().to_ascii_lowercase();
        if let Some(via) = request.http.get_header(VIA_HEADER) {
            if via.to_ascii_lowercase().contains(&self_token) {
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
        self.bindings
            .read()
            .ok()?
            .get(&normalize_binding(routing_binding))
            .cloned()
    }

    /// Record a `3gpp-Sbi-Binding` value from a producer response so later
    /// requests carrying it in `3gpp-Sbi-Routing-Binding` stick to the same
    /// producer. When the binding names an `nfset`, the target is also indexed
    /// at the set level (scpd-11) so an `nf-set` Routing-Binding can reselect a
    /// set member after the originally-bound instance is gone.
    pub fn binding_store(&self, binding: &str, target: &ApiRoot) {
        if let Ok(mut map) = self.bindings.write() {
            map.insert(normalize_binding(binding), target.clone());
        }
        if let Some(set) = ParsedBinding::parse(binding).nfset {
            if let Ok(mut sets) = self.set_bindings.write() {
                sets.insert(set.to_ascii_lowercase(), target.clone());
            }
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
                return self
                    .set_bindings
                    .read()
                    .ok()?
                    .get(&set.to_ascii_lowercase())
                    .cloned();
            }
        }
        None
    }

    /// Get or create a pooled HTTP/2 client for a target authority.
    fn client_for(&self, target: &ApiRoot) -> Arc<SbiClient> {
        let key = format!("{}://{}:{}", target.scheme, target.host, target.port);
        if let Ok(clients) = self.clients.read() {
            if let Some(client) = clients.get(&key) {
                return client.clone();
            }
        }
        let mut config = SbiClientConfig::new(target.host.clone(), target.port)
            .with_connect_timeout(self.config.connect_timeout)
            .with_request_timeout(self.config.request_timeout);
        config.scheme = target.scheme;
        let client = Arc::new(SbiClient::new(config));
        if let Ok(mut clients) = self.clients.write() {
            clients.insert(key, client.clone());
        }
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
        if let Ok(clients) = self.oauth_clients.read() {
            if let Some(client) = clients.get(&key) {
                return Some(client.clone());
            }
        }
        let mut config = SbiClientConfig::new(target.host.clone(), target.port)
            .with_connect_timeout(self.config.connect_timeout)
            .with_request_timeout(self.config.request_timeout);
        config.scheme = target.scheme;
        let client = Arc::new(SbiClient::new(config).with_oauth2(oauth2, target_nf_type));
        if let Ok(mut clients) = self.oauth_clients.write() {
            clients.insert(key, client.clone());
        }
        Some(client)
    }

    /// Decide how to route an incoming request (TS 29.500 §6.10.2):
    /// Target-apiRoot wins; otherwise a Routing-Binding that matches a cached
    /// Binding; otherwise delegated discovery when Discovery headers are
    /// present; otherwise the request is malformed.
    fn route(&self, request: &SbiRequest) -> RouteDecision {
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

    /// Model D delegated discovery (TS 29.500 §6.10.3, TS 29.510 §5.3.2):
    /// query the NRF's `nnrf-disc` service with the parameters carried in
    /// the `3gpp-Sbi-Discovery-*` request headers, parse the SearchResult,
    /// and select a producer. The requester identity comes from
    /// `3gpp-Sbi-Discovery-requester-nf-type` (NOT User-Agent).
    async fn discover(&self, request: &SbiRequest) -> Result<DiscoveredProducer, SbiResponse> {
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
        // keyed on (target-nf-type, service-names), without re-querying the NRF.
        let service_key = request
            .http
            .get_header(discovery_header::SERVICE_NAMES)
            .cloned()
            .unwrap_or_default();
        if let Some(cached) = self.discovery_cache.get(&target_nf_type, &service_key) {
            if let Some(selected) = select_nf_instance(&cached) {
                return Ok(DiscoveredProducer {
                    target: ApiRoot {
                        scheme: selected.scheme,
                        host: selected.host.clone(),
                        port: selected.port,
                        prefix: selected.prefix.clone(),
                    },
                    nf_instance_id: selected.nf_instance_id.clone(),
                    nf_set_id: None,
                    nf_group_id: None,
                });
            }
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

        let response = self
            .client_for(&nrf)
            .send_request(disc)
            .await
            .map_err(|e| upstream_error_response(&nrf.to_uri(), &e))?;

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
        let selected = select_nf_instance(&candidates).ok_or_else(|| {
            problem_response(
                502,
                "Bad Gateway",
                "NRF discovery returned no usable NF instance",
                "NF_DISCOVERY_FAILURE",
            )
        })?;

        // scpd-08: cache the parsed candidates with the SearchResult
        // `validityPeriod` (seconds) as TTL (default 3600 when absent).
        if !candidates.is_empty() {
            let validity = value
                .get("validityPeriod")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600);
            self.discovery_cache.put(
                &target_nf_type,
                &service_key,
                candidates.clone(),
                Duration::from_secs(validity),
            );
        }

        // scpd-02/scpd-12: surface the producer's set id / group id when present.
        let (nf_set_id, nf_group_id) = extract_set_and_group(&value, &selected.nf_instance_id);

        // Build the producer ApiRoot from the NF profile fields parsed out of
        // the SearchResult: scheme and prefix come from nfServices[].scheme /
        // nfServices[].apiPrefix; host is ipv4→fqdn→ipv6(bracketed).
        // `client_for`/`oauth_client_for` already honour the scheme field, so
        // an `https` producer is now contacted over TLS automatically.
        let target = ApiRoot {
            scheme: selected.scheme,
            host: selected.host.clone(),
            port: selected.port,
            prefix: selected.prefix.clone(),
        };
        Ok(DiscoveredProducer {
            target,
            nf_instance_id: selected.nf_instance_id.clone(),
            nf_set_id,
            nf_group_id,
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
        producer_id: Option<&str>,
        group_id: Option<&str>,
        delegated_nf_type: Option<NfType>,
    ) -> SbiResponse {
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
        // to this producer) so L1 attaches a fresh, correctly scoped Bearer
        // token. If no OAuth2 client is configured, fall back to forwarding the
        // request as-is (Authorization, if any, passes through).
        let (client, delegated) =
            match delegated_nf_type.and_then(|nf| self.oauth_client_for(target, nf)) {
                Some(oauth_client) => {
                    strip_authorization(&mut fwd.http.headers);
                    (oauth_client, true)
                }
                None => (self.client_for(target), false),
            };

        // scpd-07: keep a pristine (pre-token) copy for a single refresh-and-
        // retry on a delegated 401/403 Bearer challenge.
        let retry_fwd = if delegated { Some(fwd.clone()) } else { None };

        let mut upstream = match client.send_request(fwd).await {
            Ok(response) => response,
            Err(e) => return self.stamp_server(upstream_error_response(&target.to_uri(), &e)),
        };

        // scpd-07: on a delegated forward that the producer rejects with
        // 401/403 + a Bearer `WWW-Authenticate`, the cached token was refused —
        // invalidate it, mint a fresh one, and retry exactly once
        // (TS 29.500 §6.10.11.2.3). If it still fails, the response is relayed.
        if delegated && matches!(upstream.status, 401 | 403) && www_authenticate_is_bearer(&upstream)
        {
            if let (Some(oauth2), Some(retry)) = (self.oauth2.as_ref(), retry_fwd) {
                oauth2.clear_cache().await;
                if let Ok(retried) = client.send_request(retry).await {
                    upstream = retried;
                }
            }
        }

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
            if let Some(id) = producer_id.filter(|s| !s.is_empty()) {
                relayed.http.set_header(custom_header::PRODUCER_ID, id);
            }
            if let Some(g) = group_id.filter(|s| !s.is_empty()) {
                relayed.http.set_header(custom_header::TARGET_NF_GROUP_ID, g);
            }
        }

        // scpd-03: a relayed producer error (4xx/5xx) carries this SCP's Via
        // (TS 29.500 §6.10.8.3); its body/status stay verbatim.
        if upstream.status >= 400 {
            self.append_via(&mut relayed.http);
        }

        relayed
    }

    /// Handle one inbound SBI request end-to-end (the server handler entry
    /// point).
    pub async fn handle(&self, request: SbiRequest) -> SbiResponse {
        // scpd-04: reject looped / hop-exhausted requests before any forwarding.
        if let Some(rejection) = self.ingress_guard(&request) {
            return rejection;
        }

        match self.route(&request) {
            RouteDecision::TargetApiRoot(target) => {
                log::debug!(
                    "SCP Model C: {} {} -> {}",
                    request.header.method,
                    request.header.uri,
                    target.to_uri()
                );
                self.forward(&request, &target, None, None, None).await
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
                self.forward(&request, &target, producer_id.as_deref(), None, None)
                    .await
            }
            RouteDecision::Discover => match self.discover(&request).await {
                Ok(producer) => {
                    // The producer NF type comes from the delegated-discovery
                    // header; used to scope the OAuth2 token the SCP attaches.
                    let delegated_nf_type = request
                        .http
                        .get_header(discovery_header::TARGET_NF_TYPE)
                        .and_then(|s| nf_type_from_str(s));
                    let producer_id =
                        build_producer_id(&producer.nf_instance_id, producer.nf_set_id.as_deref());
                    log::debug!(
                        "SCP Model D: {} {} -> {} (producer {})",
                        request.header.method,
                        request.header.uri,
                        producer.target.to_uri(),
                        producer.nf_instance_id
                    );
                    self.forward(
                        &request,
                        &producer.target,
                        producer_id.as_deref(),
                        producer.nf_group_id.as_deref(),
                        delegated_nf_type,
                    )
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

    /// Reserve an ephemeral localhost port.
    fn ephemeral_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        port
    }

    /// Start a mock producer that echoes the request (method, uri, body and
    /// selected headers) as JSON and returns Binding/Oci headers.
    async fn start_mock_producer(port: u16) -> nextgcore_sbi::server::SbiServer {
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        server
            .start(move |request: SbiRequest| {
                let hits = hits.clone();
                async move {
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
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

    #[tokio::test]
    async fn test_nrf_returning_no_candidates_is_502() {
        let nrf_port = ephemeral_port();
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
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
        assert_eq!(response.status, 502);
        let problem: ProblemDetails = response.json_body().unwrap();
        assert_eq!(problem.cause.as_deref(), Some("NF_DISCOVERY_FAILURE"));

        server.stop().await.expect("nrf stop");
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
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
        let selected = select_nf_instance(&candidates).expect("candidate selected");

        // Simulate what discover() now does.
        let target = ApiRoot {
            scheme: selected.scheme,
            host: selected.host.clone(),
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
        let selected = select_nf_instance(&candidates).expect("candidate selected");

        let target = ApiRoot {
            scheme: selected.scheme,
            host: selected.host.clone(),
            port: selected.port,
            prefix: selected.prefix.clone(),
        };

        assert_eq!(target.scheme, UriScheme::Http);
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 7777);
        assert_eq!(target.prefix, "");
        assert_eq!(target.to_uri(), "http://10.0.0.1:7777");
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
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
        let server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        server
            .start(move |request: SbiRequest| {
                let captured = captured.clone();
                async move {
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

        // NOTE: the nextgcore-sbi client serializes query params verbatim (no
        // percent-encoding, a pre-existing lib gap outside scpd's ownership), so
        // factor *values* here are query-safe tokens. scpd-06 is about the
        // header→param *mapping*, which is value-independent.
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
        assert_eq!(params.get("target-nf-type").map(String::as_str), Some("UDM"));
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

    /// scpd-09: a discovered `apiPrefix` is prepended to the forwarded request
    /// URI seen by the producer.
    #[tokio::test]
    async fn test_apiprefix_propagates_into_forwarded_uri() {
        let producer_port = ephemeral_port();
        let nrf_port = ephemeral_port();
        let scp_port = ephemeral_port();

        let producer = start_mock_producer(producer_port).await;
        let nrf_server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], nrf_port)),
        ));
        nrf_server
            .start(move |_request: SbiRequest| async move {
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
        assert_eq!(echoed["targetApiroot"].as_str(), Some(producer_apiroot.as_str()));

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
        let nrf_server = nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], nrf_port)),
        ));
        nrf_server
            .start(move |_request: SbiRequest| async move {
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
}
