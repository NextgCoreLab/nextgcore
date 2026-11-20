//! Caller-owner binding for SBI resources a consumer creates and then manages
//! (#1865; the pattern of nrfd #1809).
//!
//! A resource (a subscription, a context, a registration) is bound at creation
//! to the **verified** identity of the NF that created it, and a later modify,
//! replace or delete is answered `403` unless the caller proves that same
//! identity. TS 33.501 §13.4.1: the producer authorizes on the identity it
//! authenticated, never on an ID the body or the path claims. Knowing a
//! resource's ID is not proof of having created it.
//!
//! # The identity rule
//!
//! The caller's identity is read only from what this process verified, in this
//! order:
//!
//! 1. the NF Instance ID in the URI SAN of the verified client certificate
//!    ([`SbiRequest::peer_cert_nf_instance_id`], TS 33.310 §6.1.3c), unless that
//!    certificate names relay types only ([`is_relay_certificate`]: an SCP or
//!    SEPP is not the consumer; one also naming a consumer type is, #2113), else
//! 2. the `sub` of the verified OAuth2 access token
//!    ([`SbiRequest::oauth2_subject`], TS 29.510 `AccessTokenClaims.sub`, the
//!    consumer's NF Instance ID), which survives an SCP hop (TS 33.501 §13.3).
//!
//! A relay is recognised only by the RFC 9310 NFTypes extension of its
//! certificate. An SCP certificate without one counts as the consumer, so it
//! disagrees with the consumer's token and the request is refused: this fails
//! closed (R32 on #1936).
//!
//! A binding is to one NF instance. There is no NF-set or AMF-set awareness
//! (TS 29.500 §6.5, TS 23.501 §5.21): a set member that takes over another's
//! resources gets 403 until the resource is re-created (#1937).
//!
//! When both are present they must name the same NF instance. A caller whose
//! certificate and token disagree is refused at create (nothing is stored) and
//! at every later operation.
//!
//! # Ownerless resources
//!
//! A resource created with no verified identity has no owner. Whether that is
//! allowed is the `required` flag, [`identity_required`] by default:
//!
//! - under the `dev` SBI profile (plaintext, nothing to verify) an anonymous
//!   caller may create, and an ownerless resource is managed by anyone, as
//!   before this binding existed;
//! - under `production` an anonymous create is refused, and an ownerless
//!   resource (one restored from a state file written before the binding) is
//!   **frozen**: no caller can prove it created it, so none may modify or
//!   delete it. It keeps working until it lapses or the NF drops it, and its
//!   consumer re-creates it, this time bound (the rule nrfd #1809 settled on).
//!
//! An NF that persists resources across a restart restores pre-binding ones
//! ownerless, so under production they are frozen; one whose resources carry a
//! lifetime must cap the restored lifetime (nrfd caps at 24 h, #1831), or a
//! frozen resource nobody may remove can outlive the upgrade indefinitely.
//!
//! This module reproduces the API of the per-NF copies written for #1860,
//! #1861 and #1862 (same names and signatures), so those move onto it by
//! replacing the copy with `use nextgcore_sbi::owner_binding;`; the one rule
//! they then gain is the production freeze above.
//!
//! # Use
//!
//! ```ignore
//! // create: before the body is stored
//! let owner = match owner_binding::owner_for_new_resource(&request, "Subscribe") {
//!     Ok(owner) => owner,
//!     Err(refused) => return *refused,
//! };
//! // modify / delete: straight after the lookup, before any side effect
//! if let Some(refused) = owner_binding::refuse_non_owner(sub.owner.as_deref(), &request, "Unsubscribe") {
//!     return refused;
//! }
//! ```
//!
//! An unknown ID stays `404`, checked first: a `403` for a missing resource
//! would tell a prober nothing it could not learn from the `404` anyway, but the
//! owner of a resource that is gone must still see it gone.

use crate::message::{SbiRequest, SbiResponse};
use crate::security::SbiProfile;

/// Certificate NF types that identify a relay rather than the consumer.
pub const RELAY_NF_TYPES: &[&str] = &["SCP", "SEPP"];

/// #2113: whether a certificate naming `nf_types` (RFC 9310 NFTypes) is a
/// relay's: it names at least one type and every one is a relay type
/// ([`RELAY_NF_TYPES`]). A certificate that also names a consumer type -- say
/// `[SCP, PCF]` -- is that consumer's, not a relay's: its holder is identified
/// and typed by it, so it cannot borrow another NF's token by calling itself an
/// SCP. A certificate naming no types is not a relay's either (see the module
/// docs: it fails closed).
pub fn is_relay_certificate<S: AsRef<str>>(nf_types: &[S]) -> bool {
    !nf_types.is_empty()
        && nf_types.iter().all(|t| {
            RELAY_NF_TYPES
                .iter()
                .any(|r| r.eq_ignore_ascii_case(t.as_ref().trim()))
        })
}

/// NF Instance IDs are UUIDs (TS 29.571 `NfInstanceId`), compared without case.
pub fn same_nf_instance_id(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Whether a verified identity is required to create a resource and an
/// ownerless one is frozen: on under the `production` SBI profile, off under
/// `dev` (see the module docs).
pub fn identity_required() -> bool {
    SbiProfile::resolve().is_production()
}

/// The caller's verified NF Instance ID: `Ok(None)` when it proved none,
/// `Err(detail)` when its certificate and token name different NF instances.
pub fn verified_consumer_id(request: &SbiRequest) -> Result<Option<String>, String> {
    let relay = is_relay_certificate(&request.peer_cert_nf_types);
    let cert = request
        .peer_cert_nf_instance_id
        .as_deref()
        .filter(|s| !relay && !s.trim().is_empty());
    let token = request
        .oauth2_subject
        .as_deref()
        .filter(|s| !s.trim().is_empty());
    match (cert, token) {
        (Some(c), Some(t)) if !same_nf_instance_id(c, t) => Err(format!(
            "the requester's client certificate ({c:?}) and access token subject ({t:?}) \
             name different NF instances"
        )),
        (Some(c), _) => Ok(Some(c.trim().to_string())),
        (None, Some(t)) => Ok(Some(t.trim().to_string())),
        (None, None) => Ok(None),
    }
}

/// The owner to record for a resource `request` is creating, under
/// [`identity_required`]. `Err` is the `403` to send instead of creating.
pub fn owner_for_new_resource(
    request: &SbiRequest,
    operation: &str,
) -> Result<Option<String>, Box<SbiResponse>> {
    owner_for_new_resource_with(request, operation, identity_required())
}

/// [`owner_for_new_resource`] with an explicit `required`. `Ok(None)` only when
/// the caller proved no identity and none is `required`.
pub fn owner_for_new_resource_with(
    request: &SbiRequest,
    operation: &str,
    required: bool,
) -> Result<Option<String>, Box<SbiResponse>> {
    match verified_consumer_id(request) {
        Err(why) => Err(Box::new(forbidden(operation, &why))),
        Ok(None) if required => Err(Box::new(forbidden(
            operation,
            "the requester has no verified identity (client certificate or access token), \
             so the resource could not be bound to it",
        ))),
        Ok(owner) => Ok(owner),
    }
}

/// Why `request` may not act on a resource bound to `owner`, or `None` if it
/// may, under [`identity_required`].
pub fn non_owner_refusal(owner: Option<&str>, request: &SbiRequest) -> Option<String> {
    non_owner_refusal_with(owner, request, identity_required())
}

/// [`non_owner_refusal`] with an explicit `required`: an ownerless resource is
/// open when not `required` and frozen when it is.
pub fn non_owner_refusal_with(
    owner: Option<&str>,
    request: &SbiRequest,
    required: bool,
) -> Option<String> {
    let Some(owner) = owner else {
        return required.then(|| {
            "the resource has no verified owner (it predates owner binding), so no \
             requester can be shown to have created it"
                .to_string()
        });
    };
    match verified_consumer_id(request) {
        Err(why) => Some(why),
        Ok(None) => Some(format!(
            "the requester has no verified identity; the resource belongs to NF instance \
             {owner}"
        )),
        Ok(Some(caller)) if !same_nf_instance_id(&caller, owner) => Some(format!(
            "the resource belongs to NF instance {owner}, not the requester ({caller})"
        )),
        Ok(Some(_)) => None,
    }
}

/// [`non_owner_refusal`] as the `403` to send. `Some` means refuse and change
/// nothing.
pub fn refuse_non_owner(
    owner: Option<&str>,
    request: &SbiRequest,
    operation: &str,
) -> Option<SbiResponse> {
    refuse_non_owner_with(owner, request, operation, identity_required())
}

/// [`refuse_non_owner`] with an explicit `required`.
pub fn refuse_non_owner_with(
    owner: Option<&str>,
    request: &SbiRequest,
    operation: &str,
    required: bool,
) -> Option<SbiResponse> {
    let why = non_owner_refusal_with(owner, request, required)?;
    Some(forbidden(operation, &why))
}

/// A resource identifier nobody can guess: 122 random bits (UUID v4), so
/// knowing one ID tells a peer nothing about another, and IDs never repeat
/// across a restart.
pub fn unguessable_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

// ---------------------------------------------------------------------------
// #2099: the caller's verified NF type
// ---------------------------------------------------------------------------

/// How long an NRF answer about a caller's NF type is reused (#2099, the
/// ausfd #1964 figure).
pub const NF_TYPE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// #2123 (R41): how long an NRF answer that a caller is NOT of a type is
/// reused. Short, so an NF the NRF has only just registered (its profile not
/// yet visible when first looked up) is refused for seconds rather than for
/// [`NF_TYPE_TTL`]. Not zero, because a refusal is free to provoke: a peer
/// replaying refused requests would otherwise cost one NRF query each.
pub const NF_TYPE_NEGATIVE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// At most this many cached answers; a full cache drops the expired ones, then
/// everything, rather than grow.
const NF_TYPE_CACHE_MAX: usize = 1024;

/// (NRF URI, NF type, NF instance ID) -> (that NRF lists that instance with
/// that type, valid until). Both answers are cached; a lookup that fails is
/// never cached: it refuses, and the next call asks again.
///
/// The NRF URI is part of the key (#2120), so after the configured NRF changes
/// the old NRF's answers are never reused: the new NRF is asked. The type is
/// part of it too, so an instance's answer as one type is never its answer as
/// another.
type NfTypeCache = std::collections::HashMap<String, (bool, std::time::Instant)>;

fn nf_type_cache() -> std::sync::MutexGuard<'static, NfTypeCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<NfTypeCache>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| std::sync::Mutex::new(NfTypeCache::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn nf_type_key(nrf_uri: &str, nf_type: &str, id: &str) -> String {
    // A space cannot occur in a URI, an NF type or a UUID, so the parts cannot
    // run into each other.
    format!(
        "{} {} {}",
        nrf_uri.trim().trim_end_matches('/'),
        nf_type.to_ascii_uppercase(),
        id.trim().to_ascii_lowercase()
    )
}

/// The `seed_nf_type_for_test` answers: (NF type, NF instance ID) keys, valid
/// whichever NRF is configured, or none.
#[cfg(any(test, feature = "test-support"))]
fn seeded_nf_types() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    static SEEDED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    SEEDED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Tests (of this crate and, through the `test-support` feature, of the NFs):
/// record that the NRF lists `id` as an `nf_type`, for the whole test run and
/// whichever NRF is configured (none included), so a token-identified caller
/// needs no NRF. Only ever adds a positive answer for that one type, so tests
/// using their own ids cannot collide.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_nf_type_for_test(id: &str, nf_type: crate::types::NfType) {
    seeded_nf_types().insert(nf_type_key("", nf_type.to_str(), id));
}

#[cfg(any(test, feature = "test-support"))]
fn seeded_nf_type(id: &str, nf_type: crate::types::NfType) -> bool {
    seeded_nf_types().contains(&nf_type_key("", nf_type.to_str(), id))
}

#[cfg(not(any(test, feature = "test-support")))]
fn seeded_nf_type(_id: &str, _nf_type: crate::types::NfType) -> bool {
    false
}

/// The one NRF client the lookups share, rebuilt only when the NRF URI changes.
fn nrf_client(nrf_uri: &str) -> Option<std::sync::Arc<crate::client::SbiClient>> {
    static CLIENT: std::sync::Mutex<Option<(String, std::sync::Arc<crate::client::SbiClient>)>> =
        std::sync::Mutex::new(None);
    let mut held = CLIENT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((uri, client)) = held.as_ref() {
        if uri == nrf_uri {
            return Some(client.clone());
        }
    }
    // #1617: the NRF client TLS for an https NRF URI or the production profile.
    let config = crate::nrf_tls::nrf_client_config_for_uri(nrf_uri)?
        .with_connect_timeout(std::time::Duration::from_secs(2))
        .with_request_timeout(std::time::Duration::from_secs(3));
    let client = std::sync::Arc::new(crate::client::SbiClient::new(config));
    *held = Some((nrf_uri.to_string(), client.clone()));
    Some(client)
}

/// #2099: NFDiscovery at `nrf_uri` of instance `id` as an `nf_type` (TS 29.510
/// §6.2.3.2.3.1, `target-nf-instance-id`). `Ok(true)` only for a 200 that lists
/// `id` itself with that `nfType`, so an NRF that ignores the instance filter
/// cannot vouch for an unlisted caller. `Err` when the NRF does not answer
/// usably. Uncached; [`verified_nf_type`] caches.
pub async fn nrf_lists_nf_type_at(
    nrf_uri: &str,
    id: &str,
    nf_type: crate::types::NfType,
    requester: Option<crate::types::NfType>,
) -> Result<bool, String> {
    let client = nrf_client(nrf_uri).ok_or_else(|| format!("invalid NRF URI {nrf_uri:?}"))?;
    let mut request = SbiRequest::get("/nnrf-disc/v1/nf-instances");
    request.http.set_param("target-nf-type", nf_type.to_str());
    if let Some(requester) = requester {
        request
            .http
            .set_param("requester-nf-type", requester.to_str());
    }
    request.http.set_param("target-nf-instance-id", id);
    let resp = client
        .send_request(request)
        .await
        .map_err(|e| format!("the NRF lookup failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("the NRF lookup returned {}", resp.status));
    }
    let body: serde_json::Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("the NRF lookup answer does not parse: {e}"))?;
    Ok(body["nfInstances"].as_array().is_some_and(|list| {
        list.iter().any(|i| {
            i["nfInstanceId"]
                .as_str()
                .is_some_and(|n| same_nf_instance_id(n, id))
                && i["nfType"]
                    .as_str()
                    .is_some_and(|t| t.eq_ignore_ascii_case(nf_type.to_str()))
        })
    }))
}

/// [`nrf_lists_nf_type_at`] at the configured NRF, through the cache.
async fn nrf_lists_nf_type(id: &str, nf_type: crate::types::NfType) -> Result<bool, String> {
    if seeded_nf_type(id, nf_type) {
        return Ok(true);
    }
    let ctx = crate::context::global_context();
    let nrf_uri = ctx
        .get_nrf_uri()
        .await
        .ok_or("no NRF is configured to look the caller up")?;
    let requester = requester_nf_type(
        ctx.get_self_instance().await.map(|i| i.nf_type),
        crate::nf_instance_id::own_nf_type(),
    );
    cached_nrf_lists_nf_type_at(&nrf_uri, id, nf_type, requester).await
}

/// #2123 (#2120 item 3): the `requester-nf-type` of the lookup, which TS 29.510
/// makes mandatory (nrfd answers 400 without it): this NF's self instance's
/// type, else the type it resolved its NF Instance ID as
/// ([`crate::nf_instance_id::own_nf_type`]), so an NF that never registers a
/// self instance (udrd before #2123) still names itself.
fn requester_nf_type(
    self_instance: Option<crate::types::NfType>,
    own: Option<crate::types::NfType>,
) -> Option<crate::types::NfType> {
    self_instance.or(own)
}

fn cached_nf_type(nrf_uri: &str, id: &str, nf_type: crate::types::NfType) -> Option<bool> {
    let (listed, until) = nf_type_cache()
        .get(&nf_type_key(nrf_uri, nf_type.to_str(), id))
        .copied()?;
    (std::time::Instant::now() < until).then_some(listed)
}

/// [`nrf_lists_nf_type_at`] through the cache: a positive answer is reused for
/// [`NF_TYPE_TTL`], a negative one for [`NF_TYPE_NEGATIVE_TTL`]; a failed
/// lookup is not cached.
async fn cached_nrf_lists_nf_type_at(
    nrf_uri: &str,
    id: &str,
    nf_type: crate::types::NfType,
    requester: Option<crate::types::NfType>,
) -> Result<bool, String> {
    if let Some(listed) = cached_nf_type(nrf_uri, id, nf_type) {
        return Ok(listed);
    }
    let key = nf_type_key(nrf_uri, nf_type.to_str(), id);
    let listed = nrf_lists_nf_type_at(nrf_uri, id, nf_type, requester).await?;
    let mut cache = nf_type_cache();
    if cache.len() >= NF_TYPE_CACHE_MAX {
        let now = std::time::Instant::now();
        cache.retain(|_, (_, until)| now < *until);
        if cache.len() >= NF_TYPE_CACHE_MAX {
            cache.clear();
        }
    }
    let ttl = if listed {
        NF_TYPE_TTL
    } else {
        NF_TYPE_NEGATIVE_TTL
    };
    cache.insert(key, (listed, std::time::Instant::now() + ttl));
    Ok(listed)
}

/// #2099 (CONVENTIONS: a caller's NF type is verified, never assumed): `Ok`
/// when the caller of `request` is shown to be an `expected`, else `Err` with
/// why. The one rule smfd's AMF-change gate (#2078) and lmfd's
/// LocationContextTransfer (#2077) apply:
///
/// - the caller's identity is [`verified_consumer_id`]'s; none, or a
///   certificate/token mismatch, refuses;
/// - the consumer's own client certificate naming NF types (RFC 9310, TS
///   33.310 §6.1.3c) must name `expected`. A relay's certificate (one naming
///   relay types only, [`is_relay_certificate`]) is not the consumer's; one
///   naming a relay type and a consumer type is (#2113);
/// - otherwise -- a token alone, a token through an SCP or SEPP, or a
///   certificate without NF types plus a token -- the NRF must list the
///   token's verified subject as an `expected` ([`nrf_lists_nf_type_at`],
///   cached for [`NF_TYPE_TTL`], a negative answer for
///   [`NF_TYPE_NEGATIVE_TTL`]), and a lookup that fails refuses. An access
///   token names no NF type of its consumer (TS 29.510 `AccessTokenClaims`), so
///   the NRF is the only verified source;
/// - a certificate without NF types and no token refuses: it cannot be told
///   apart from a relay's.
pub async fn verified_nf_type(
    request: &SbiRequest,
    expected: crate::types::NfType,
) -> Result<(), String> {
    let want = expected.to_str();
    match verified_consumer_id(request)? {
        Some(_) => {}
        None => return Err("the requester has no verified identity".to_string()),
    }
    let types = &request.peer_cert_nf_types;
    let relay = is_relay_certificate(types);
    let cert = request
        .peer_cert_nf_instance_id
        .as_deref()
        .is_some_and(|c| !c.trim().is_empty());
    if cert && !relay && !types.is_empty() {
        return if types.iter().any(|t| t.eq_ignore_ascii_case(want)) {
            Ok(())
        } else {
            Err(format!(
                "the requester's certificate names {types:?}, not {want}"
            ))
        };
    }
    let Some(sub) = request
        .oauth2_subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(format!(
            "the requester's certificate names no NF types and it sent no access token, \
             so it cannot be shown to be an {want}"
        ));
    };
    match nrf_lists_nf_type(sub, expected).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("the NRF does not list {sub} as an {want}")),
        Err(e) => {
            log::warn!("{e}; refusing {sub}'s {want}-only request");
            Err(format!("the NRF does not list {sub} as an {want} ({e})"))
        }
    }
}

fn forbidden(operation: &str, why: &str) -> SbiResponse {
    // debug, not warn: a peer can send these at will (#1620 review m7).
    log::debug!("{operation} refused: {why}");
    crate::server::send_forbidden(&format!("{operation}: {why}"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(cert: Option<&str>, token: Option<&str>, types: &[&str]) -> SbiRequest {
        let mut r = SbiRequest::post("/x");
        r.peer_cert_nf_instance_id = cert.map(str::to_string);
        r.oauth2_subject = token.map(str::to_string);
        r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        r
    }

    // ---- #2099: verified_nf_type ----

    use crate::types::NfType;

    /// A stand-in NRF: `listed` are AMFs, `smf` an SMF, `err` answers 500.
    /// Counts the lookups.
    async fn stand_in_nrf_2099(
        listed: &'static str,
        smf: &'static str,
        err: &'static str,
    ) -> (
        crate::server::SbiServer,
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        crate::security::set_sbi_profile_override(crate::security::SbiProfile::Dev);
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a = asked.clone();
        let (server, addr) =
            crate::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let a = a.clone();
                async move {
                    a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let id = req
                        .http
                        .params
                        .get("target-nf-instance-id")
                        .cloned()
                        .unwrap_or_default();
                    if id == err {
                        return SbiResponse::with_status(500);
                    }
                    let list = if id == listed {
                        vec![serde_json::json!({ "nfInstanceId": listed, "nfType": "AMF" })]
                    } else if id == smf {
                        vec![serde_json::json!({ "nfInstanceId": smf, "nfType": "SMF" })]
                    } else {
                        vec![]
                    };
                    SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({ "nfInstances": list }))
                        .expect("json")
                }
            })
            .await;
        (server, format!("http://127.0.0.1:{}", addr.port()), asked)
    }

    /// **#2099**: the NRF lookup passes only a 200 listing the instance itself
    /// with that `nfType`. Another type, an unknown instance, an error and an
    /// NRF that does not answer refuse.
    ///
    /// REVERT-VERIFIED: with the `nfType` check dropped, "an SMF is not an AMF"
    /// fails.
    #[tokio::test]
    async fn the_nrf_lookup_of_a_type_fails_closed_2099() {
        const AMF: &str = "aaaaaaaa-2099-4000-8000-0000000000a1";
        const SMF: &str = "bbbbbbbb-2099-4000-8000-0000000000b1";
        const ERR: &str = "cccccccc-2099-4000-8000-0000000000c1";
        let (_nrf, nrf, _) = stand_in_nrf_2099(AMF, SMF, ERR).await;
        let at = |id: &'static str| nrf_lists_nf_type_at(&nrf, id, NfType::Amf, Some(NfType::Smf));
        assert_eq!(at(AMF).await, Ok(true), "a listed AMF is an AMF");
        assert_eq!(at(SMF).await, Ok(false), "an SMF is not an AMF");
        assert_eq!(at("dddddddd-2099-4000-8000-0000000000d1").await, Ok(false));
        assert!(at(ERR).await.is_err(), "an NRF error is a failed lookup");
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        assert!(
            nrf_lists_nf_type_at(
                &format!("http://127.0.0.1:{dead_port}"),
                AMF,
                NfType::Amf,
                None
            )
            .await
            .is_err(),
            "an NRF that does not answer is a failed lookup"
        );
    }

    /// **#2123 (R41)**: a negative answer is reused only for
    /// [`NF_TYPE_NEGATIVE_TTL`], so an NF the NRF lists a moment later is
    /// admitted within seconds; a positive one for [`NF_TYPE_TTL`].
    ///
    /// REVERT-VERIFIED: with a negative answer cached for `NF_TYPE_TTL`, the
    /// `negative lifetime` assertion fails.
    #[tokio::test]
    async fn a_negative_answer_is_reused_for_seconds_only_2123() {
        const AMF: &str = "aaaaaaaa-2123-4000-8000-0000000000a2";
        const NOT: &str = "dddddddd-2123-4000-8000-0000000000d2";
        let (_nrf, nrf, asked) = stand_in_nrf_2099(AMF, "-", "-").await;
        let n = || asked.load(std::sync::atomic::Ordering::SeqCst);
        let until = |id: &str| {
            nf_type_cache()
                .get(&nf_type_key(&nrf, "AMF", id))
                .map(|(_, until)| *until)
                .expect("cached")
        };
        let before = std::time::Instant::now();
        assert_eq!(
            cached_nrf_lists_nf_type_at(&nrf, NOT, NfType::Amf, None).await,
            Ok(false)
        );
        assert_eq!(
            cached_nrf_lists_nf_type_at(&nrf, NOT, NfType::Amf, None).await,
            Ok(false)
        );
        assert_eq!(n(), 1, "a negative answer is reused at once");
        assert!(
            until(NOT) <= std::time::Instant::now() + NF_TYPE_NEGATIVE_TTL,
            "negative lifetime"
        );
        assert!(until(NOT) >= before + NF_TYPE_NEGATIVE_TTL);
        assert_eq!(
            cached_nrf_lists_nf_type_at(&nrf, AMF, NfType::Amf, None).await,
            Ok(true)
        );
        assert!(until(AMF) >= before + NF_TYPE_TTL, "positive lifetime");
        // Lapsed: asked again.
        nf_type_cache()
            .get_mut(&nf_type_key(&nrf, "AMF", NOT))
            .expect("cached")
            .1 = std::time::Instant::now();
        assert_eq!(
            cached_nrf_lists_nf_type_at(&nrf, NOT, NfType::Amf, None).await,
            Ok(false)
        );
        assert_eq!(n(), 3, "a lapsed negative answer is asked again");
    }

    /// **#2123 (#2120 item 3)**: the lookup's `requester-nf-type` is the self
    /// instance's type, else the type this process resolved its NF Instance ID
    /// as, so an NF that registers no self instance still names itself.
    ///
    /// REVERT-VERIFIED: with the fallback dropped (`self_instance` alone), the
    /// `no self instance` assertion fails.
    #[test]
    fn the_requester_falls_back_to_the_own_nf_type_2123() {
        assert_eq!(
            requester_nf_type(Some(NfType::Smf), Some(NfType::Udr)),
            Some(NfType::Smf)
        );
        assert_eq!(
            requester_nf_type(None, Some(NfType::Udr)),
            Some(NfType::Udr),
            "no self instance"
        );
        assert_eq!(requester_nf_type(None, None), None);
    }

    /// **#2099**: an NRF answer is reused within [`NF_TYPE_TTL`] (one lookup for
    /// two asks), and a failed lookup is never cached (asked again each time).
    ///
    /// REVERT-VERIFIED: with the cache bypassed, "the answer is reused" fails;
    /// with a failed lookup turned into a cached `false`, the failed lookup's
    /// `is_err` assertion fails.
    #[tokio::test]
    async fn answers_are_cached_and_failures_are_not_2099() {
        const AMF: &str = "aaaaaaaa-2099-4000-8000-0000000000a2";
        const ERR: &str = "cccccccc-2099-4000-8000-0000000000c2";
        let (_nrf, nrf, asked) = stand_in_nrf_2099(AMF, "-", ERR).await;
        let n = || asked.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            cached_nrf_lists_nf_type_at(&nrf, AMF, NfType::Amf, None).await,
            Ok(true)
        );
        assert_eq!(
            cached_nrf_lists_nf_type_at(&nrf, AMF, NfType::Amf, None).await,
            Ok(true)
        );
        assert_eq!(n(), 1, "the answer is reused");
        assert!(cached_nrf_lists_nf_type_at(&nrf, ERR, NfType::Amf, None)
            .await
            .is_err());
        assert!(cached_nrf_lists_nf_type_at(&nrf, ERR, NfType::Amf, None)
            .await
            .is_err());
        assert_eq!(n(), 3, "a failure is not cached");
    }

    /// A stand-in NRF for #2120 that lists `listed` as an AMF and records each
    /// lookup's `target-nf-type`.
    async fn recording_nrf_2120(
        listed: &'static str,
    ) -> (
        crate::server::SbiServer,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        crate::security::set_sbi_profile_override(crate::security::SbiProfile::Dev);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        let (server, addr) =
            crate::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let s = s.clone();
                async move {
                    let param = |k: &str| req.http.params.get(k).cloned().unwrap_or_default();
                    let target = param("target-nf-type");
                    s.lock().unwrap().push(target.clone());
                    let list = if param("target-nf-instance-id") == listed && target == "AMF" {
                        vec![serde_json::json!({ "nfInstanceId": listed, "nfType": "AMF" })]
                    } else {
                        vec![]
                    };
                    SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({ "nfInstances": list }))
                        .expect("json")
                }
            })
            .await;
        (server, format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    /// **#2120 (1)**: the cache keeps an instance's answer as one NF type apart
    /// from its answer as another. An AMF the NRF lists, cached as an AMF, is
    /// asked about again as an SMF, and is not one.
    ///
    /// REVERT-VERIFIED: with the type dropped from `nf_type_key`, the SMF ask is
    /// answered `Ok(true)` from the AMF's cached answer and "is not an SMF"
    /// fails.
    #[tokio::test]
    async fn the_cache_keeps_each_nf_type_apart_2120() {
        const AMF: &str = "aaaaaaaa-2120-4000-8000-0000000000a1";
        let (_nrf, nrf, seen) = recording_nrf_2120(AMF).await;
        let ask = |nf_type| cached_nrf_lists_nf_type_at(&nrf, AMF, nf_type, Some(NfType::Lmf));
        assert_eq!(ask(NfType::Amf).await, Ok(true), "a listed AMF is an AMF");
        assert_eq!(ask(NfType::Smf).await, Ok(false), "is not an SMF");
        assert_eq!(ask(NfType::Smf).await, Ok(false), "still not an SMF");
        assert_eq!(
            *seen.lock().unwrap(),
            ["AMF", "SMF"],
            "the SMF ask went to the NRF once, then was cached"
        );
    }

    /// **#2120 (2)**: the cache keeps each NRF's answers apart, so after the NRF
    /// URI changes the new NRF is asked rather than the old one's answer reused.
    /// The same NRF written with a trailing `/` is the same NRF.
    ///
    /// REVERT-VERIFIED: with the NRF URI dropped from `nf_type_key`, the new
    /// NRF is never asked: the old NRF's `Ok(true)` is returned and "the new
    /// NRF does not list it" fails.
    #[tokio::test]
    async fn the_cache_keeps_each_nrf_apart_2120() {
        const AMF: &str = "aaaaaaaa-2120-4000-8000-0000000000a2";
        let (_old, old_nrf, old_seen) = recording_nrf_2120(AMF).await;
        let (_new, new_nrf, new_seen) = recording_nrf_2120("-").await;
        let ask = |nrf: String| async move {
            cached_nrf_lists_nf_type_at(&nrf, AMF, NfType::Amf, Some(NfType::Lmf)).await
        };
        assert_eq!(ask(old_nrf.clone()).await, Ok(true), "the old NRF lists it");
        assert_eq!(ask(format!("{old_nrf}/")).await, Ok(true));
        assert_eq!(old_seen.lock().unwrap().len(), 1, "one ask of the old NRF");
        assert_eq!(
            ask(new_nrf.clone()).await,
            Ok(false),
            "the new NRF does not list it"
        );
        assert_eq!(new_seen.lock().unwrap().len(), 1, "the new NRF was asked");
    }

    /// **#2099**: the caller-side rule. A certificate of the consumer naming NF
    /// types decides alone (no NRF); a certificate without NF types and no
    /// token, an anonymous caller and a certificate/token mismatch refuse; a
    /// token (alone or through an SCP) is the NRF's to vouch for, here seeded.
    ///
    /// REVERT-VERIFIED: with "no NF types" counted as `expected` (the #1860
    /// rule), the typeless certificate is admitted and its `unwrap_err` panics.
    #[tokio::test]
    async fn verified_nf_type_takes_the_certificate_else_the_nrf_2099() {
        const AMF: &str = "aaaaaaaa-2099-4000-8000-0000000000a3";
        const SCP: &str = "55555555-2099-4000-8000-000000000005";
        seed_nf_type_for_test(AMF, NfType::Amf);
        let ok = |r: SbiRequest| async move { verified_nf_type(&r, NfType::Amf).await };
        assert_eq!(
            ok(caller(Some(B), None, &["AMF"])).await,
            Ok(()),
            "direct AMF"
        );
        assert!(ok(caller(Some(B), None, &["SMF"]))
            .await
            .unwrap_err()
            .contains("not AMF"));
        assert!(
            ok(caller(Some(AMF), None, &[]))
                .await
                .unwrap_err()
                .contains("names no NF types"),
            "typeless certificate"
        );
        assert!(ok(caller(None, None, &[])).await.is_err(), "anonymous");
        assert!(
            ok(caller(Some(A), Some(B), &["AMF"])).await.is_err(),
            "mismatch"
        );
        assert_eq!(
            ok(caller(None, Some(AMF), &[])).await,
            Ok(()),
            "seeded token"
        );
        assert_eq!(
            ok(caller(Some(SCP), Some(AMF), &["SCP"])).await,
            Ok(()),
            "SCP + token"
        );
        assert_eq!(
            ok(caller(Some(AMF), Some(AMF), &[])).await,
            Ok(()),
            "typeless certificate plus its token"
        );
    }

    /// **#2113**: a certificate naming a relay type AND a consumer type is the
    /// consumer's, not a relay's. `[SCP, PCF]` relaying an AMF's token (seeded
    /// in the NRF as an AMF) is refused: its own id disagrees with the token's,
    /// and carrying the AMF's own id it is still typed by its certificate, which
    /// names no AMF. A relay-only certificate (`[SCP]`, `[SCP, SEPP]`) still
    /// lets the token decide.
    ///
    /// REVERT-VERIFIED: with `is_relay_certificate` back to "any type is a
    /// relay type", the `[SCP, PCF]` cases resolve to the AMF's token and the
    /// `mixed certificate` assertions fail.
    #[tokio::test]
    async fn a_certificate_naming_a_relay_and_a_consumer_type_is_the_consumers_2113() {
        const AMF: &str = "aaaaaaaa-2113-4000-8000-0000000000a3";
        const MIXED: &str = "cccccccc-2113-4000-8000-0000000000c3";
        seed_nf_type_for_test(AMF, NfType::Amf);
        let ok = |r: SbiRequest| async move { verified_nf_type(&r, NfType::Amf).await };
        assert!(is_relay_certificate(&["SCP"]));
        assert!(is_relay_certificate(&["scp", "SEPP"]));
        assert!(!is_relay_certificate(&["SCP", "PCF"]));
        assert!(!is_relay_certificate::<&str>(&[]));
        assert_eq!(
            verified_consumer_id(&caller(Some(MIXED), None, &["SCP", "PCF"])),
            Ok(Some(MIXED.into())),
            "mixed certificate: its own id is the identity"
        );
        assert!(
            verified_consumer_id(&caller(Some(MIXED), Some(AMF), &["SCP", "PCF"])).is_err(),
            "mixed certificate: it cannot relay another NF's token"
        );
        let refused = ok(caller(Some(MIXED), Some(AMF), &["SCP", "PCF"])).await;
        assert!(
            refused.is_err(),
            "mixed certificate + AMF token: {refused:?}"
        );
        let refused = ok(caller(Some(AMF), Some(AMF), &["PCF", "SCP"]))
            .await
            .unwrap_err();
        assert!(
            refused.contains("not AMF"),
            "mixed certificate typed: {refused}"
        );
        assert_eq!(
            ok(caller(Some(MIXED), Some(AMF), &["SCP", "SEPP"])).await,
            Ok(()),
            "relay-only certificate: the token decides"
        );
        assert_eq!(
            ok(caller(Some(AMF), None, &["AMF", "SCP"])).await,
            Ok(()),
            "a mixed certificate naming AMF is an AMF"
        );
    }

    const A: &str = "aaaaaaaa-1865-4000-8000-000000000001";
    const B: &str = "bbbbbbbb-1865-4000-8000-000000000002";

    /// REVERT-VERIFIED: with the mismatch arm removed the (A, B) caller
    /// resolves to A and the `is_err` assertion fails; with the relay filter
    /// removed the SCP-certificate cases resolve to B.
    #[test]
    fn the_identity_is_the_certificate_else_the_token_and_they_must_agree() {
        assert_eq!(
            verified_consumer_id(&caller(Some(A), None, &["AMF"])),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id(&caller(None, Some(A), &[])),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id(&caller(Some(A), Some(&A.to_uppercase()), &[])),
            Ok(Some(A.into()))
        );
        // Through an SCP: its certificate is not the consumer; the token is.
        assert_eq!(
            verified_consumer_id(&caller(Some(B), Some(A), &["SCP"])),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id(&caller(Some(B), None, &["sepp"])),
            Ok(None)
        );
        assert_eq!(verified_consumer_id(&caller(None, None, &[])), Ok(None));
        assert!(verified_consumer_id(&caller(Some(A), Some(B), &["AMF"])).is_err());
    }

    /// REVERT-VERIFIED: with the `required` arm removed the anonymous create
    /// under `required` returns `Ok(None)`; with the mismatch mapped to
    /// `Ok(None)` the mixed caller is not refused.
    #[test]
    fn create_refuses_a_mismatch_always_and_an_anonymous_caller_when_required() {
        let mixed = caller(Some(A), Some(B), &[]);
        for required in [false, true] {
            let refused = owner_for_new_resource_with(&mixed, "Subscribe", required)
                .expect_err("certificate and token disagree");
            assert_eq!(refused.status, 403);
            assert_eq!(
                owner_for_new_resource_with(&caller(None, Some(A), &[]), "Subscribe", required)
                    .ok(),
                Some(Some(A.into()))
            );
        }
        let anonymous = caller(None, None, &[]);
        assert_eq!(
            owner_for_new_resource_with(&anonymous, "Subscribe", false).ok(),
            Some(None)
        );
        let refused = owner_for_new_resource_with(&anonymous, "Subscribe", true)
            .expect_err("production refuses an anonymous create");
        assert_eq!(refused.status, 403);
    }

    /// REVERT-VERIFIED: with the caller comparison dropped (any verified caller
    /// passes) the foreign-certificate and foreign-token cases pass; with the
    /// frozen arm dropped the ownerless resource opens under `required`.
    #[test]
    fn only_the_owner_manages_a_bound_resource_and_an_ownerless_one_is_frozen_when_required() {
        for required in [false, true] {
            assert_eq!(
                non_owner_refusal_with(Some(A), &caller(Some(A), None, &[]), required),
                None
            );
            assert_eq!(
                non_owner_refusal_with(Some(A), &caller(None, Some(A), &[]), required),
                None
            );
            assert_eq!(
                non_owner_refusal_with(Some(A), &caller(Some(B), Some(A), &["SCP"]), required),
                None
            );
            for other in [
                caller(Some(B), None, &[]),
                caller(None, Some(B), &[]),
                caller(None, None, &[]),
                caller(Some(A), Some(B), &[]),
                caller(Some(A), None, &["SCP"]),
            ] {
                assert!(
                    non_owner_refusal_with(Some(A), &other, required).is_some(),
                    "{other:?} must not manage A's resource (required={required})"
                );
            }
        }
        // Ownerless: open under dev, frozen under production, for every caller.
        assert_eq!(
            non_owner_refusal_with(None, &caller(Some(B), None, &[]), false),
            None
        );
        for anyone in [caller(Some(B), None, &[]), caller(None, None, &[])] {
            let resp = refuse_non_owner_with(None, &anyone, "Unsubscribe", true)
                .expect("an ownerless resource is frozen under production");
            assert_eq!(resp.status, 403);
        }
        let resp = refuse_non_owner_with(Some(A), &caller(None, Some(B), &[]), "Op", false)
            .expect("a foreign caller is refused");
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn ids_are_unguessable() {
        let (x, y) = (unguessable_id(), unguessable_id());
        assert_ne!(x, y);
        assert_eq!(x.len(), 32);
        assert!(x.chars().all(|c| c.is_ascii_hexdigit()), "{x}");
    }
}
