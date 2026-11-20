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
//!    certificate names a relay type ([`RELAY_NF_TYPES`]: an SCP or SEPP is not
//!    the consumer), else
//! 2. the `sub` of the verified OAuth2 access token
//!    ([`SbiRequest::oauth2_subject`], TS 29.510 `AccessTokenClaims.sub`, the
//!    consumer's NF Instance ID), which survives an SCP hop (TS 33.501 §13.3).
//!
//! A relay is recognised only by the RFC 9310 NFTypes extension of its
//! certificate. #2065: a certificate that names NO NF type cannot be told from a
//! relay's, so under the `production` SBI profile it is not an identity at all:
//! with a token, the token's `sub` is the caller; without one, the caller is
//! refused (an untyped SCP certificate would otherwise own every resource
//! created through it, fail-open). Under `dev` an untyped certificate still
//! counts as the consumer, as before: it then disagrees with a consumer's token
//! behind an SCP and the request is refused (R32 on #1936).
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
/// `Err(detail)` when its certificate and token name different NF instances,
/// or (#2065, under [`identity_required`]) when its only identity is a
/// certificate that names no NF type.
pub fn verified_consumer_id(request: &SbiRequest) -> Result<Option<String>, String> {
    verified_consumer_id_with(request, identity_required())
}

/// [`verified_consumer_id`] with an explicit `required` (the production rule of
/// #2065 for an untyped certificate).
pub fn verified_consumer_id_with(
    request: &SbiRequest,
    required: bool,
) -> Result<Option<String>, String> {
    let untyped = request.peer_cert_nf_types.is_empty()
        && request
            .peer_cert_nf_instance_id
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
    if required && untyped {
        // #2065: an untyped certificate is not an identity under production.
        return match request
            .oauth2_subject
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(sub) => Ok(Some(sub.to_string())),
            None => Err(
                "the requester's client certificate names no NF type (RFC 9310 \
                         NFTypes), so it cannot be told from a relay's, and it presented no \
                         access token"
                    .to_string(),
            ),
        };
    }
    let relay = request
        .peer_cert_nf_types
        .iter()
        .any(|t| RELAY_NF_TYPES.iter().any(|r| r.eq_ignore_ascii_case(t)));
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
    match verified_consumer_id_with(request, required) {
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
    match verified_consumer_id_with(request, required) {
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

/// At most this many cached answers; a full cache drops the expired ones, then
/// everything, rather than grow.
const NF_TYPE_CACHE_MAX: usize = 1024;

/// (NF type, NF instance ID) -> (the NRF lists that instance with that type,
/// valid until). Both answers are cached; a lookup that fails is never cached:
/// it refuses, and the next call asks again.
type NfTypeCache = std::collections::HashMap<String, (bool, std::time::Instant)>;

fn nf_type_cache() -> std::sync::MutexGuard<'static, NfTypeCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<NfTypeCache>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| std::sync::Mutex::new(NfTypeCache::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn nf_type_key(nf_type: &str, id: &str) -> String {
    format!(
        "{}:{}",
        nf_type.to_ascii_uppercase(),
        id.trim().to_ascii_lowercase()
    )
}

/// Tests (of this crate and, through the `test-support` feature, of the NFs):
/// record that the NRF lists `id` as an `nf_type`, for the whole test run, so a
/// token-identified caller needs no NRF. Only ever adds a positive answer for
/// that one type, so tests using their own ids cannot collide.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_nf_type_for_test(id: &str, nf_type: crate::types::NfType) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(24 * 3600);
    nf_type_cache().insert(nf_type_key(nf_type.to_str(), id), (true, until));
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
    if let Some(listed) = cached_nf_type(id, nf_type) {
        return Ok(listed);
    }
    let ctx = crate::context::global_context();
    let nrf_uri = ctx
        .get_nrf_uri()
        .await
        .ok_or("no NRF is configured to look the caller up")?;
    let requester = ctx.get_self_instance().await.map(|i| i.nf_type);
    cached_nrf_lists_nf_type_at(&nrf_uri, id, nf_type, requester).await
}

fn cached_nf_type(id: &str, nf_type: crate::types::NfType) -> Option<bool> {
    let (listed, until) = nf_type_cache()
        .get(&nf_type_key(nf_type.to_str(), id))
        .copied()?;
    (std::time::Instant::now() < until).then_some(listed)
}

/// [`nrf_lists_nf_type_at`] through the cache: an answer is reused for
/// [`NF_TYPE_TTL`]; a failed lookup is not cached.
async fn cached_nrf_lists_nf_type_at(
    nrf_uri: &str,
    id: &str,
    nf_type: crate::types::NfType,
    requester: Option<crate::types::NfType>,
) -> Result<bool, String> {
    if let Some(listed) = cached_nf_type(id, nf_type) {
        return Ok(listed);
    }
    let key = nf_type_key(nf_type.to_str(), id);
    let listed = nrf_lists_nf_type_at(nrf_uri, id, nf_type, requester).await?;
    let mut cache = nf_type_cache();
    if cache.len() >= NF_TYPE_CACHE_MAX {
        let now = std::time::Instant::now();
        cache.retain(|_, (_, until)| now < *until);
        if cache.len() >= NF_TYPE_CACHE_MAX {
            cache.clear();
        }
    }
    cache.insert(key, (listed, std::time::Instant::now() + NF_TYPE_TTL));
    Ok(listed)
}

/// #2099 (CONVENTIONS: a caller's NF type is verified, never assumed): `Ok`
/// when the caller of `request` is shown to be an `expected`, else `Err` with
/// why. The one rule smfd's AMF-change gate (#2078) and lmfd's
/// LocationContextTransfer (#2077) apply:
///
/// - the caller's identity is [`verified_consumer_id`]'s; none, or a
///   certificate/token mismatch, refuses;
/// - the consumer's own client certificate (not a relay's, [`RELAY_NF_TYPES`])
///   naming NF types (RFC 9310, TS 33.310 §6.1.3c) must name `expected`;
/// - otherwise -- a token alone, a token through an SCP or SEPP, or a
///   certificate without NF types plus a token -- the NRF must list the
///   token's verified subject as an `expected` ([`nrf_lists_nf_type_at`],
///   cached for [`NF_TYPE_TTL`]), and a lookup that fails refuses. An access
///   token names no NF type of its consumer (TS 29.510 `AccessTokenClaims`), so
///   the NRF is the only verified source;
/// - a certificate without NF types and no token refuses: it cannot be told
///   apart from a relay's.
pub async fn verified_nf_type(
    request: &SbiRequest,
    expected: crate::types::NfType,
) -> Result<(), String> {
    verified_nf_type_with(request, expected, identity_required()).await
}

/// [`verified_nf_type`] with an explicit `required` (the production rule of
/// #2065, passed on to [`verified_consumer_id_with`]): under it a certificate
/// without NF types and no token is refused as no identity at all, before any
/// NF-type check.
pub async fn verified_nf_type_with(
    request: &SbiRequest,
    expected: crate::types::NfType,
    required: bool,
) -> Result<(), String> {
    let want = expected.to_str();
    match verified_consumer_id_with(request, required)? {
        Some(_) => {}
        None => return Err("the requester has no verified identity".to_string()),
    }
    let types = &request.peer_cert_nf_types;
    let relay = types
        .iter()
        .any(|t| RELAY_NF_TYPES.iter().any(|r| r.eq_ignore_ascii_case(t)));
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

    /// **#2099**: the caller-side rule. A certificate of the consumer naming NF
    /// types decides alone (no NRF); a certificate without NF types and no
    /// token, an anonymous caller and a certificate/token mismatch refuse; a
    /// token (alone or through an SCP) is the NRF's to vouch for, here seeded.
    ///
    /// Both profiles are passed explicitly (`verified_nf_type_with`), so the
    /// test reads no process-global profile and passes run alone (#2089 R40:
    /// it used to depend on a sibling having set Dev). Under production
    /// (#2065) the typeless certificate is refused as no identity at all,
    /// before the NF-type check; under dev it reaches the NF-type check and is
    /// refused there.
    ///
    /// REVERT-VERIFIED: with "no NF types" counted as `expected` (the #1860
    /// rule), the dev typeless certificate is admitted and its `unwrap_err`
    /// panics; with #2065's untyped arm off, the production typeless
    /// certificate gets the NF-type message and "no identity" fails.
    #[tokio::test]
    async fn verified_nf_type_takes_the_certificate_else_the_nrf_2099() {
        const AMF: &str = "aaaaaaaa-2099-4000-8000-0000000000a3";
        const SCP: &str = "55555555-2099-4000-8000-000000000005";
        seed_nf_type_for_test(AMF, NfType::Amf);
        for production in [true, false] {
            let ok = |r: SbiRequest| async move {
                verified_nf_type_with(&r, NfType::Amf, production).await
            };
            assert_eq!(
                ok(caller(Some(B), None, &["AMF"])).await,
                Ok(()),
                "direct AMF (production={production})"
            );
            assert!(ok(caller(Some(B), None, &["SMF"]))
                .await
                .unwrap_err()
                .contains("not AMF"));
            assert!(ok(caller(None, None, &[])).await.is_err(), "anonymous");
            assert!(
                ok(caller(Some(A), Some(B), &["AMF"])).await.is_err(),
                "mismatch"
            );
            assert_eq!(
                ok(caller(None, Some(AMF), &[])).await,
                Ok(()),
                "seeded token (production={production})"
            );
            assert_eq!(
                ok(caller(Some(SCP), Some(AMF), &["SCP"])).await,
                Ok(()),
                "SCP + token (production={production})"
            );
            assert_eq!(
                ok(caller(Some(AMF), Some(AMF), &[])).await,
                Ok(()),
                "typeless certificate plus its token (production={production})"
            );
        }
        let production = verified_nf_type_with(&caller(Some(AMF), None, &[]), NfType::Amf, true)
            .await
            .unwrap_err();
        assert!(
            production.contains("names no NF type (RFC 9310 NFTypes)")
                && production.contains("presented no access token"),
            "under production a typeless certificate alone is no identity: {production}"
        );
        let dev = verified_nf_type_with(&caller(Some(AMF), None, &[]), NfType::Amf, false)
            .await
            .unwrap_err();
        assert!(
            dev.contains("names no NF types") && dev.contains("cannot be shown to be an AMF"),
            "under dev a typeless certificate alone fails the NF-type check: {dev}"
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
            verified_consumer_id_with(&caller(Some(A), None, &["AMF"]), false),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id_with(&caller(None, Some(A), &[]), false),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id_with(&caller(Some(A), Some(&A.to_uppercase()), &[]), false),
            Ok(Some(A.into()))
        );
        // Through an SCP: its certificate is not the consumer; the token is.
        assert_eq!(
            verified_consumer_id_with(&caller(Some(B), Some(A), &["SCP"]), false),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id_with(&caller(Some(B), None, &["sepp"]), false),
            Ok(None)
        );
        assert_eq!(
            verified_consumer_id_with(&caller(None, None, &[]), false),
            Ok(None)
        );
        assert!(verified_consumer_id_with(&caller(Some(A), Some(B), &["AMF"]), false).is_err());
    }

    /// #2065: under production a certificate naming no NF type is not an identity:
    /// alone it is refused (it cannot be told from an untyped relay's, which would
    /// own every resource created through it); with a token the token's `sub` is
    /// the caller. Typed certificates and dev are unchanged. REVERT-VERIFIED: with
    /// the untyped arm removed, the lone untyped certificate is accepted as A.
    #[test]
    fn an_untyped_certificate_is_no_identity_under_production_2065() {
        assert!(
            verified_consumer_id_with(&caller(Some(A), None, &[]), true).is_err(),
            "an untyped certificate alone must be refused"
        );
        assert_eq!(
            verified_consumer_id_with(&caller(Some(B), Some(A), &[]), true),
            Ok(Some(A.into())),
            "with a token, the token's sub is the caller"
        );
        assert_eq!(
            verified_consumer_id_with(&caller(Some(A), None, &["AMF"]), true),
            Ok(Some(A.into())),
            "a typed certificate is still an identity"
        );
        // Dev: as before.
        assert_eq!(
            verified_consumer_id_with(&caller(Some(A), None, &[]), false),
            Ok(Some(A.into()))
        );
        // Through the create and manage paths.
        assert!(owner_for_new_resource_with(&caller(Some(A), None, &[]), "Create", true).is_err());
        assert!(non_owner_refusal_with(Some(A), &caller(Some(A), None, &[]), true).is_some());
        assert_eq!(
            non_owner_refusal_with(Some(A), &caller(Some(B), Some(A), &[]), true),
            None
        );
    }

    /// (#2065: the certificates here are typed, an AMF's; an untyped one is no
    /// identity under `required`, see `an_untyped_certificate_is_no_identity_...`.)
    /// REVERT-VERIFIED: with the `required` arm removed the anonymous create
    /// under `required` returns `Ok(None)`; with the mismatch mapped to
    /// `Ok(None)` the mixed caller is not refused.
    #[test]
    fn create_refuses_a_mismatch_always_and_an_anonymous_caller_when_required() {
        let mixed = caller(Some(A), Some(B), &["AMF"]);
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
                non_owner_refusal_with(Some(A), &caller(Some(A), None, &["AMF"]), required),
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
                caller(Some(B), None, &["AMF"]),
                caller(None, Some(B), &[]),
                caller(None, None, &[]),
                caller(Some(A), Some(B), &["AMF"]),
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
            non_owner_refusal_with(None, &caller(Some(B), None, &["AMF"]), false),
            None
        );
        for anyone in [caller(Some(B), None, &["AMF"]), caller(None, None, &[])] {
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
