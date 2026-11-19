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
/// `Err(detail)` when its certificate and token name different NF instances.
pub fn verified_consumer_id(request: &SbiRequest) -> Result<Option<String>, String> {
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
