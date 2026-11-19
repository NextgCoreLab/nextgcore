//! Caller-owner binding for SBI resources a consumer creates and then manages
//! (#1860, #1861, #1862; the pattern of nrfd #1809).
//!
//! A resource (an SM context, a subscription) is bound at creation to the
//! **verified** identity of the NF that created it, and a later modify, release,
//! retrieve or delete is answered `403` unless the caller proves that same
//! identity. TS 33.501 §13.4.1: the producer authorizes on the identity it
//! authenticated, never on an ID the body claims. The identity is read only from
//! what this process verified:
//!
//! - the OAuth2 access token's `sub` (TS 29.510 `AccessTokenClaims.sub`, the
//!   consumer's NF Instance ID), which survives an SCP hop (TS 33.501 §13.3), and
//! - the URI SAN NF Instance ID of the verified client certificate, unless that
//!   certificate names a relay type (SCP, SEPP), whose ID is not the consumer's.
//!
//! When both are present they must agree. A resource created with no verified
//! identity (the plaintext `dev` profile, or a record written before the binding
//! existed) has no owner and is managed as before; production always presents a
//! certificate and a token.
//!
//! Self-contained over [`SbiRequest`], and copied byte-identical into each NF
//! that needs it, so #1865 can lift one copy into nextgcore-sbi and delete the
//! others.

use nextgcore_sbi::message::{SbiRequest, SbiResponse};

/// Certificate NF types that identify a relay rather than the consumer.
pub const RELAY_NF_TYPES: &[&str] = &["SCP", "SEPP"];

/// NF Instance IDs are UUIDs (TS 29.571 `NfInstanceId`), compared without case.
pub fn same_nf_instance_id(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The caller's verified NF Instance ID, `Ok(None)` when it proved none, or
/// `Err(detail)` when its two verified identities disagree.
pub fn verified_consumer_id(request: &SbiRequest) -> Result<Option<String>, String> {
    let token = request
        .oauth2_subject
        .as_deref()
        .filter(|s| !s.trim().is_empty());
    let relay = request
        .peer_cert_nf_types
        .iter()
        .any(|t| RELAY_NF_TYPES.iter().any(|r| r.eq_ignore_ascii_case(t)));
    let cert = request
        .peer_cert_nf_instance_id
        .as_deref()
        .filter(|s| !relay && !s.trim().is_empty());
    match (token, cert) {
        (Some(t), Some(c)) if !same_nf_instance_id(t, c) => Err(format!(
            "the requester's access token subject ({t:?}) and client certificate ({c:?}) \
             name different NF instances"
        )),
        (Some(t), _) => Ok(Some(t.to_string())),
        (None, Some(c)) => Ok(Some(c.to_string())),
        (None, None) => Ok(None),
    }
}

/// The owner to record for a resource `request` is creating: `Ok(None)` when
/// the caller proved no identity. `Err` is the `403` to send instead of creating.
pub fn owner_for_new_resource(
    request: &SbiRequest,
    operation: &str,
) -> Result<Option<String>, Box<SbiResponse>> {
    verified_consumer_id(request).map_err(|why| Box::new(forbidden(operation, &why)))
}

/// Why `request` may not act on a resource bound to `owner`, or `None` if it
/// may. An ownerless resource binds nothing.
pub fn non_owner_refusal(owner: Option<&str>, request: &SbiRequest) -> Option<String> {
    let owner = owner?;
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
    let why = non_owner_refusal(owner, request)?;
    Some(forbidden(operation, &why))
}

/// A resource identifier nobody can guess: 122 random bits (UUID v4), so
/// knowing one ID tells a peer nothing about another.
pub fn unguessable_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn forbidden(operation: &str, why: &str) -> SbiResponse {
    // debug, not warn: a peer can send these at will (#1620 review m7).
    log::debug!("{operation} refused: {why}");
    nextgcore_sbi::server::send_forbidden(&format!("{operation}: {why}"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(token: Option<&str>, cert: Option<&str>, types: &[&str]) -> SbiRequest {
        let mut r = SbiRequest::post("/x");
        r.oauth2_subject = token.map(str::to_string);
        r.peer_cert_nf_instance_id = cert.map(str::to_string);
        r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        r
    }

    const A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
    const B: &str = "bbbbbbbb-0000-4000-8000-000000000002";

    #[test]
    fn the_verified_identity_is_the_token_or_a_non_relay_certificate() {
        assert_eq!(
            verified_consumer_id(&caller(Some(A), None, &[])),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id(&caller(None, Some(A), &["AMF"])),
            Ok(Some(A.into()))
        );
        // Through an SCP: its certificate is not the consumer; the token is.
        assert_eq!(
            verified_consumer_id(&caller(Some(A), Some(B), &["SCP"])),
            Ok(Some(A.into()))
        );
        assert_eq!(
            verified_consumer_id(&caller(None, Some(B), &["SCP"])),
            Ok(None)
        );
        assert_eq!(verified_consumer_id(&caller(None, None, &[])), Ok(None));
        assert!(verified_consumer_id(&caller(Some(A), Some(B), &["AMF"])).is_err());
        assert_eq!(
            verified_consumer_id(&caller(Some(A), Some(&A.to_uppercase()), &[])),
            Ok(Some(A.into()))
        );
    }

    #[test]
    fn only_the_owner_passes_a_bound_resource() {
        assert_eq!(
            non_owner_refusal(Some(A), &caller(Some(A), None, &[])),
            None
        );
        assert_eq!(
            non_owner_refusal(Some(A), &caller(None, Some(A), &[])),
            None
        );
        for other in [
            caller(Some(B), None, &[]),
            caller(None, Some(B), &[]),
            caller(None, None, &[]),
            caller(Some(A), Some(B), &[]),
            caller(None, Some(A), &["SCP"]),
        ] {
            assert!(non_owner_refusal(Some(A), &other).is_some(), "{other:?}");
        }
        // Ownerless: as before.
        assert_eq!(non_owner_refusal(None, &caller(Some(B), None, &[])), None);
        let resp = refuse_non_owner(Some(A), &caller(Some(B), None, &[]), "Op").unwrap();
        assert_eq!(resp.status, 403);
    }

    #[test]
    fn ids_are_unguessable() {
        let (x, y) = (unguessable_id(), unguessable_id());
        assert_ne!(x, y);
        assert_eq!(x.len(), 32);
        assert!(x.parse::<u64>().is_err());
    }
}
