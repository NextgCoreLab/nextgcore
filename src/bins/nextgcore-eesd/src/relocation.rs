//! EEC context relocation, T-EES side (TS 29.558 §5.10; TS 24.558 §5.2.2.2
//! step 2).
//!
//! When an EEC registers at a **target** EES carrying `(eecCntxId, srcEesId)`,
//! the spec has the T-EES *"retrieve the EEC's context from the source EES
//! according to the procedures specified in clause 5.10 of 3GPP TS 29.558"*. The
//! wire form is the same query-form pull this EES already **serves** (see
//! `handle_eec_context_pull`): `GET
//! {apiRoot}/eees-eeccontextreloc/v1/eec-contexts?ees-id=…&eec-cntx-id=…` →
//! `200` with an [`EECContext`], or `404`.
//!
//! # Why a seam rather than a bare client call
//!
//! [`pull_eec_context`] normally builds an [`SbiClient`] and performs the GET. A
//! process-global hook ([`set_pull_hook`]) can replace that with a closure, which
//! is what lets a test observe *whether the pull was invoked and with what* — the
//! thing #105's acceptance criterion asks for — without standing up a second EES.
//! Same shape as [`crate::notifier`]'s notifier slot.
//!
//! # Addressing the source EES
//!
//! `srcEesId` is `type: string` in `TS24558_Eees_EECRegistration.yaml:262-264`
//! and there is **no** companion member carrying the S-EES's endpoint, even
//! though the TS 24.558 prose says "an EEC context ID, a source EES endpoint".
//! This EES therefore treats `srcEesId` as the S-EES `apiRoot` when it is an
//! absolute `http(s)` URI and reports [`PullOutcome::NotAddressable`] otherwise:
//! there is no EES-level NRF discovery in this tree to resolve a bare identifier,
//! and guessing a host from an opaque id would issue requests to an address the
//! operator never configured.

use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use nextgcore_sbi::{SbiClient, SbiClientConfig, SbiRequest, UriScheme};

use crate::services::EECContext;

/// Fallback `ees-id` used when [`set_self_ees_id`] has not run (unit tests, and
/// any code path that reaches the pull before startup finished).
///
/// The pull's `ees-id` names the *requesting* EES (`yaml:81-92`) and is REQUIRED —
/// a conformant S-EES answers an empty one with `400 MANDATORY_IE_MISSING`, which
/// is exactly what this EES's own pull handler does — so it must never be blank.
pub const DEFAULT_EES_ID: &str = "nextgcore-eesd";

/// Resource path of the EEC-context collection, relative to the S-EES `apiRoot`.
const EEC_CONTEXTS_PATH: &str = "/eees-eeccontextreloc/v1/eec-contexts";

/// Wall-clock ceiling on one pull. The pull happens **inside** the registration
/// request, so an unreachable S-EES would otherwise hold the EEC's registration
/// open for the transport's own timeout; §5.2.2.2 does not make the retrieval a
/// precondition of the registration succeeding, so it must not be able to stall
/// it indefinitely.
pub const PULL_TIMEOUT: Duration = Duration::from_secs(3);

/// What this EES asks the source EES for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    /// `srcEesId` from the registration — the S-EES holding the context.
    pub src_ees_id: String,
    /// `eecCntxId` from the registration — the context to retrieve.
    pub eec_cntx_id: String,
    /// The `ees-id` query parameter: who is asking (this EES).
    pub self_ees_id: String,
}

/// Result of one attempted pull. Every variant is a distinct operator-visible
/// situation, which is why this is not `Option<EECContext>`: "the S-EES does not
/// have that context" and "we could not address the S-EES at all" call for
/// different action, and collapsing them would hide a misconfiguration behind a
/// message that reads like a stale context.
#[derive(Debug, Clone, PartialEq)]
pub enum PullOutcome {
    /// The S-EES returned `200` with a usable [`EECContext`].
    Retrieved(Box<EECContext>),
    /// `srcEesId` is not an absolute `http(s)` URI — see the module note.
    NotAddressable,
    /// The S-EES answered `404`: it holds no context under that `eecCntxId`.
    NotFound,
    /// Transport error, unexpected status, or an unparseable body.
    Failed(String),
}

/// A test/replacement pull implementation.
pub type PullHook = Arc<dyn Fn(&PullRequest) -> PullOutcome + Send + Sync>;

static HOOK: OnceLock<RwLock<Option<PullHook>>> = OnceLock::new();

fn hook_slot() -> &'static RwLock<Option<PullHook>> {
    HOOK.get_or_init(|| RwLock::new(None))
}

/// Install a pull implementation, replacing the real HTTP client. Process-global
/// and last-writer-wins, like [`crate::notifier::set_notifier`].
pub fn set_pull_hook(hook: PullHook) {
    if let Ok(mut g) = hook_slot().write() {
        *g = Some(hook);
    }
}

/// Remove any installed hook, restoring the real client.
pub fn clear_pull_hook() {
    if let Ok(mut g) = hook_slot().write() {
        *g = None;
    }
}

fn hook() -> Option<PullHook> {
    hook_slot().read().ok().and_then(|g| g.clone())
}

/// Serializes tests that install or clear the process-global pull hook.
///
/// The hook is process-global, so two tests running concurrently interleave
/// `set_pull_hook` / `clear_pull_hook` and each sees the other's state: one test's
/// `clear` lands between the other's `set` and its `pull_eec_context`, and the
/// pull falls through to a real DNS lookup. Every test that touches the slot —
/// here and in `main.rs` — must hold this.
#[cfg(test)]
pub static PULL_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`PULL_HOOK_LOCK`], ignoring poisoning: a panicking test must not turn
/// every later hook test into a spurious failure.
#[cfg(test)]
pub fn lock_pull_hook() -> std::sync::MutexGuard<'static, ()> {
    PULL_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

static SELF_EES_ID: OnceLock<RwLock<String>> = OnceLock::new();

fn self_ees_id_slot() -> &'static RwLock<String> {
    SELF_EES_ID.get_or_init(|| RwLock::new(DEFAULT_EES_ID.to_string()))
}

/// Publish this EES's identity for use as the pull's `ees-id`. Called once at
/// startup with the resolved `--ees-id`, so the pull presents the same identifier
/// the EES registers with at the ECS rather than a second, invented one.
pub fn set_self_ees_id(id: String) {
    if id.trim().is_empty() {
        return;
    }
    if let Ok(mut g) = self_ees_id_slot().write() {
        *g = id;
    }
}

/// This EES's `ees-id` for the pull, or [`DEFAULT_EES_ID`] before startup set it.
pub fn self_ees_id() -> String {
    self_ees_id_slot()
        .read()
        .map(|g| g.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// Retrieve an EEC context from the source EES (TS 29.558 §5.10).
///
/// Delegates to an installed [`PullHook`] when present. Otherwise splits
/// `src_ees_id` into an `SbiClient` target and performs the query-form `GET`,
/// bounded by [`PULL_TIMEOUT`].
pub async fn pull_eec_context(request: PullRequest) -> PullOutcome {
    if let Some(hook) = hook() {
        let outcome = hook(&request);
        log::debug!(
            "EEC context pull via installed hook: cntxId={} srcEesId={} -> {outcome:?}",
            request.eec_cntx_id,
            request.src_ees_id
        );
        return outcome;
    }

    let Some((scheme, host, port, root)) = parse_api_root(&request.src_ees_id) else {
        log::warn!(
            "EEC context pull skipped: srcEesId {:?} is not an absolute http(s) URI, and this \
             EES has no way to resolve a bare EES identifier to an address",
            request.src_ees_id
        );
        return PullOutcome::NotAddressable;
    };

    // The S-EES's own pull handler reads `sess-cntxs` as a JSON document; this
    // pull requests the WHOLE context (no narrowing), because a registering EEC
    // has not told us which application sessions it cares about.
    let uri = format!(
        "{root}{EEC_CONTEXTS_PATH}?ees-id={}&eec-cntx-id={}",
        request.self_ees_id, request.eec_cntx_id
    );
    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_scheme(scheme)
            .with_request_timeout(PULL_TIMEOUT)
            .with_pool_size(1),
    );
    match client.send_request(SbiRequest::get(uri)).await {
        Ok(resp) if resp.status == 200 => match resp.http.content.as_deref() {
            Some(body) => match serde_json::from_str::<EECContext>(body) {
                Ok(ctx) => PullOutcome::Retrieved(Box::new(ctx)),
                Err(e) => PullOutcome::Failed(format!("unparseable EECContext: {e}")),
            },
            None => PullOutcome::Failed("200 with an empty body".to_string()),
        },
        Ok(resp) if resp.status == 404 => PullOutcome::NotFound,
        Ok(resp) => PullOutcome::Failed(format!("S-EES answered {}", resp.status)),
        Err(e) => PullOutcome::Failed(format!("transport error: {e}")),
    }
}

/// Split an absolute `apiRoot` URI into `(scheme, host, port, root-path)`.
///
/// The trailing path is kept as the `apiRoot` prefix (TS 29.558 §7.5 allows a
/// deployment-specific prefix ahead of the service name), with any trailing `/`
/// removed so the joined URI never doubles the separator.
fn parse_api_root(uri: &str) -> Option<(UriScheme, String, u16, String)> {
    let (scheme, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (UriScheme::Https, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (UriScheme::Http, r)
    } else {
        return None;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (
            authority.to_string(),
            match scheme {
                UriScheme::Https => 443,
                _ => 80,
            },
        ),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port, path.trim_end_matches('/').to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_api_root_accepts_absolute_uris_and_rejects_bare_identifiers() {
        assert_eq!(
            parse_api_root("http://s-ees.example.com:8080"),
            Some((
                UriScheme::Http,
                "s-ees.example.com".to_string(),
                8080,
                String::new()
            ))
        );
        // Default port per scheme, and an apiRoot prefix is preserved without a
        // trailing slash (otherwise the joined URI carries `//eees-...`).
        assert_eq!(
            parse_api_root("https://s-ees.example.com/edge/"),
            Some((
                UriScheme::Https,
                "s-ees.example.com".to_string(),
                443,
                "/edge".to_string()
            ))
        );
        // A bare EES identifier is NOT addressable — this is the case the module
        // note is about, and returning a default host for it would send the pull
        // somewhere the operator never configured.
        assert_eq!(parse_api_root("ees-1"), None);
        assert_eq!(parse_api_root("s-ees.example.com"), None);
        assert_eq!(parse_api_root("ftp://s-ees.example.com"), None);
        assert_eq!(parse_api_root("http://"), None);
    }

    #[tokio::test]
    // The guard is deliberately held ACROSS the await: the whole point is that the
    // installed hook cannot change between `set_pull_hook` and the pull it is meant
    // to serve. Dropping it first would reinstate the race this lock exists for.
    #[allow(clippy::await_holding_lock)]
    async fn a_bare_src_ees_id_is_not_addressable_and_never_reaches_a_client() {
        let _guard = lock_pull_hook();
        clear_pull_hook();
        let outcome = pull_eec_context(PullRequest {
            src_ees_id: "ees-1".into(),
            eec_cntx_id: "cntx-1".into(),
            self_ees_id: "t-ees".into(),
        })
        .await;
        assert_eq!(outcome, PullOutcome::NotAddressable);
    }

    #[tokio::test]
    // The guard is deliberately held ACROSS the await: the whole point is that the
    // installed hook cannot change between `set_pull_hook` and the pull it is meant
    // to serve. Dropping it first would reinstate the race this lock exists for.
    #[allow(clippy::await_holding_lock)]
    async fn an_installed_hook_replaces_the_client_and_sees_the_request() {
        let _guard = lock_pull_hook();
        let seen = Arc::new(RwLock::new(Vec::<PullRequest>::new()));
        let recorder = seen.clone();
        set_pull_hook(Arc::new(move |req: &PullRequest| {
            if let Ok(mut g) = recorder.write() {
                g.push(req.clone());
            }
            PullOutcome::NotFound
        }));
        let outcome = pull_eec_context(PullRequest {
            src_ees_id: "http://s-ees.example.com".into(),
            eec_cntx_id: "cntx-9".into(),
            self_ees_id: "t-ees".into(),
        })
        .await;
        clear_pull_hook();
        assert_eq!(outcome, PullOutcome::NotFound);
        let calls = seen.read().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].eec_cntx_id, "cntx-9");
        assert_eq!(calls[0].self_ees_id, "t-ees");
    }
}
