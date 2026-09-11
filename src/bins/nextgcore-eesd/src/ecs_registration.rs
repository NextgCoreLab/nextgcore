//! EES self-registration toward the Edge Configuration Server (ECS).
//!
//! TS 29.558 §9 `Eecs_EESRegistration`: the EES registers itself with the ECS
//! (reference point EDGE-6), NOT with the 5GC NRF — the EES is an Edge Enabler
//! Layer entity and has no `nfType` in TS 29.510. This module replaces the old
//! (incorrect) NRF self-registration as an `nfType "EES"` NF (eesd-01).
//!
//! Wire shape: `POST {ecsApiRoot}/eecs-eesregistration/v1/registrations`
//! (operationId `CreateEESRegistration`) with an `EESRegistration` body; the
//! ECS returns the resource at `registrations/{registrationId}` which is
//! refreshed periodically (PUT).
//!
//! Registration is gated behind the `--ecs-uri` config: when unset, the request is
//! built and logged but skipped (the request SHAPE is still unit-tested). When set,
//! the request is POSTed via the existing `nextgcore-sbi` client and a refresh task
//! is spawned. A live ECS now exists in this stack -- `ecs_role` serves the
//! EDGE-6 side when `ECS_ROLE=1` (#107).
//!
//! # What #107 hardened
//!
//! Three things made this brittle, and all three were silent:
//!
//! 1. **One POST and then give up.** A transient blip during startup dropped the
//!    EES from the ECS registry permanently, with one `warn` line. Now retried with
//!    capped exponential backoff.
//! 2. **The refresh only ever PUT.** A 404 -- exactly what an ECS returns for a
//!    resource it lost across a restart -- was logged and the loop kept PUTting to a
//!    resource that no longer existed, forever. Now it re-POSTs and adopts the new
//!    `registrationId`.
//! 3. **A static body.** `easIds: None` and `expTime: None` meant the ECS's view of
//!    this EES was wrong even on the happy path, so target-EES selection could
//!    never match it. Both are now derived from live state on every POST and every
//!    refresh.

use std::time::Duration;

use nextgcore_sbi::context::global_context;
use serde::{Deserialize, Serialize};

use crate::types::EndPoint;

/// API name + version prefix for the ECS-side EES registration service.
pub const ECS_API_PREFIX: &str = "eecs-eesregistration/v1";

/// Resource path (relative to the ECS apiRoot) of the EES registrations
/// collection.
pub fn ecs_registration_collection_path() -> String {
    format!("/{ECS_API_PREFIX}/registrations")
}

/// Resource path of an individual EES registration.
pub fn ecs_registration_resource_path(registration_id: &str) -> String {
    format!("/{ECS_API_PREFIX}/registrations/{registration_id}")
}

/// TS 29.558 §8 `EESProfile` (subset) — the EES's own description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EesProfile {
    /// EES identifier.
    pub ees_id: String,
    /// EES service endpoint(s).
    pub end_pt: EndPoint,
    /// Provider identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prov_id: Option<String>,
    /// EAS application identifiers this EES serves (optional; populated as EASs
    /// register).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eas_ids: Option<Vec<String>>,
}

/// TS 29.558 §8 `EESRegistration` (subset) — body of `CreateEESRegistration`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EesRegistration {
    /// EES profile (mandatory).
    pub ees_prof: EesProfile,
    /// Registration expiration time (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_time: Option<String>,
    /// Supported features (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supp_feat: Option<String>,
}

/// How long a registration this EES creates is valid for. The refresh loop runs at
/// [`REFRESH_INTERVAL`], comfortably inside it, so a live EES is never expired by
/// an ECS that honours `expTime` -- while an EES that has stopped refreshing is.
pub const REGISTRATION_LIFETIME: Duration = Duration::from_secs(600);

/// How often the registration is refreshed.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// The EAS application identifiers this EES currently serves.
///
/// Read from the live EAS pool on every POST and every refresh, which is the whole
/// point of #107's criterion 5: a static `easIds: None` makes the ECS's view of this
/// EES wrong even on the happy path, and `Eecs_TargetEESDiscovery` matches on
/// exactly this member -- so an EES advertising none can never be selected as a
/// target.
///
/// `None` rather than `Some([])` when the pool is empty: the member is optional, and
/// an empty array asserts "serves no EAS" where absent says "not stated". An EES
/// with no EAS yet is the former, so an empty array is in fact the honest value --
/// but sending it would make an ECS that filters on presence treat this EES as
/// having declared itself useless. Absent is the conservative reading and matches
/// what the ECS role's discovery does with it (no match either way).
fn current_eas_ids() -> Option<Vec<String>> {
    let ctx = crate::context::ees_self();
    let guard = ctx.read().ok()?;
    let mut ids: Vec<String> = guard
        .eas_list()
        .into_iter()
        .map(|r| r.eas_prof.eas_id)
        .collect();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

/// An RFC 3339 timestamp [`REGISTRATION_LIFETIME`] from now, for `expTime`.
///
/// Formatted here rather than pulled from a date crate this binary does not depend
/// on: the shape is `YYYY-MM-DDTHH:MM:SSZ` and the arithmetic is a civil-date
/// conversion from the Unix epoch, which is exact for all values this produces.
fn expiry_timestamp() -> Option<String> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        + REGISTRATION_LIFETIME.as_secs();
    Some(rfc3339_utc(secs))
}

/// Format a Unix timestamp as an RFC 3339 UTC instant.
fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // Civil-from-days (Howard Hinnant's algorithm), shifted to a March-based year.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Build the `EESRegistration` body the EES POSTs to the ECS.
///
/// `easIds` and `expTime` are derived from live state, not left `None` (#107).
pub fn build_ees_registration(ees_id: &str, sbi_addr: &str, sbi_port: u16) -> EesRegistration {
    EesRegistration {
        ees_prof: EesProfile {
            ees_id: ees_id.to_string(),
            end_pt: EndPoint {
                ipv4_addrs: Some(vec![sbi_addr.to_string()]),
                port: Some(sbi_port as u32),
                ..Default::default()
            },
            prov_id: None,
            eas_ids: current_eas_ids(),
        },
        exp_time: expiry_timestamp(),
        supp_feat: None,
    }
}

/// Parse "scheme://host:port[/path]" into ("host", port).
pub(crate) fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let host_port = without_scheme
        .split_once('/')
        .map(|(hp, _)| hp)
        .unwrap_or(without_scheme);
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port_str.parse().ok()?))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
}

/// Start EES self-registration toward the ECS.
///
/// When `ecs_uri` is `None`, logs the built request and skips (no live ECS).
/// When `Some`, POSTs the `EESRegistration` and, on success, spawns a periodic
/// refresh task (PUT to the returned resource).
pub async fn start_ecs_registration(
    ecs_uri: Option<&str>,
    ees_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) {
    let registration = build_ees_registration(ees_id, sbi_addr, sbi_port);

    let Some(ecs_uri) = ecs_uri else {
        log::info!(
            "No --ecs-uri configured; skipping ECS self-registration. \
             Would POST {} with EESRegistration {{ eesId={ees_id} }}",
            ecs_registration_collection_path(),
        );
        return;
    };

    match register_with_backoff(ecs_uri, ees_id, sbi_addr, sbi_port).await {
        Some(registration_id) => {
            log::info!("EES registered with ECS at {ecs_uri} (registrationId={registration_id})");
            spawn_refresh(
                ecs_uri.to_string(),
                ees_id.to_string(),
                sbi_addr.to_string(),
                sbi_port,
                registration_id,
            );
        }
        None => log::warn!(
            "ECS registration did not succeed after {MAX_REGISTRATION_ATTEMPTS} attempts; \
             operating without ECS. EAS discovery through the edge layer will not work until \
             an operator restarts this EES or the refresh loop is given a registration."
        ),
    }
}

/// Attempts before giving up on the initial registration.
pub const MAX_REGISTRATION_ATTEMPTS: u32 = 5;

/// The first backoff delay; doubles per attempt up to [`MAX_BACKOFF`].
pub const BASE_BACKOFF: Duration = Duration::from_millis(500);

/// The cap. Bounded because an unbounded doubling reaches hours, and an EES that
/// takes hours to notice the ECS came back is not meaningfully better than one that
/// gave up.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The delay before attempt `attempt` (1-based). Exposed so the test asserts on the
/// same schedule the loop uses rather than on a copy of it.
pub fn backoff_for_attempt(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    let scaled = BASE_BACKOFF
        .checked_mul(1u32 << shift)
        .unwrap_or(MAX_BACKOFF);
    scaled.min(MAX_BACKOFF)
}

/// POST the registration, retrying with capped exponential backoff (#107).
///
/// The body is rebuilt on every attempt rather than captured once: `easIds` comes
/// from the live EAS pool, and an EAS that registered while the ECS was unreachable
/// must appear in the registration that finally lands.
async fn register_with_backoff(
    ecs_uri: &str,
    ees_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) -> Option<String> {
    for attempt in 1..=MAX_REGISTRATION_ATTEMPTS {
        let registration = build_ees_registration(ees_id, sbi_addr, sbi_port);
        match register_once(ecs_uri, &registration).await {
            Ok(Some(id)) => return Some(id),
            Ok(None) => {
                // Accepted but unusable: without the id the refresh loop has no
                // resource to PUT, so this is a failure and not a success.
                log::warn!(
                    "ECS registration attempt {attempt} was accepted but returned no \
                     registrationId; retrying"
                );
            }
            Err(e) => log::warn!("ECS registration attempt {attempt} failed: {e}"),
        }
        if attempt < MAX_REGISTRATION_ATTEMPTS {
            let delay = backoff_for_attempt(attempt);
            log::debug!("retrying ECS registration in {delay:?}");
            tokio::time::sleep(delay).await;
        }
    }
    None
}

/// POST the `EESRegistration` to the ECS once; returns the assigned
/// `registrationId` (from the `Location` header or response body) on success.
async fn register_once(
    ecs_uri: &str,
    registration: &EesRegistration,
) -> Result<Option<String>, String> {
    let (host, port) = parse_host_port(ecs_uri).ok_or_else(|| "invalid --ecs-uri".to_string())?;
    let client = global_context().get_client(&host, port).await;
    let path = ecs_registration_collection_path();

    log::debug!("ECS registration: POST {path}");
    let response = client
        .post_json(&path, registration)
        .await
        .map_err(|e| format!("POST {path} failed: {e}"))?;

    match response.status {
        200 | 201 => Ok(extract_registration_id(&response)),
        s => Err(format!("ECS registration returned status {s}")),
    }
}

/// Extract the assigned registrationId from the `Location` header (last path
/// segment) or, failing that, the response body's `registrationId` field.
fn extract_registration_id(response: &nextgcore_sbi::message::SbiResponse) -> Option<String> {
    if let Some(loc) = response.http.get_header("location") {
        if let Some(id) = loc.trim_end_matches('/').rsplit('/').next() {
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    response
        .http
        .content
        .as_ref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|v| {
            v.get("registrationId")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
}

/// Spawn a periodic refresh task that PUTs the registration to keep it alive, and
/// **re-creates it when the ECS no longer has it** (#107).
fn spawn_refresh(
    ecs_uri: String,
    ees_id: String,
    sbi_addr: String,
    sbi_port: u16,
    registration_id: String,
) {
    tokio::spawn(async move {
        let mut registration_id = registration_id;
        loop {
            tokio::time::sleep(REFRESH_INTERVAL).await;
            match refresh_once(&ecs_uri, &ees_id, &sbi_addr, sbi_port, &registration_id).await {
                RefreshOutcome::Refreshed => {
                    log::debug!("ECS registration refreshed (registrationId={registration_id})")
                }
                RefreshOutcome::Recreated(new_id) => {
                    log::warn!(
                        "ECS no longer held registration {registration_id} (it restarted, or \
                         expired us); re-registered as {new_id}"
                    );
                    registration_id = new_id;
                }
                RefreshOutcome::Failed => {
                    // Kept in the loop rather than abandoned: the next tick is the
                    // retry, which is what makes a transient ECS outage survivable.
                }
                RefreshOutcome::Fatal => break,
            }
        }
    });
}

/// What one refresh tick achieved.
#[derive(Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The PUT was accepted.
    Refreshed,
    /// The ECS did not have the resource, so it was re-created under a new id.
    Recreated(String),
    /// This tick failed; the next one retries.
    Failed,
    /// Unrecoverable (the ECS URI stopped parsing), so the loop stops.
    Fatal,
}

/// One refresh: PUT, and on **any non-2xx** re-POST to re-create the registration.
///
/// Not only on 404. A 404 is the case #107 names -- an ECS that lost the resource
/// across a restart -- but a 410 Gone, or a 400 from an ECS that has forgotten the
/// schema version this id was created under, leave the EES in exactly the same
/// state: PUTting a resource that will never accept it again. Re-creating is
/// idempotent from this side (the ECS mints a fresh id), so the narrower check would
/// buy nothing and would leave those statuses looping forever.
///
/// The body is rebuilt from live state, so a refresh carries the EASs that have
/// registered since the last one -- criterion 5's "updated on EAS
/// register/deregister", achieved by deriving at send time rather than by hooking
/// every mutation.
pub async fn refresh_once(
    ecs_uri: &str,
    ees_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
    registration_id: &str,
) -> RefreshOutcome {
    let Some((host, port)) = parse_host_port(ecs_uri) else {
        log::error!("ECS URI '{ecs_uri}' stopped parsing; abandoning the refresh loop");
        return RefreshOutcome::Fatal;
    };
    let registration = build_ees_registration(ees_id, sbi_addr, sbi_port);
    let path = ecs_registration_resource_path(registration_id);
    let client = global_context().get_client(&host, port).await;
    match client.put_json(&path, &registration).await {
        Ok(r) if (200..300).contains(&r.status) => RefreshOutcome::Refreshed,
        Ok(r) => {
            log::warn!(
                "ECS registration refresh returned status {}; re-creating the registration",
                r.status
            );
            match register_once(ecs_uri, &registration).await {
                Ok(Some(new_id)) => RefreshOutcome::Recreated(new_id),
                Ok(None) => {
                    log::warn!("ECS re-registration was accepted but returned no registrationId");
                    RefreshOutcome::Failed
                }
                Err(e) => {
                    log::warn!("ECS re-registration failed: {e}");
                    RefreshOutcome::Failed
                }
            }
        }
        Err(e) => {
            log::warn!("ECS registration refresh failed: {e}");
            RefreshOutcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// eesd-01: the ECS registration request is built with the correct
    /// `eecs-eesregistration` path and a camelCase `EESRegistration` body.
    #[test]
    fn test_build_ees_registration_shape() {
        let reg = build_ees_registration("ees1.example.com", "10.0.0.5", 7814);
        assert_eq!(reg.ees_prof.ees_id, "ees1.example.com");
        assert_eq!(reg.ees_prof.end_pt.port, Some(7814));
        assert_eq!(
            reg.ees_prof.end_pt.ipv4_addrs.as_deref(),
            Some(["10.0.0.5".to_string()].as_slice())
        );

        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"eesProf\""));
        assert!(json.contains("\"eesId\":\"ees1.example.com\""));
        assert!(json.contains("\"endPt\""));
        assert!(json.contains("\"ipv4Addrs\""));
    }

    #[test]
    fn test_ecs_registration_paths() {
        assert_eq!(
            ecs_registration_collection_path(),
            "/eecs-eesregistration/v1/registrations"
        );
        assert_eq!(
            ecs_registration_resource_path("abc-123"),
            "/eecs-eesregistration/v1/registrations/abc-123"
        );
    }

    #[test]
    fn test_ees_registration_roundtrip() {
        let reg = build_ees_registration("ees1.example.com", "10.0.0.5", 7814);
        let json = serde_json::to_string(&reg).unwrap();
        let back: EesRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }

    // ── #107: the hardened client ──

    /// The backoff schedule increases and is capped, asserted on the function the
    /// loop itself uses rather than on a copy of the numbers.
    #[test]
    fn the_backoff_increases_and_is_capped() {
        let delays: Vec<Duration> = (1..=8).map(backoff_for_attempt).collect();
        for pair in delays.windows(2) {
            assert!(
                pair[1] >= pair[0],
                "the backoff must not decrease: {delays:?}"
            );
        }
        assert!(
            delays[1] > delays[0],
            "the second attempt must wait LONGER than the first, or it is not a backoff"
        );
        assert_eq!(delays[0], BASE_BACKOFF);
        assert_eq!(
            *delays.last().expect("delays"),
            MAX_BACKOFF,
            "an unbounded doubling reaches hours; the cap is the point"
        );
    }

    /// A stub ECS whose first `n` POSTs fail and which then accepts, recording every
    /// request with the instant it arrived.
    struct StubEcs {
        server: nextgcore_sbi::server::SbiServer,
        uri: String,
        seen: Arc<StdMutex<Vec<(String, String, std::time::Instant, serde_json::Value)>>>,
    }

    use std::sync::{Arc, Mutex as StdMutex};

    async fn spawn_stub_ecs(fail_posts: usize, put_status: u16) -> StubEcs {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Arc<StdMutex<Vec<(String, String, std::time::Instant, serde_json::Value)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let posts_failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |req: nextgcore_sbi::message::SbiRequest| {
                let sink = Arc::clone(&sink);
                let posts_failed = Arc::clone(&posts_failed);
                async move {
                    let method = req.header.method.clone();
                    let uri = req.header.uri.clone();
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(serde_json::Value::Null);
                    sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                        method.clone(),
                        uri.clone(),
                        std::time::Instant::now(),
                        body,
                    ));
                    if method == "POST" {
                        let n = posts_failed.load(std::sync::atomic::Ordering::SeqCst);
                        if n < fail_posts {
                            posts_failed.store(n + 1, std::sync::atomic::Ordering::SeqCst);
                            return nextgcore_sbi::message::SbiResponse::with_status(503);
                        }
                        let id = format!("reg-{}", n + 1);
                        return nextgcore_sbi::message::SbiResponse::with_status(201).with_header(
                            "Location",
                            format!("/eecs-eesregistration/v1/registrations/{id}"),
                        );
                    }
                    nextgcore_sbi::message::SbiResponse::with_status(put_status)
                }
            },
        )
        .await;
        StubEcs {
            server,
            uri: format!("http://127.0.0.1:{}", addr.port()),
            seen,
        }
    }

    /// #107 criterion 3: the initial POST is retried with increasing delay rather
    /// than abandoned after one attempt.
    ///
    /// Asserted on the ARRIVAL TIMES at the stub, so it measures the delay the peer
    /// actually experienced rather than the schedule the caller intended.
    #[tokio::test]
    async fn the_initial_post_retries_with_increasing_delay() {
        let ecs = spawn_stub_ecs(2, 204).await;
        let id = register_with_backoff(&ecs.uri, "ees1.example.com", "10.0.0.5", 7814).await;
        let seen = ecs.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        ecs.server.stop().await.expect("stop stub ECS");

        assert_eq!(
            id.as_deref(),
            Some("reg-3"),
            "two failures then an accept must end in a registration, not a give-up"
        );
        let posts: Vec<_> = seen.iter().filter(|(m, ..)| m == "POST").collect();
        assert_eq!(
            posts.len(),
            3,
            "more than one attempt is the whole criterion; got {}",
            posts.len()
        );
        let gap1 = posts[1].2.duration_since(posts[0].2);
        let gap2 = posts[2].2.duration_since(posts[1].2);
        assert!(
            gap1 >= BASE_BACKOFF,
            "the first retry waited {gap1:?}, less than the base backoff"
        );
        assert!(
            gap2 > gap1,
            "the delay must INCREASE between attempts: {gap1:?} then {gap2:?}"
        );
    }

    /// #107 criterion 4: a refresh the ECS answers 404 re-POSTs and adopts a fresh
    /// registrationId, rather than looping on a resource that no longer exists.
    #[tokio::test]
    async fn a_404_refresh_re_registers_and_adopts_the_new_id() {
        let ecs = spawn_stub_ecs(0, 404).await;
        let outcome =
            refresh_once(&ecs.uri, "ees1.example.com", "10.0.0.5", 7814, "stale-id").await;
        let seen = ecs.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        ecs.server.stop().await.expect("stop stub ECS");

        assert_eq!(
            outcome,
            RefreshOutcome::Recreated("reg-1".to_string()),
            "a fresh registrationId must be obtained and adopted"
        );
        assert!(
            seen.iter()
                .any(|(m, u, ..)| m == "PUT"
                    && u == "/eecs-eesregistration/v1/registrations/stale-id"),
            "the PUT is still attempted first: a live registration must not be re-created"
        );
        assert!(
            seen.iter()
                .any(|(m, u, ..)| m == "POST" && u == "/eecs-eesregistration/v1/registrations"),
            "the 404 must produce a re-POST; got {seen:?}"
        );
    }

    /// The other half of criterion 4's interlock: a refresh the ECS ACCEPTS must not
    /// re-POST. Without this, "re-create on failure" could be satisfied by a version
    /// that re-creates every tick, which would mint a new id every 60 seconds and
    /// leave the ECS holding a growing pile of dead registrations.
    #[tokio::test]
    async fn an_accepted_refresh_does_not_re_register() {
        let ecs = spawn_stub_ecs(0, 204).await;
        let outcome = refresh_once(&ecs.uri, "ees1.example.com", "10.0.0.5", 7814, "live-id").await;
        let seen = ecs.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        ecs.server.stop().await.expect("stop stub ECS");

        assert_eq!(outcome, RefreshOutcome::Refreshed);
        assert!(
            !seen.iter().any(|(m, ..)| m == "POST"),
            "an accepted refresh must not re-create anything; got {seen:?}"
        );
    }

    /// #107 criterion 5: `easIds` is populated from the current EAS pool and
    /// `expTime` is set, and a registration made AFTER an EAS registers carries it.
    #[tokio::test]
    async fn the_registration_body_carries_the_current_eas_pool_and_an_expiry() {
        let _g = crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // `fini` then `init`, not `init` alone: `init` does not empty the EAS pool, so
        // a sibling test's leftover registration would make the "serves none" half of
        // this test fail for a reason that has nothing to do with it. That is not
        // hypothetical -- it happened during this PR's revert pass, when a panicking
        // sibling skipped its own cleanup.
        crate::context::ees_context_final();
        crate::context::ees_context_init(64);

        // Before any EAS registers, easIds is absent -- there is nothing to state.
        let empty = build_ees_registration("ees1.example.com", "10.0.0.5", 7814);
        assert!(
            empty.ees_prof.eas_ids.is_none(),
            "an EES serving no EAS states none"
        );
        assert!(
            empty.exp_time.is_some(),
            "expTime must be set, or the ECS can never expire a dead EES"
        );

        // Register an EAS, then rebuild: it must appear.
        let ctx = crate::context::ees_self();
        {
            let guard = ctx.read().expect("ees context");
            guard
                .eas_register(crate::types::EasRegistration {
                    eas_prof: crate::types::EasProfile {
                        eas_id: "eas-107.example.com".to_string(),
                        end_pt: EndPoint {
                            ipv4_addrs: Some(vec!["10.0.0.20".to_string()]),
                            port: Some(8080),
                            ..Default::default()
                        },
                        prov_id: None,
                        eas_type: None,
                        flex_eas_type: None,
                        ac_ids: None,
                        svc_area: None,
                        svc_kpi: None,
                    },
                    exp_time: None,
                    supp_feat: None,
                    registration_id: None,
                })
                .expect("EAS registers");
        }
        let with_eas = build_ees_registration("ees1.example.com", "10.0.0.5", 7814);
        assert!(
            with_eas
                .ees_prof
                .eas_ids
                .as_deref()
                .is_some_and(|ids| ids.contains(&"eas-107.example.com".to_string())),
            "the EAS that registered must appear in the next registration body -- this is what \
             makes the EES selectable as a target"
        );

        // And on the wire, from the refresh path rather than only from the builder.
        let ecs = spawn_stub_ecs(0, 204).await;
        refresh_once(&ecs.uri, "ees1.example.com", "10.0.0.5", 7814, "live-id").await;
        let seen = ecs.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        ecs.server.stop().await.expect("stop stub ECS");
        let put = seen
            .iter()
            .find(|(m, ..)| m == "PUT")
            .expect("a PUT must have been sent");
        assert!(
            put.3["eesProf"]["easIds"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|v| v == "eas-107.example.com")),
            "the REFRESH body carries the pool too, not just the initial POST; body was {:?}",
            put.3
        );
        assert!(
            put.3["expTime"].is_string(),
            "expTime on the wire, body was {:?}",
            put.3
        );

        crate::context::ees_context_final();
    }

    /// The expiry timestamp is a well-formed RFC 3339 UTC instant in the future.
    /// The civil-date conversion is hand-rolled, so it gets its own assertion rather
    /// than being trusted because it compiled.
    #[test]
    fn the_expiry_timestamp_is_rfc3339_and_in_the_future() {
        // Two fixed points, so the conversion is checked against known values rather
        // than against itself.
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day, which is where a civil-date conversion goes wrong if it does.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let exp = expiry_timestamp().expect("timestamp");
        assert!(exp.ends_with('Z') && exp.len() == 20, "got {exp}");
        assert!(
            exp > rfc3339_utc(now),
            "the expiry must be in the future: {exp} vs now {}",
            rfc3339_utc(now)
        );
        assert!(
            exp <= rfc3339_utc(now + REGISTRATION_LIFETIME.as_secs() + 2),
            "and not further out than the stated lifetime: {exp}"
        );
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("http://ecs:8000"),
            Some(("ecs".to_string(), 8000))
        );
        assert_eq!(
            parse_host_port("https://ecs.example.com:443/edge"),
            Some(("ecs.example.com".to_string(), 443))
        );
        assert_eq!(
            parse_host_port("https://ecs.example.com"),
            Some(("ecs.example.com".to_string(), 443))
        );
    }

    #[test]
    fn test_extract_registration_id_from_location() {
        let resp = nextgcore_sbi::message::SbiResponse::with_status(201)
            .with_header("Location", "/eecs-eesregistration/v1/registrations/reg-42");
        assert_eq!(extract_registration_id(&resp), Some("reg-42".to_string()));
    }

    #[test]
    fn test_extract_registration_id_from_body() {
        let resp = nextgcore_sbi::message::SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({"registrationId": "reg-99"}))
            .unwrap();
        assert_eq!(extract_registration_id(&resp), Some("reg-99".to_string()));
    }
}
