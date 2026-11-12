//! #1458: the PCF's UDR policy-data subscription (TS 29.519 §5.2.10, §5.2.11),
//! created and then kept alive by one maintainer task.
//!
//! Before #1458 the PCF subscribed once, at startup, and gave up on any failure. On
//! the devtest1 EKS run for nextgsim #477 the UDR registered with the NRF 367 ms
//! after the PCF's discovery, and the PCF lost that race in 4 of 6 deploys. When it
//! loses, no policy-data change reaches a live SM policy association (#299).
//!
//! # What the maintainer does
//!
//! - **Until it succeeds**, it discovers a UDR and POSTs the `PolicyDataSubscription`,
//!   retrying with a backoff that doubles from [`BACKOFF_INITIAL`] to [`BACKOFF_MAX`]
//!   and stays there. A UDR that is late, or an NRF that is late, is picked up at the
//!   next attempt.
//! - **Expiry** (TS 29.519 §5.4.2.10 `expiry`): when the UDR confirms an expiry time,
//!   the subscription is renewed with a PUT on the individual resource (§5.2.11.3.1)
//!   before it lapses. See [`renew_at`]. A 404 on that PUT means the UDR no longer
//!   holds it, and a new one is created.
//! - **UDR re-registration**: every [`audit_interval`] it checks two things. First, it
//!   re-discovers the UDRs. While the subscription's UDR is listed anywhere in the
//!   result it is kept (the NRF's order is not stable); when the NRF lists other UDRs
//!   and not this one, the old subscription is DELETEd there, best effort, and a new
//!   one is made. Second, it GETs the individual subscription
//!   (§5.2.11.3.3): a 404 means the UDR restarted and lost it, as udrd does without a
//!   state file, so it subscribes again.
//!   A failure to reach the NRF or the UDR leaves the subscription in place, because a
//!   transient error is not evidence that it is gone.
//!
//! # Off every request path
//!
//! The maintainer is its own task, spawned after the SBI server is listening. Each
//! request is bounded at 3 s: the UDR ones by `client_for`, the NRF discovery by
//! [`DISCOVERY_TIMEOUT`]. Startup does not wait for it, it checks the shutdown flags
//! at least every [`STOP_POLL`], and it starts no POST once shutdown is requested.

use std::sync::Mutex;
use std::time::Duration;

use nextgcore_sbi::datetime::{now_epoch_secs, rfc3339_to_epoch};
use nextgcore_sbi::types::NfType;

use crate::sbi_path::{
    client_for, pcf_discover_endpoints, policy_data_notify_uri, policy_data_subscription_body,
    uri_path_only, DiscoveredEndpoint,
};

/// The first pause after a failed subscribe attempt.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// The longest pause between two subscribe attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The default pause between two audits of a held subscription.
pub const AUDIT_DEFAULT: Duration = Duration::from_secs(30);

/// Overrides [`AUDIT_DEFAULT`], in whole seconds (at least 1).
pub const AUDIT_ENV: &str = "PCF_POLICY_DATA_AUDIT_SECS";

/// How often a waiting maintainer checks the shutdown flags.
pub const STOP_POLL: Duration = Duration::from_millis(100);

/// The bound on one UDR discovery at the NRF (#1458 review): the shared NRF client
/// waits 30 s, which would hold an audit past a due renewal, and a shutdown past
/// its join.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

/// The most a renewal is moved ahead of the confirmed expiry, in seconds.
const RENEW_LEAD_MAX_SECS: u64 = 60;

/// A subscription the UDR has confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// The UDR the subscription was created at. Renewal, audit and DELETE go here,
    /// never to whichever UDR discovery happens to return at that moment.
    pub udr: DiscoveredEndpoint,
    /// The `Location` the UDR answered, or `None` if it gave none. Without a
    /// Location the subscription cannot be renewed or audited, only replaced when
    /// the UDR changes.
    pub resource: Option<String>,
    /// The confirmed expiry (epoch seconds), `None` when unlimited.
    pub expiry: Option<u64>,
    /// When it was confirmed or last renewed (epoch seconds).
    pub granted_at: u64,
}

/// The subscription currently held, for shutdown and for tests.
static CURRENT: Mutex<Option<Subscription>> = Mutex::new(None);

/// The subscription this PCF holds now, if any.
pub fn current() -> Option<Subscription> {
    CURRENT.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

fn set_current(sub: Option<Subscription>) {
    *CURRENT.lock().unwrap_or_else(|p| p.into_inner()) = sub;
}

/// The pause between two audits: [`AUDIT_ENV`] when it parses to at least 1 s,
/// otherwise [`AUDIT_DEFAULT`].
pub fn audit_interval() -> Duration {
    std::env::var(AUDIT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s >= 1)
        .map(Duration::from_secs)
        .unwrap_or(AUDIT_DEFAULT)
}

/// The pause after `prev`: doubled, never above [`BACKOFF_MAX`].
pub fn next_backoff(prev: Duration) -> Duration {
    (prev * 2).min(BACKOFF_MAX)
}

/// When a subscription confirmed at `granted_at` and expiring at `expiry` is
/// renewed: half its lifetime early, but never more than 60 s early, so a long
/// lifetime is not renewed long before it needs to be, and a short one still has
/// time for a retry before it lapses.
pub fn renew_at(granted_at: u64, expiry: u64) -> u64 {
    let lifetime = expiry.saturating_sub(granted_at);
    expiry.saturating_sub((lifetime / 2).min(RENEW_LEAD_MAX_SECS))
}

/// The `expiry` a UDR confirmed in a `PolicyDataSubscription` body, as epoch seconds.
pub fn confirmed_expiry(body: Option<&str>) -> Option<u64> {
    let json: serde_json::Value = serde_json::from_str(body?).ok()?;
    rfc3339_to_epoch(json.get("expiry")?.as_str()?)
}

/// The outcome of one subscribe attempt.
#[derive(Debug)]
pub enum Attempt {
    /// The UDR answered 201.
    Subscribed(Subscription),
    /// Nothing to subscribe to yet: no UDR registered, no NRF configured, or no
    /// self identity to put in the notification URI.
    NotYet(&'static str),
    /// Discovery or the POST failed.
    Failed(String),
}

/// Discover a UDR and POST the policy-data subscription (TS 29.519 §5.2.10.3.1).
///
/// `stopping` is checked between the discovery and the POST, so a shutdown that
/// arrives during a slow discovery never creates a subscription at the UDR that the
/// PCF would then have no time to record and delete.
pub async fn subscribe_once(stopping: &impl Fn() -> bool) -> Attempt {
    let Some(notification_uri) = policy_data_notify_uri() else {
        return Attempt::NotYet("no advertised SBI address for the notification URI");
    };
    let udr = match pcf_discover_endpoints("UDR", "nudr-dr", DISCOVERY_TIMEOUT).await {
        Ok(found) => match found.into_iter().next() {
            Some(ep) => ep,
            None => return Attempt::NotYet("no UDR discoverable"),
        },
        Err(e) => return Attempt::Failed(format!("UDR discovery failed: {e}")),
    };
    if stopping() {
        return Attempt::NotYet("shutting down");
    }
    let body = policy_data_subscription_body(&notification_uri);
    let resp = match client_for(&udr, NfType::Udr)
        .post_json("/nudr-dr/v2/policy-data/subs-to-notify", &body)
        .await
    {
        Ok(resp) => resp,
        Err(e) => return Attempt::Failed(format!("POST subs-to-notify failed: {e}")),
    };
    if resp.status != 201 {
        return Attempt::Failed(format!("the UDR answered {} to the subscribe", resp.status));
    }
    let resource = resp
        .http
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone());
    let expiry = confirmed_expiry(resp.http.content.as_deref());
    log::info!(
        "Subscribed to UDR policy-data changes; notifications arrive at {} (subscription {}, \
         expiry {})",
        nextgcore_sbi::log_redact::redact_last_segment(&notification_uri),
        resource.as_deref().unwrap_or("<no Location>"),
        expiry.map_or("none".to_string(), |e| e.to_string()),
    );
    Attempt::Subscribed(Subscription {
        udr,
        resource,
        expiry,
        granted_at: now_epoch_secs(),
    })
}

/// What a renewal or an audit found.
#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    /// Still held; the expiry the UDR now confirms (renewal) or the one we had (audit).
    Held(Option<u64>),
    /// Gone, or held by a UDR that is no longer the registered one: subscribe again.
    Lost(String),
    /// The check itself failed; keep the subscription and look again later.
    Unknown(String),
}

/// Renew `sub` with a PUT on its individual resource (TS 29.519 §5.2.11.3.1).
pub async fn renew(sub: &Subscription) -> Check {
    let Some(resource) = sub.resource.as_deref() else {
        return Check::Held(sub.expiry);
    };
    let Some(notification_uri) = policy_data_notify_uri() else {
        return Check::Unknown("no advertised SBI address".into());
    };
    let body = policy_data_subscription_body(&notification_uri);
    match client_for(&sub.udr, NfType::Udr)
        .put_json(&uri_path_only(resource), &body)
        .await
    {
        Ok(resp) if resp.status == 200 => {
            Check::Held(confirmed_expiry(resp.http.content.as_deref()))
        }
        // 204 confirms the update and nothing else (no body, so no expiry). The
        // lifetime the UDR confirmed before still applies, from now; reading it as
        // "unlimited" would stop the renewals and let the subscription lapse.
        Ok(resp) if resp.status == 204 => Check::Held(
            sub.expiry
                .map(|expiry| now_epoch_secs() + expiry.saturating_sub(sub.granted_at)),
        ),
        Ok(resp) if resp.status == 404 => Check::Lost("the UDR no longer holds it".into()),
        Ok(resp) => Check::Unknown(format!("the UDR answered {} to the renewal", resp.status)),
        Err(e) => Check::Unknown(format!("renewal failed: {e}")),
    }
}

/// Check that `sub` is still the live one: its UDR is still registered, and still
/// holds it (TS 29.519 §5.2.11.3.3).
///
/// "Still registered" means *listed anywhere* in the discovery result, not listed
/// first: the NRF's order is not stable, and treating a reordering as a switch made
/// the PCF subscribe again at every audit (#1458 review). Only when the NRF lists
/// UDRs and this one is not among them has the UDR been replaced; the old
/// subscription is then deleted, best effort, before a new one is made.
pub async fn audit(sub: &Subscription) -> Check {
    match pcf_discover_endpoints("UDR", "nudr-dr", DISCOVERY_TIMEOUT).await {
        Ok(found) if !found.is_empty() && !found.contains(&sub.udr) => {
            delete_at(sub).await;
            return Check::Lost(format!(
                "UDR {}:{} is no longer registered ({} other UDR(s) are)",
                sub.udr.host,
                sub.udr.port,
                found.len()
            ));
        }
        Ok(_) => {}
        Err(e) => return Check::Unknown(format!("UDR discovery failed: {e}")),
    }
    let Some(resource) = sub.resource.as_deref() else {
        return Check::Held(sub.expiry);
    };
    match client_for(&sub.udr, NfType::Udr)
        .get(&uri_path_only(resource))
        .await
    {
        Ok(resp) if resp.status == 200 => Check::Held(sub.expiry),
        Ok(resp) if resp.status == 404 => Check::Lost("the UDR no longer holds it".into()),
        Ok(resp) => Check::Unknown(format!("the UDR answered {} to the audit", resp.status)),
        Err(e) => Check::Unknown(format!("audit failed: {e}")),
    }
}

/// Sleep for `pause`, returning `true` early once `stopping()` holds.
async fn wait_or_stop(pause: Duration, stopping: &impl Fn() -> bool) -> bool {
    let until = tokio::time::Instant::now() + pause;
    loop {
        if stopping() {
            return true;
        }
        let now = tokio::time::Instant::now();
        if now >= until {
            return false;
        }
        tokio::time::sleep((until - now).min(STOP_POLL)).await;
    }
}

/// The pause before the next look at a held subscription: the audit interval, or
/// less when the renewal is due sooner.
fn pause_for(sub: &Subscription, audit: Duration) -> Duration {
    match sub.expiry {
        Some(expiry) => {
            let due = renew_at(sub.granted_at, expiry);
            let now = now_epoch_secs();
            audit.min(Duration::from_secs(due.saturating_sub(now)))
        }
        None => audit,
    }
}

/// Log a failed subscribe attempt and wait out the backoff. Loud once, then quiet:
/// a UDR that takes minutes to appear would otherwise fill the log. `true` when
/// shutdown was requested during the wait.
async fn retry_after_failure(
    why: &str,
    failures: u32,
    backoff: &mut Duration,
    stopping: &impl Fn() -> bool,
) -> bool {
    if failures == 1 {
        log::warn!(
            "UDR policy-data subscription not created ({why}); retrying with backoff up to \
             {}s. Until it is, an operator's policy-data edit reaches no live SM policy \
             association (#299).",
            BACKOFF_MAX.as_secs()
        );
    } else {
        log::debug!("UDR policy-data subscribe attempt {failures}: {why}");
    }
    let stop = wait_or_stop(*backoff, stopping).await;
    *backoff = next_backoff(*backoff);
    stop
}

/// Subscribe, then keep the subscription alive, until `stopping()` holds.
pub async fn maintain(stopping: impl Fn() -> bool) {
    let audit_every = audit_interval();
    let mut backoff = BACKOFF_INITIAL;
    let mut failures: u32 = 0;
    loop {
        if stopping() {
            return;
        }
        let Some(mut sub) = current() else {
            let stop = match subscribe_once(&stopping).await {
                Attempt::Subscribed(sub) => {
                    if failures > 0 {
                        log::info!(
                            "UDR policy-data subscription created after {failures} failed \
                             attempt(s)"
                        );
                    }
                    failures = 0;
                    backoff = BACKOFF_INITIAL;
                    let pause = pause_for(&sub, audit_every);
                    set_current(Some(sub));
                    wait_or_stop(pause, &stopping).await
                }
                Attempt::NotYet(why) => {
                    failures += 1;
                    retry_after_failure(why, failures, &mut backoff, &stopping).await
                }
                Attempt::Failed(why) => {
                    failures += 1;
                    retry_after_failure(&why, failures, &mut backoff, &stopping).await
                }
            };
            if stop {
                return;
            }
            continue;
        };

        let now = now_epoch_secs();
        let renewing = sub
            .expiry
            .is_some_and(|expiry| now >= renew_at(sub.granted_at, expiry));
        let check = if renewing {
            renew(&sub).await
        } else {
            audit(&sub).await
        };
        let pause = match check {
            Check::Held(expiry) => {
                if renewing {
                    log::debug!("UDR policy-data subscription renewed (expiry {expiry:?})");
                    sub.expiry = expiry;
                    sub.granted_at = now_epoch_secs();
                    set_current(Some(sub.clone()));
                }
                backoff = BACKOFF_INITIAL;
                pause_for(&sub, audit_every)
            }
            Check::Lost(why) => {
                log::warn!("UDR policy-data subscription lost ({why}); subscribing again");
                set_current(None);
                continue;
            }
            Check::Unknown(why) => {
                // Past its expiry with no confirmed renewal, the subscription is gone
                // whatever the reason the renewal failed.
                if sub.expiry.is_some_and(|expiry| now_epoch_secs() >= expiry) {
                    log::warn!("UDR policy-data subscription expired unrenewed ({why})");
                    set_current(None);
                    continue;
                }
                log::debug!("UDR policy-data subscription check inconclusive: {why}");
                // The backoff, not the renewal time: a renewal that is already due
                // would otherwise be retried in a tight loop.
                let pause = backoff.min(audit_every);
                backoff = next_backoff(backoff);
                pause
            }
        };
        if wait_or_stop(pause, &stopping).await {
            return;
        }
    }
}

/// Spawn [`maintain`] on the current runtime.
pub fn spawn(stopping: impl Fn() -> bool + Send + Sync + 'static) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { maintain(stopping).await })
}

/// Delete the held subscription at the UDR it was made at (#299), at shutdown.
pub async fn unsubscribe() {
    let Some(sub) = current() else {
        return;
    };
    set_current(None);
    delete_at(&sub).await;
}

/// DELETE `sub` at its own UDR (TS 29.519 §5.2.11.3.2), bounded by `client_for`.
///
/// Best effort and logged: a UDR that keeps the subscription only logs a delivery
/// failure per notification, so failing loudly here would be noise, but staying
/// silent would hide a leak that outlives the process.
async fn delete_at(sub: &Subscription) {
    let Some(resource) = sub.resource.as_deref() else {
        log::warn!("Policy-data subscription has no Location: it cannot be deleted and leaks");
        return;
    };
    let path = uri_path_only(resource);
    match client_for(&sub.udr, NfType::Udr).delete(&path).await {
        Ok(resp) if (200..300).contains(&resp.status) => {
            log::info!("Policy-data subscription {resource} deleted");
        }
        Ok(resp) => log::warn!(
            "UDR answered {} to DELETE {path}: the policy-data subscription may linger",
            resp.status
        ),
        Err(e) => log::warn!("DELETE {path} failed: {e}; the policy-data subscription may linger"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_and_stops_at_its_bound() {
        let mut b = BACKOFF_INITIAL;
        let mut seen = vec![b.as_secs()];
        for _ in 0..8 {
            b = next_backoff(b);
            seen.push(b.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30, 30, 30]);
    }

    #[test]
    fn a_renewal_lands_before_the_expiry_with_room_for_a_retry() {
        // Short lifetime: half of it early.
        assert_eq!(renew_at(1000, 1004), 1002);
        // Long lifetime: at most a minute early.
        assert_eq!(renew_at(1000, 1000 + 86_400), 1000 + 86_400 - 60);
        // Already past: due now.
        assert_eq!(renew_at(1000, 900), 900);
    }

    #[test]
    fn the_confirmed_expiry_is_read_from_the_body() {
        assert_eq!(
            confirmed_expiry(Some(r#"{"expiry":"1970-01-01T00:16:40Z"}"#)),
            Some(1000)
        );
        assert_eq!(confirmed_expiry(Some(r#"{"notificationUri":"x"}"#)), None);
        assert_eq!(confirmed_expiry(None), None);
    }
}
