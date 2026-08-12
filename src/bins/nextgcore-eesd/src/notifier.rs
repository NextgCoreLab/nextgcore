//! Notification delivery seam (D5 stub → D6 real sender).
//!
//! Several EES service APIs POST a callback to a subscriber's
//! `notificationDestination` when an event fires (ACR events, AC information,
//! EAS-discovery change, ACR-management events). D5 introduces the [`Notifier`]
//! trait as the single hand-off point plus a queue-backed default stub, so the
//! `eees-acrevents` emission path can build spec-exact bodies and enqueue them
//! **without** the outbound-HTTP machinery yet existing.
//!
//! D6 adds the real [`SbiNotifier`]: an mpsc queue drained by a background
//! tokio task that POSTs each notification to its `notificationDestination`
//! over `nextgcore-sbi`'s [`SbiClient`], with bounded retry + backoff that
//! honours `Retry-After` (TS 29.558 §6 / TS 29.122 notification pattern; the
//! subscriber answers 204). It is installed as the process notifier at eesd
//! startup via [`install_sbi_notifier`]; the D5/D7 unit tests keep using the
//! default [`QueueNotifier`] (which records each enqueued notification on an
//! in-memory queue inspected via [`Notifier::drain`]).
//!
//! Delivery is fire-and-forget: [`Notifier::enqueue`] must never block or fail
//! the triggering request (fail-closed applies to *inbound* validation, not
//! *outbound* delivery). Callers MUST collect the `(uri, body)` pairs under any
//! `EesContext` lock and enqueue only after releasing it (the documented
//! NF-context AB-BA rule) — [`SbiNotifier::enqueue`] is a non-blocking
//! `try_send` that never touches an `EesContext` lock, so the hand-off cannot
//! deadlock even if a caller enqueues while holding a context read guard.
//!
//! ## Delivery success vs. the generic SBI retry policy
//!
//! For a callback, *success* is a 204 (200 is accepted leniently with a warn);
//! **any** other status — 4xx/5xx included — is a delivery failure worth
//! retrying, which is a broader retryable set than the generic SBI client's
//! (429/503 only, TS 29.500 §6.5). The notifier therefore owns its own bounded
//! attempt loop over a single-shot [`SbiClient`] rather than delegating to
//! [`nextgcore_sbi::RetryPolicy`], so "exactly N attempts then drop" is
//! observable and the callback semantics are exact.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use nextgcore_sbi::{SbiClient, SbiClientConfig, SbiRequest, SbiResponse, UriScheme};
use tokio::sync::mpsc;

/// One queued outbound notification: the callback URI, the JSON body, and a
/// static `kind` tag naming the spec schema (for logging/metrics).
#[derive(Debug, Clone, PartialEq)]
pub struct QueuedNotification {
    /// Absolute callback URI (`notificationDestination`) to POST to.
    pub uri: String,
    /// The serialized spec notification body (`application/json`).
    pub body: serde_json::Value,
    /// Schema name of `body` (e.g. `"ACRInfoNotification"`), for logs/metrics.
    pub kind: &'static str,
}

/// The delivery seam. D5 ships the queue-backed stub ([`QueueNotifier`]); D6
/// provides an `SbiClient` sender implementing this trait.
pub trait Notifier: Send + Sync {
    /// Hand a built notification off for delivery. Fire-and-forget: never
    /// blocks, never fails the triggering request.
    fn enqueue(&self, item: QueuedNotification);

    /// Stub/test inspection hook: drain (and clear) the queued notifications.
    /// A real (D6) sender keeps nothing queued and returns an empty vec.
    fn drain(&self) -> Vec<QueuedNotification> {
        Vec::new()
    }
}

/// D5 default [`Notifier`]: appends every notification to an in-memory queue
/// instead of performing outbound HTTP. Replaced by the real sender in D6.
#[derive(Default)]
pub struct QueueNotifier {
    queue: RwLock<Vec<QueuedNotification>>,
}

impl Notifier for QueueNotifier {
    fn enqueue(&self, item: QueuedNotification) {
        log::info!(
            "notification queued (D5 stub — delivery lands in D6): kind={} uri={}",
            item.kind,
            item.uri
        );
        if let Ok(mut q) = self.queue.write() {
            q.push(item);
        }
    }

    fn drain(&self) -> Vec<QueuedNotification> {
        self.queue
            .write()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }
}

/// Process-wide notifier slot. Default = the D5 [`QueueNotifier`]; D6 swaps in
/// the real sender via [`set_notifier`]. Mirrors the `auth` JWKS-slot pattern.
static NOTIFIER: OnceLock<RwLock<Arc<dyn Notifier>>> = OnceLock::new();

fn slot() -> &'static RwLock<Arc<dyn Notifier>> {
    NOTIFIER.get_or_init(|| RwLock::new(Arc::new(QueueNotifier::default())))
}

/// The current process-wide notifier (default: the D5 queue stub).
pub fn notifier() -> Arc<dyn Notifier> {
    slot()
        .read()
        .map(|g| g.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// Install a [`Notifier`] implementation (the D6 real sender, or a test
/// double). Idempotent; last writer wins.
pub fn set_notifier(n: Arc<dyn Notifier>) {
    if let Ok(mut g) = slot().write() {
        *g = n;
    }
}

/// Build a [`QueuedNotification`] and hand it to the current notifier.
pub fn enqueue(uri: String, body: serde_json::Value, kind: &'static str) {
    notifier().enqueue(QueuedNotification { uri, body, kind });
}

// ===========================================================================
// D6 — real callback sender (SbiClient + bounded retry/backoff).
// ===========================================================================

/// Tuning for the real [`SbiNotifier`]. Defaults follow the D6 spec: 3 attempts,
/// 1 s base backoff, honour `Retry-After`, 5 s per-attempt request timeout, and
/// a bounded in-memory queue so a slow/absent subscriber cannot grow memory
/// without bound (excess is dropped-with-log, never blocking the caller).
#[derive(Debug, Clone)]
pub struct SbiNotifierConfig {
    /// Total delivery attempts per notification, including the first
    /// (clamped to ≥ 1). Exhausting the budget logs an error and drops.
    pub max_attempts: u32,
    /// Backoff between attempts when the response carries no honoured
    /// `Retry-After`. Zero disables the wait.
    pub base_backoff: Duration,
    /// Honour a `Retry-After` (delta-seconds) header on a failed attempt in
    /// preference to `base_backoff` (RFC 9110 §10.2.3).
    pub honor_retry_after: bool,
    /// Per-attempt request timeout handed to the [`SbiClient`].
    pub request_timeout: Duration,
    /// Bounded queue depth; a full queue drops the newest with a warn.
    pub queue_capacity: usize,
}

impl Default for SbiNotifierConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff: Duration::from_secs(1),
            honor_retry_after: true,
            request_timeout: Duration::from_secs(5),
            queue_capacity: 1024,
        }
    }
}

/// The real (D6) [`Notifier`]: an mpsc sender feeding a background tokio task
/// that POSTs each notification to its `notificationDestination`.
///
/// [`enqueue`](SbiNotifier::enqueue) is a non-blocking `try_send` — it never
/// awaits, never blocks the triggering request, and never touches an
/// `EesContext` lock, so it is safe to call while holding a context guard.
pub struct SbiNotifier {
    tx: mpsc::Sender<QueuedNotification>,
    /// Count of notifications abandoned (retry budget exhausted, unparseable
    /// URI, or queue full). Observable so tests and operators can assert the
    /// fail-open drop path fired rather than hanging.
    dropped: Arc<AtomicU64>,
}

impl SbiNotifier {
    /// Create the sender and spawn its background delivery worker on the
    /// current tokio runtime. MUST be called from within a runtime (eesd's
    /// `#[tokio::main]` provides one).
    pub fn spawn(config: SbiNotifierConfig) -> Self {
        let (tx, mut rx) = mpsc::channel(config.queue_capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = dropped.clone();
        let worker_cfg = config;
        tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                deliver(item, &worker_cfg, &worker_dropped).await;
            }
            log::debug!("EES notifier worker stopped (queue closed)");
        });
        Self { tx, dropped }
    }

    /// Total notifications dropped (delivery exhausted / bad URI / queue full).
    #[cfg(test)]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

impl Notifier for SbiNotifier {
    fn enqueue(&self, item: QueuedNotification) {
        // Fire-and-forget, non-blocking: a full or closed queue drops the
        // newest notification (with a warn + drop-count bump) rather than
        // blocking the triggering request or awaiting here.
        if let Err(e) = self.tx.try_send(item) {
            let (reason, dropped) = match e {
                mpsc::error::TrySendError::Full(it) => ("queue full", it),
                mpsc::error::TrySendError::Closed(it) => ("worker stopped", it),
            };
            log::warn!(
                "EES notifier dropping {} to {} ({reason})",
                dropped.kind,
                dropped.uri
            );
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    // drain() keeps the trait default (empty): the real sender queues nothing
    // for inspection — it delivers.
}

/// Install the real [`SbiNotifier`] as the process notifier (D6). Called once
/// at eesd startup from within the tokio runtime.
pub fn install_sbi_notifier(config: SbiNotifierConfig) {
    log::info!(
        "EES notifier: real callback sender active (max_attempts={}, base_backoff={:?}, honor_retry_after={})",
        config.max_attempts,
        config.base_backoff,
        config.honor_retry_after
    );
    set_notifier(Arc::new(SbiNotifier::spawn(config)));
}

/// Deliver one notification with bounded retry/backoff. A 204 (or a lenient
/// 200) ends the exchange; any other status or a transport error is retried
/// until the attempt budget is spent, after which the notification is dropped
/// (logged + counted). Never panics; never blocks a caller (runs on the
/// background worker).
async fn deliver(item: QueuedNotification, config: &SbiNotifierConfig, dropped: &AtomicU64) {
    let QueuedNotification { uri, body, kind } = item;

    let Some((scheme, host, port, path)) = parse_callback_uri(&uri) else {
        log::error!("EES notifier: unparseable callback URI {uri:?} for {kind}; dropping");
        dropped.fetch_add(1, Ordering::SeqCst);
        return;
    };

    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_scheme(scheme)
            .with_request_timeout(config.request_timeout)
            .with_pool_size(1),
    );
    let body_str = body.to_string();
    let max = config.max_attempts.max(1);

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let request =
            SbiRequest::post(path.clone()).with_body(body_str.clone(), "application/json");
        match client.send_request(request).await {
            Ok(resp) if resp.status == 204 => {
                log::debug!("EES notifier delivered {kind} to {uri} (204, attempt {attempt})");
                return;
            }
            Ok(resp) if resp.status == 200 => {
                log::warn!(
                    "EES notifier: {kind} to {uri} answered 200 (spec expects 204); accepting"
                );
                return;
            }
            Ok(resp) => {
                if attempt >= max {
                    log::error!(
                        "EES notifier: giving up on {kind} to {uri} after {attempt} attempt(s) \
                         (last status {})",
                        resp.status
                    );
                    dropped.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if let Some(d) = retry_delay(config, Some(&resp)) {
                    tokio::time::sleep(d).await;
                }
            }
            Err(e) => {
                if attempt >= max {
                    log::error!(
                        "EES notifier: giving up on {kind} to {uri} after {attempt} attempt(s) \
                         (transport error: {e})"
                    );
                    dropped.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if let Some(d) = retry_delay(config, None) {
                    tokio::time::sleep(d).await;
                }
            }
        }
    }
}

/// Backoff before the next retry: an honoured `Retry-After` (delta-seconds)
/// when present, else the policy base backoff. `None` means "no wait".
fn retry_delay(config: &SbiNotifierConfig, response: Option<&SbiResponse>) -> Option<Duration> {
    if config.honor_retry_after {
        if let Some(after) = response
            .and_then(|r| r.http.get_header("Retry-After"))
            .and_then(|v| parse_retry_after(v))
        {
            return Some(after);
        }
    }
    if config.base_backoff.is_zero() {
        None
    } else {
        Some(config.base_backoff)
    }
}

/// Parse a `Retry-After` value (RFC 9110 §10.2.3), delta-seconds form only.
/// The HTTP-date form yields `None` (caller falls back to base backoff).
fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Split an absolute callback URI into `(scheme, host, port, path)` for the
/// [`SbiClient`]. Defaults the port per scheme (80/443) and the path to `/`.
/// Returns `None` for a relative or non-http(s) URI (dropped fail-open).
fn parse_callback_uri(uri: &str) -> Option<(UriScheme, String, u16, String)> {
    let (scheme, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (UriScheme::Https, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (UriScheme::Http, r)
    } else {
        return None;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
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
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    Some((scheme, host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_notifier_enqueue_then_drain() {
        let n = QueueNotifier::default();
        assert!(n.drain().is_empty());
        n.enqueue(QueuedNotification {
            uri: "http://cb/1".into(),
            body: serde_json::json!({"subId":"s1"}),
            kind: "ACRInfoNotification",
        });
        n.enqueue(QueuedNotification {
            uri: "http://cb/2".into(),
            body: serde_json::json!({"subId":"s2"}),
            kind: "ACRInfoNotification",
        });
        let drained = n.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].uri, "http://cb/1");
        // drain clears the queue.
        assert!(n.drain().is_empty());
    }

    // ---- parse_callback_uri / retry_delay unit tests -----------------------

    #[test]
    fn test_parse_callback_uri() {
        assert_eq!(
            parse_callback_uri("http://127.0.0.1:8080/acr-cb"),
            Some((
                UriScheme::Http,
                "127.0.0.1".to_string(),
                8080,
                "/acr-cb".to_string()
            ))
        );
        // Default ports per scheme when the authority omits a port.
        assert_eq!(
            parse_callback_uri("http://eec.example.com/cb"),
            Some((
                UriScheme::Http,
                "eec.example.com".to_string(),
                80,
                "/cb".to_string()
            ))
        );
        assert_eq!(
            parse_callback_uri("https://eec.example.com/cb?x=1"),
            Some((
                UriScheme::Https,
                "eec.example.com".to_string(),
                443,
                "/cb?x=1".to_string()
            ))
        );
        // No path → "/".
        assert_eq!(
            parse_callback_uri("http://h:1"),
            Some((UriScheme::Http, "h".to_string(), 1, "/".to_string()))
        );
        // Relative / non-http(s) / empty-authority / bad-port → None (dropped).
        assert!(parse_callback_uri("/relative/cb").is_none());
        assert!(parse_callback_uri("ftp://h/cb").is_none());
        assert!(parse_callback_uri("http:///cb").is_none());
        assert!(parse_callback_uri("http://h:notaport/cb").is_none());
    }

    #[test]
    fn test_retry_delay_prefers_retry_after() {
        let cfg = SbiNotifierConfig {
            base_backoff: Duration::from_millis(50),
            honor_retry_after: true,
            ..Default::default()
        };
        // A parseable Retry-After wins over base_backoff.
        let resp = SbiResponse::with_status(503).with_header("Retry-After", "2");
        assert_eq!(retry_delay(&cfg, Some(&resp)), Some(Duration::from_secs(2)));
        // No Retry-After → base_backoff.
        let plain = SbiResponse::with_status(500);
        assert_eq!(
            retry_delay(&cfg, Some(&plain)),
            Some(Duration::from_millis(50))
        );
        // Transport error (no response) → base_backoff.
        assert_eq!(retry_delay(&cfg, None), Some(Duration::from_millis(50)));
        // honor_retry_after=false ignores the header.
        let cfg_off = SbiNotifierConfig {
            honor_retry_after: false,
            ..cfg.clone()
        };
        assert_eq!(
            retry_delay(&cfg_off, Some(&resp)),
            Some(Duration::from_millis(50))
        );
        // Zero base backoff → no wait.
        let cfg_zero = SbiNotifierConfig {
            base_backoff: Duration::ZERO,
            honor_retry_after: false,
            ..cfg
        };
        assert_eq!(retry_delay(&cfg_zero, None), None);
    }

    // ---- SbiNotifier loopback integration ----------------------------------

    /// Response strategy for the loopback receiver: given the 0-based request
    /// index, return `(status, Retry-After?)`.
    type Responder = Arc<dyn Fn(usize) -> (u16, Option<String>) + Send + Sync>;

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    /// Spin a `nextgcore-sbi` `SbiServer` on `127.0.0.1:port` acting as the
    /// subscriber callback receiver. It counts every POST, records the decoded
    /// JSON body, and answers per `responder`.
    async fn start_receiver(
        port: u16,
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        responder: Responder,
    ) -> nextgcore_sbi::SbiServer {
        use std::net::SocketAddr;
        let server = nextgcore_sbi::SbiServer::new(nextgcore_sbi::SbiServerConfig::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
        ));
        let handler = move |req: SbiRequest| {
            let counter = counter.clone();
            let bodies = bodies.clone();
            let responder = responder.clone();
            async move {
                let nth = counter.fetch_add(1, Ordering::SeqCst);
                if let Some(content) = req.http.content.as_deref() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
                        if let Ok(mut b) = bodies.lock() {
                            b.push(v);
                        }
                    }
                }
                let (status, retry_after) = responder(nth);
                let mut resp = SbiResponse::with_status(status);
                if let Some(ra) = retry_after {
                    resp = resp.with_header("Retry-After", ra);
                }
                resp
            }
        };
        server.start(handler).await.expect("receiver starts");
        server
    }

    async fn wait_until<F: Fn() -> bool>(pred: F, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while !pred() {
            if start.elapsed() > timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    fn notif_body() -> serde_json::Value {
        serde_json::json!({"subId":"s1","easId":"eas1.example.com","eventId":"ACR_COMPLETE"})
    }

    /// The happy path: one enqueue → exactly one POST arrives, the body is the
    /// spec JSON we sent, the receiver's 204 ends the exchange, nothing dropped.
    #[tokio::test]
    async fn test_sbi_notifier_delivers_one_post() {
        let port = free_port();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Responder = Arc::new(|_| (204, None));
        let server = start_receiver(port, counter.clone(), bodies.clone(), responder).await;

        let n = SbiNotifier::spawn(SbiNotifierConfig {
            base_backoff: Duration::from_millis(10),
            ..Default::default()
        });
        n.enqueue(QueuedNotification {
            uri: format!("http://127.0.0.1:{port}/acr-cb"),
            body: notif_body(),
            kind: "ACRInfoNotification",
        });

        assert!(
            wait_until(
                || counter.load(Ordering::SeqCst) >= 1,
                Duration::from_secs(5)
            )
            .await,
            "the notification should be POSTed to the subscriber"
        );
        // Settle: assert exactly one POST (no spurious retry on success).
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(n.dropped_count(), 0);
        {
            let b = bodies.lock().unwrap();
            assert_eq!(b.len(), 1);
            assert_eq!(b[0]["subId"], "s1");
            assert_eq!(b[0]["eventId"], "ACR_COMPLETE");
        }
        let _ = server.stop().await;
    }

    /// Retry then succeed: the receiver 500s twice then 204s → exactly 3
    /// attempts observed and eventual success (no drop).
    #[tokio::test]
    async fn test_sbi_notifier_retries_then_succeeds() {
        let port = free_port();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Responder = Arc::new(|n| if n < 2 { (500, None) } else { (204, None) });
        let server = start_receiver(port, counter.clone(), bodies.clone(), responder).await;

        let n = SbiNotifier::spawn(SbiNotifierConfig {
            max_attempts: 3,
            base_backoff: Duration::from_millis(10),
            ..Default::default()
        });
        n.enqueue(QueuedNotification {
            uri: format!("http://127.0.0.1:{port}/acr-cb"),
            body: notif_body(),
            kind: "ACRInfoNotification",
        });

        assert!(
            wait_until(
                || counter.load(Ordering::SeqCst) >= 3,
                Duration::from_secs(5)
            )
            .await,
            "three attempts (two 500s then a 204)"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 3, "exactly 3 attempts");
        assert_eq!(n.dropped_count(), 0, "eventual success ⇒ no drop");
        let _ = server.stop().await;
    }

    /// Exhaust and drop: the receiver always 500s → exactly `max_attempts`
    /// POSTs then a counted drop (no infinite loop, no panic).
    #[tokio::test]
    async fn test_sbi_notifier_exhausts_then_drops() {
        let port = free_port();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Responder = Arc::new(|_| (500, None));
        let server = start_receiver(port, counter.clone(), bodies.clone(), responder).await;

        let n = SbiNotifier::spawn(SbiNotifierConfig {
            max_attempts: 3,
            base_backoff: Duration::from_millis(10),
            ..Default::default()
        });
        n.enqueue(QueuedNotification {
            uri: format!("http://127.0.0.1:{port}/acr-cb"),
            body: notif_body(),
            kind: "ACRInfoNotification",
        });

        assert!(
            wait_until(|| n.dropped_count() >= 1, Duration::from_secs(5)).await,
            "delivery should be abandoned after the attempt budget is spent"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "exactly max_attempts POSTs"
        );
        assert_eq!(n.dropped_count(), 1);
        let _ = server.stop().await;
    }

    /// Retry-After honoured: a 503 + `Retry-After: 1` then 204 → the retry waits
    /// ~1 s (far above the tiny base backoff), proving the header is honoured.
    #[tokio::test]
    async fn test_sbi_notifier_honors_retry_after() {
        let port = free_port();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Responder = Arc::new(|n| {
            if n == 0 {
                (503, Some("1".to_string()))
            } else {
                (204, None)
            }
        });
        let server = start_receiver(port, counter.clone(), bodies.clone(), responder).await;

        let n = SbiNotifier::spawn(SbiNotifierConfig {
            max_attempts: 3,
            base_backoff: Duration::from_millis(20),
            honor_retry_after: true,
            ..Default::default()
        });
        let start = std::time::Instant::now();
        n.enqueue(QueuedNotification {
            uri: format!("http://127.0.0.1:{port}/acr-cb"),
            body: notif_body(),
            kind: "ACRInfoNotification",
        });

        assert!(
            wait_until(
                || counter.load(Ordering::SeqCst) >= 2,
                Duration::from_secs(6)
            )
            .await,
            "second attempt (after the Retry-After wait) succeeds"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900),
            "Retry-After:1 must delay the retry ~1s (got {elapsed:?}); base backoff was 20ms"
        );
        assert_eq!(n.dropped_count(), 0);
        let _ = server.stop().await;
    }

    /// Lock-safety + discovery-path integration: build an `EesContext` with a
    /// matching discovery subscription, install the real sender, and fire
    /// `notify_discovery_subscribers` **while holding a context read guard**
    /// (the `main.rs` call pattern). It must not deadlock (bounded by a
    /// timeout), and the delivered body must be a spec `EasDiscoveryNotification`.
    // The std `GLOBAL_STATE_TEST_LOCK` is intentionally held across awaits to
    // serialize the process-global notifier swap with the other tests; it is a
    // test-only mutex guarding shared state, not a runtime lock.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_notify_discovery_delivers_under_context_lock() {
        use crate::context::EesContext;
        use crate::types::{
            EasDiscoveryNotification, EasDiscoverySubscription, EasProfile, EndPoint,
            EAS_AVAILABILITY_CHANGE,
        };

        // Serialize with the other tests that swap the process-global notifier.
        let _g = crate::auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let port = free_port();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: Responder = Arc::new(|_| (204, None));
        let server = start_receiver(port, counter.clone(), bodies.clone(), responder).await;

        // Install the real sender as THE process notifier for this test.
        install_sbi_notifier(SbiNotifierConfig {
            base_backoff: Duration::from_millis(10),
            ..Default::default()
        });

        // A local context with a filter-less discovery subscription (matches any EAS).
        let mut ctx = EesContext::new();
        ctx.init(64);
        ctx.disc_sub_create(EasDiscoverySubscription {
            notification_uri: format!("http://127.0.0.1:{port}/disc-cb"),
            ..Default::default()
        })
        .expect("subscription created");
        let ctx_lock = std::sync::RwLock::new(ctx);

        let prof = EasProfile {
            eas_id: "eas-lock.example.com".into(),
            end_pt: EndPoint {
                fqdn: Some("eas-lock.edge.example.com".into()),
                ..Default::default()
            },
            prov_id: None,
            eas_type: Some("VIDEO".into()),
            flex_eas_type: None,
            ac_ids: None,
            svc_area: None,
            svc_kpi: None,
        };

        // The main.rs pattern: hold a read guard on the context and notify.
        // Bounded by a timeout: a deadlock (or a blocking enqueue) trips it.
        let matched = tokio::time::timeout(Duration::from_secs(3), async {
            let guard = ctx_lock.read().unwrap();
            guard.notify_discovery_subscribers(&prof)
        })
        .await
        .expect("notify while holding a context read lock must not deadlock");
        assert_eq!(matched, 1, "the filter-less subscription matches");

        assert!(
            wait_until(
                || counter.load(Ordering::SeqCst) >= 1,
                Duration::from_secs(5)
            )
            .await,
            "the discovery notification is delivered by the real sender"
        );
        let delivered = bodies.lock().unwrap()[0].clone();
        let notif: EasDiscoveryNotification =
            serde_json::from_value(delivered).expect("spec EasDiscoveryNotification");
        assert!(!notif.sub_id.is_empty());
        assert_eq!(notif.event_type, EAS_AVAILABILITY_CHANGE);
        assert_eq!(notif.discovered_eas.len(), 1);
        assert_eq!(notif.discovered_eas[0].eas.eas_id, "eas-lock.example.com");

        // Restore the default notifier for the rest of the suite.
        set_notifier(Arc::new(QueueNotifier::default()));
        let _ = server.stop().await;
    }
}
