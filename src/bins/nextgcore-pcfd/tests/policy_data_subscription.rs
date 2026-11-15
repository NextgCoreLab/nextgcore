//! #1458: the real pcfd binary gets its UDR policy-data subscription even when the
//! UDR registers after the PCF looks, and keeps it: re-created when the UDR loses it
//! or is replaced, and renewed before a confirmed expiry (TS 29.519 §5.2.10,
//! §5.2.11, §5.4.2.10).
//!
//! The NRF and the UDR are in-process stubs on loopback listeners. The NRF answers
//! the PCF's registration, heartbeat and UDR discovery, listing whichever UDRs the
//! test has "registered"; each UDR stub serves `policy-data/subs-to-notify` as udrd
//! does (POST, GET, PUT, DELETE on the individual resource).
//!
//! REVERT-VERIFIED:
//! - with `app::run` making one `policy_data_sub::subscribe_once()` call instead of
//!   spawning the maintainer, every test but `a_sigterm_deletes_the_subscription`
//!   fails (the late, lost, replaced and expiry cases are the point; the no-UDR
//!   SIGTERM test fails only because one attempt never reaches three discoveries);
//! - with `renew` never taken (always the audit), the expiry test fails;
//! - with the stop check removed from `wait_or_stop`,
//!   `a_sigterm_while_no_udr_is_registered_exits_promptly` fails.
//! - review round 1: without the DELETE on a switch, the replacement test fails;
//!   comparing against the first listed UDR instead of any, the reordered-result
//!   test fails; with a 30 s discovery bound, the hung-NRF test fails; with a 204
//!   renewal read as "unlimited", the 204 test fails; without the stop check between
//!   discovery and POST, the SIGTERM-during-discovery test fails.
//! - #1497: with `spawn_pcfd_with` taking no new port when pcfd loses its SBI bind,
//!   the taken-port test fails ("pcfd exited at startup"); with no wait for the
//!   listener at all (the spawn as it was), it fails after 30 s with "the
//!   subscription within 30s", the failure #1497 reported.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::SbiServer;

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Serve `handler` on a loopback listener. The handler answers a response and how
/// long to hold it before sending (zero for most).
fn serve(
    handler: impl Fn(SbiRequest) -> (Duration, SbiResponse) + Send + Sync + 'static,
) -> impl std::future::Future<Output = (SbiServer, SocketAddr)> {
    let handler = Arc::new(handler);
    async move {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let handler = handler.clone();
                async move {
                    let (hold, resp) = handler(req);
                    if !hold.is_zero() {
                        tokio::time::sleep(hold).await;
                    }
                    resp
                }
            })
            .await
            .expect("stub server");
        (server, addr)
    }
}

/// What a stub UDR has seen, and how it answers.
#[derive(Default)]
struct UdrState {
    posts: usize,
    puts: Vec<Instant>,
    gets: usize,
    deletes: usize,
    held: HashSet<String>,
    next_id: u32,
    /// Confirm this many seconds of lifetime on every POST and PUT.
    expiry_secs: Option<u64>,
    /// Answer a renewal PUT 204 with no body, so it confirms no expiry.
    put_204: bool,
    /// The latest expiry confirmed (epoch seconds), and when it was confirmed.
    confirmed: Option<(u64, Instant)>,
}

struct Udr {
    state: Arc<Mutex<UdrState>>,
    port: u16,
    server: SbiServer,
}

impl Udr {
    async fn start(expiry_secs: Option<u64>) -> Udr {
        let state = Arc::new(Mutex::new(UdrState {
            expiry_secs,
            ..Default::default()
        }));
        let s = state.clone();
        let (server, addr) = serve(move |req| (Duration::ZERO, udr_answer(&s, &req))).await;
        Udr {
            state,
            port: addr.port(),
            server,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut UdrState) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }
}

fn udr_answer(state: &Mutex<UdrState>, req: &SbiRequest) -> SbiResponse {
    const BASE: &str = "/nudr-dr/v2/policy-data/subs-to-notify";
    let path = req.header.uri.split('?').next().unwrap_or("").to_string();
    let mut st = state.lock().unwrap();
    let body = |st: &mut UdrState| {
        let mut b: serde_json::Value = req
            .http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();
        if let Some(secs) = st.expiry_secs {
            let at = nextgcore_sbi::datetime::now_epoch_secs() + secs;
            b["expiry"] = nextgcore_sbi::datetime::epoch_to_rfc3339(at).into();
            st.confirmed = Some((at, Instant::now()));
        }
        b.to_string()
    };
    match (req.header.method.as_str(), path.as_str()) {
        ("POST", BASE) => {
            st.posts += 1;
            st.next_id += 1;
            let id = st.next_id.to_string();
            st.held.insert(id.clone());
            let b = body(&mut st);
            SbiResponse::with_status(201)
                .with_header("Location", format!("{BASE}/{id}"))
                .with_body(b, "application/json")
        }
        (method, p) if p.starts_with(&format!("{BASE}/")) => {
            let id = p[BASE.len() + 1..].to_string();
            let held = st.held.contains(&id);
            match method {
                "GET" => {
                    st.gets += 1;
                    SbiResponse::with_status(if held { 200 } else { 404 })
                }
                "PUT" => {
                    st.puts.push(Instant::now());
                    if held && st.put_204 {
                        SbiResponse::with_status(204)
                    } else if held {
                        let b = body(&mut st);
                        SbiResponse::with_status(200).with_body(b, "application/json")
                    } else {
                        SbiResponse::with_status(404)
                    }
                }
                "DELETE" => {
                    st.deletes += 1;
                    st.held.remove(&id);
                    SbiResponse::with_status(if held { 204 } else { 404 })
                }
                _ => SbiResponse::with_status(405),
            }
        }
        _ => SbiResponse::with_status(404),
    }
}

/// A stub NRF: accepts the PCF's registration and heartbeat, and lists the UDRs in
/// `udrs` (ports on 127.0.0.1) for discovery.
struct Nrf {
    udrs: Arc<Mutex<Vec<u16>>>,
    udr_discoveries: Arc<Mutex<usize>>,
    /// Rotate the UDR list by one on every discovery: TS 29.510 gives a
    /// SearchResult no order, and nrfd's comes from a HashMap.
    rotate: Arc<Mutex<bool>>,
    /// Hold every UDR discovery answer this long.
    discovery_hold: Arc<Mutex<Duration>>,
    port: u16,
    _server: SbiServer,
}

impl Nrf {
    async fn start() -> Nrf {
        let udrs: Arc<Mutex<Vec<u16>>> = Arc::default();
        let udr_discoveries: Arc<Mutex<usize>> = Arc::default();
        let rotate: Arc<Mutex<bool>> = Arc::default();
        let discovery_hold: Arc<Mutex<Duration>> = Arc::default();
        let (u, d, r, h) = (
            udrs.clone(),
            udr_discoveries.clone(),
            rotate.clone(),
            discovery_hold.clone(),
        );
        let (server, addr) = serve(move |req| {
            let uri = req.header.uri.clone();
            let resp = match req.header.method.as_str() {
                "PUT" if uri.starts_with("/nnrf-nfm/v1/nf-instances/") => {
                    SbiResponse::with_status(201).with_body(
                        req.http.content.clone().unwrap_or_else(|| "{}".into()),
                        "application/json",
                    )
                }
                "PATCH" | "DELETE" => SbiResponse::with_status(204),
                "GET" if uri.starts_with("/nnrf-disc/") => {
                    // The query may arrive in the URI or parsed into `params`.
                    let wants_udr = uri.contains("target-nf-type=UDR")
                        || req.http.params.get("target-nf-type").map(String::as_str) == Some("UDR");
                    if !wants_udr {
                        return (
                            Duration::ZERO,
                            SbiResponse::with_status(200)
                                .with_body(r#"{"nfInstances":[]}"#, "application/json"),
                        );
                    }
                    let n = {
                        let mut d = d.lock().unwrap();
                        *d += 1;
                        *d
                    };
                    let mut list = u.lock().unwrap().clone();
                    if *r.lock().unwrap() && !list.is_empty() {
                        let k = n % list.len();
                        list.rotate_left(k);
                    }
                    let instances: Vec<serde_json::Value> =
                        list.iter().map(|p| udr_profile(*p)).collect();
                    return (
                        *h.lock().unwrap(),
                        SbiResponse::with_status(200).with_body(
                            serde_json::json!({ "nfInstances": instances }).to_string(),
                            "application/json",
                        ),
                    );
                }
                _ => SbiResponse::with_status(404),
            };
            (Duration::ZERO, resp)
        })
        .await;
        Nrf {
            udrs,
            udr_discoveries,
            rotate,
            discovery_hold,
            port: addr.port(),
            _server: server,
        }
    }

    fn register_only(&self, udr_port: u16) {
        *self.udrs.lock().unwrap() = vec![udr_port];
    }

    fn register_rotating(&self, udr_ports: &[u16]) {
        *self.udrs.lock().unwrap() = udr_ports.to_vec();
        *self.rotate.lock().unwrap() = true;
    }

    fn hold_discovery(&self, hold: Duration) {
        *self.discovery_hold.lock().unwrap() = hold;
    }

    fn udr_discoveries(&self) -> usize {
        *self.udr_discoveries.lock().unwrap()
    }
}

fn udr_profile(port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": format!("00000000-0000-0000-0000-0000000{port:05}"),
        "nfType": "UDR",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": ["127.0.0.1"],
        "nfServices": [{
            "serviceInstanceId": "nudr-dr",
            "serviceName": "nudr-dr",
            "versions": [{ "apiVersionInUri": "v2", "apiFullVersion": "2.3.0" }],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }],
        }],
    })
}

/// A per-test scratch directory, removed on drop. It holds the config and pcfd's
/// stderr, which is printed when the test fails, so a pcfd that exited or never got
/// as far as subscribing leaves its reason in the test output (#1497).
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn log(&self) -> std::path::PathBuf {
        self.0.join("pcfd.log")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "--- pcfd stderr ---\n{}",
                std::fs::read_to_string(self.log()).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_file(self.0.join("pcf.yaml"));
        let _ = std::fs::remove_file(self.log());
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// What pcfd logs once its SBI listener is bound (`app::run`).
const SBI_LISTENING: &str = "SBI HTTP/2 server listening on";

/// The most SBI ports one spawn tries before giving up.
const SPAWN_ATTEMPTS: usize = 5;

/// Spawn pcfd and return once its SBI listener is bound.
async fn spawn_pcfd(name: &str, nrf: &Nrf, audit_secs: Option<u64>) -> (Killed, Scratch) {
    spawn_pcfd_with(name, nrf, audit_secs, Spawn::default()).await
}

/// How [`spawn_pcfd_with`] starts pcfd; the defaults are what every test but the
/// harness's own wants.
struct Spawn {
    /// The SBI port tried first (then fresh ones after a lost bind).
    first_port: u16,
    /// `pcf.sbi.server[0].address`.
    address: &'static str,
    /// A pause between seeing whether pcfd exited and reading its log, to widen
    /// the window #1520's review found (the harness's own tests only).
    pause_after_exit_check: Duration,
}

impl Default for Spawn {
    fn default() -> Self {
        Spawn {
            first_port: nextgcore_sbi::test_support::free_port(),
            address: "127.0.0.1",
            pause_after_exit_check: Duration::ZERO,
        }
    }
}

/// [`spawn_pcfd`], started as `how` says.
///
/// #1497: `free_port()` probes a port and releases it, and only this process's own
/// `free_port()` and `bound_listener()` calls are kept off it. Anything else can take
/// it before pcfd binds: a sibling test's pcfd connecting out to its stub NRF or UDR
/// is handed an ephemeral source port from the same range. pcfd then fails to bind,
/// exits, and the test waited 30 s for a subscription from a process that was gone.
/// So wait for the listener: on a lost bind, spawn again on another port; on any
/// other exit, fail now with pcfd's stderr.
///
/// #1520 review: whether pcfd exited is asked BEFORE its log is read, and an exit
/// is classified from that later read. Read first, a pcfd that printed the bind
/// error and exited in between was classified from a log without the error line,
/// so a lost bind failed the test instead of being retried. Once the process has
/// exited, its stderr is complete.
async fn spawn_pcfd_with(
    name: &str,
    nrf: &Nrf,
    audit_secs: Option<u64>,
    how: Spawn,
) -> (Killed, Scratch) {
    let dir =
        Scratch(std::env::temp_dir().join(format!("pcfd-1458-{name}-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let config = dir.0.join("pcf.yaml");
    let mut sbi_port = how.first_port;
    for _ in 0..SPAWN_ATTEMPTS {
        std::fs::write(
            &config,
            format!(
                "pcf:\n  sbi:\n    server:\n      - address: {}\n        port: {sbi_port}\n    \
                 client:\n      nrf:\n        - uri: http://127.0.0.1:{}\n",
                how.address, nrf.port
            ),
        )
        .unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"));
        cmd.arg("-c")
            .arg(&config)
            .env("NEXTGCORE_SBI_PROFILE", "dev")
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
            .env(
                "PCF_METRICS_PORT",
                nextgcore_sbi::test_support::free_port().to_string(),
            )
            // The readiness line is logged at info; a CI-wide RUST_LOG must not hide it.
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.log()).unwrap());
        if let Some(secs) = audit_secs {
            cmd.env("PCF_POLICY_DATA_AUDIT_SECS", secs.to_string());
        }
        let mut child = Killed(cmd.spawn().expect("spawn pcfd"));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let exited = child.0.try_wait().unwrap();
            if !how.pause_after_exit_check.is_zero() {
                tokio::time::sleep(how.pause_after_exit_check).await;
            }
            let log = std::fs::read_to_string(dir.log()).unwrap_or_default();
            match exited {
                None if log.contains(SBI_LISTENING) => return (child, dir),
                None => {}
                Some(_) if log.contains("Failed to start SBI server") && log.contains("in use") => {
                    // Lost the port: drop the dead child and try another.
                    sbi_port = nextgcore_sbi::test_support::free_port();
                    break;
                }
                Some(status) => panic!("pcfd exited at startup ({status})"),
            }
            assert!(Instant::now() < deadline, "pcfd listens within 30 s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    panic!("pcfd lost its SBI port {SPAWN_ATTEMPTS} times running");
}

/// Wait on a condition, not a timer.
async fn eventually(within: Duration, what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !cond() {
        assert!(Instant::now() < deadline, "{what} within {within:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn sigterm(child: &Child) {
    let ok = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill -TERM")
        .success();
    assert!(ok);
}

async fn exits_within(child: &mut Child, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "pcfd exits within {within:?} of a SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The EKS race: the PCF discovers before the UDR has registered, so its first
/// attempt finds no UDR. The UDR then appears, and must be subscribed to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udr_that_registers_after_the_pcf_looked_is_subscribed_to() {
    let nrf = Nrf::start().await;
    let (_pcfd, _dir) = spawn_pcfd("late", &nrf, None).await;
    eventually(
        Duration::from_secs(30),
        "the PCF looks for a UDR before any is registered",
        || nrf.udr_discoveries() >= 1,
    )
    .await;

    let udr = Udr::start(None).await;
    nrf.register_only(udr.port);
    eventually(
        Duration::from_secs(20),
        "the late UDR receives the policy-data subscription",
        || udr.with(|s| s.posts) == 1,
    )
    .await;
    udr.server.stop().await.ok();
}

/// A UDR that restarted without its state answers 404 for the subscription; the
/// audit sees that and subscribes again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udr_that_lost_the_subscription_gets_it_again() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(None).await;
    nrf.register_only(udr.port);
    let (_pcfd, _dir) = spawn_pcfd("lost", &nrf, Some(1)).await;
    eventually(Duration::from_secs(30), "the first subscription", || {
        udr.with(|s| s.posts) == 1
    })
    .await;
    eventually(
        Duration::from_secs(10),
        "an audit GET of the held one",
        || udr.with(|s| s.gets) >= 1,
    )
    .await;

    udr.with(|s| s.held.clear());
    eventually(Duration::from_secs(10), "a second subscription", || {
        udr.with(|s| s.posts) == 2
    })
    .await;
    assert_eq!(
        udr.with(|s| s.held.len()),
        1,
        "the UDR holds exactly one again"
    );
    udr.server.stop().await.ok();
}

/// The UDR is replaced by an instance at another endpoint (re-registration): the
/// new one gets the subscription.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_udr_gets_the_subscription() {
    let nrf = Nrf::start().await;
    let first = Udr::start(None).await;
    nrf.register_only(first.port);
    let (_pcfd, _dir) = spawn_pcfd("replaced", &nrf, Some(1)).await;
    eventually(
        Duration::from_secs(30),
        "the first UDR's subscription",
        || first.with(|s| s.posts) == 1,
    )
    .await;

    let second = Udr::start(None).await;
    nrf.register_only(second.port);
    eventually(
        Duration::from_secs(10),
        "the replacement UDR's subscription",
        || second.with(|s| s.posts) == 1,
    )
    .await;
    // The first UDR is still up: the subscription it holds is deleted there, not
    // left to send a second copy of every notification.
    eventually(
        Duration::from_secs(10),
        "a DELETE at the replaced UDR",
        || first.with(|s| s.deletes) == 1,
    )
    .await;
    assert!(
        first.with(|s| s.held.is_empty()),
        "the replaced UDR holds nothing"
    );
    first.server.stop().await.ok();
    second.server.stop().await.ok();
}

/// The UDR confirms a 4 s lifetime on every create and renewal. The PCF must renew
/// with a PUT on the individual resource before each confirmed expiry, more than
/// once, without re-creating it. The audit interval is the 30 s default, so only
/// the renewal can be what keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmed_expiry_is_renewed_before_it_lapses() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(Some(4)).await;
    nrf.register_only(udr.port);
    let (_pcfd, _dir) = spawn_pcfd("expiry", &nrf, None).await;
    eventually(Duration::from_secs(30), "the subscription", || {
        udr.with(|s| s.posts) == 1
    })
    .await;
    let mut lifetimes_kept = 0;
    for _ in 0..2 {
        let (_, confirmed_at) = udr.with(|s| s.confirmed).expect("an expiry was confirmed");
        let puts_before = udr.with(|s| s.puts.len());
        eventually(
            Duration::from_secs(4),
            "a renewal before the 4 s expiry",
            || udr.with(|s| s.puts.len()) > puts_before,
        )
        .await;
        let put_at = *udr.with(|s| s.puts.last().cloned()).as_ref().unwrap();
        assert!(
            put_at.duration_since(confirmed_at) < Duration::from_secs(4),
            "renewed before the confirmed expiry"
        );
        lifetimes_kept += 1;
    }
    assert_eq!(lifetimes_kept, 2);
    assert_eq!(udr.with(|s| s.posts), 1, "renewed, not re-created");
    udr.server.stop().await.ok();
}

/// SIGTERM while subscribed: the subscription is deleted at the UDR it was made at,
/// and the process exits cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sigterm_deletes_the_subscription() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(None).await;
    nrf.register_only(udr.port);
    let (mut pcfd, _dir) = spawn_pcfd("delete", &nrf, None).await;
    eventually(Duration::from_secs(30), "the subscription", || {
        udr.with(|s| s.posts) == 1
    })
    .await;
    sigterm(&pcfd.0);
    let status = exits_within(&mut pcfd.0, Duration::from_secs(10)).await;
    assert!(status.success(), "{status:?}");
    assert_eq!(
        udr.with(|s| s.deletes),
        1,
        "DELETE on the held subscription"
    );
    assert!(udr.with(|s| s.held.is_empty()));
    udr.server.stop().await.ok();
}

/// SIGTERM while the maintainer waits out its backoff (no UDR registered) still
/// ends the process promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sigterm_while_no_udr_is_registered_exits_promptly() {
    let nrf = Nrf::start().await;
    let (mut pcfd, _dir) = spawn_pcfd("nosub", &nrf, None).await;
    // Several misses, so the backoff has grown past the stop poll.
    eventually(Duration::from_secs(30), "repeated UDR discoveries", || {
        nrf.udr_discoveries() >= 3
    })
    .await;
    sigterm(&pcfd.0);
    let status = exits_within(&mut pcfd.0, Duration::from_secs(3)).await;
    assert!(status.success(), "{status:?}");
}

/// Two healthy UDRs, listed in a different order at every discovery. The
/// subscription's UDR is always listed, so it is kept: one POST over many audits,
/// and no DELETE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reordered_discovery_result_keeps_the_subscription() {
    let nrf = Nrf::start().await;
    let a = Udr::start(None).await;
    let b = Udr::start(None).await;
    nrf.register_rotating(&[a.port, b.port]);
    let (_pcfd, _dir) = spawn_pcfd("rotating", &nrf, Some(1)).await;
    let posts = || a.with(|s| s.posts) + b.with(|s| s.posts);
    eventually(Duration::from_secs(30), "the subscription", || posts() == 1).await;
    let seen = nrf.udr_discoveries();
    eventually(Duration::from_secs(15), "six more audits", || {
        nrf.udr_discoveries() >= seen + 6
    })
    .await;
    assert_eq!(posts(), 1, "one subscription across every reordering");
    assert_eq!(a.with(|s| s.deletes) + b.with(|s| s.deletes), 0);
    a.server.stop().await.ok();
    b.server.stop().await.ok();
}

/// A UDR that answers a renewal 204 confirms no new expiry; the lifetime it
/// confirmed on the POST still applies, so the PCF keeps renewing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_204_renewal_keeps_the_confirmed_lifetime() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(Some(4)).await;
    udr.with(|s| s.put_204 = true);
    nrf.register_only(udr.port);
    let (_pcfd, _dir) = spawn_pcfd("put204", &nrf, None).await;
    eventually(Duration::from_secs(30), "the subscription", || {
        udr.with(|s| s.posts) == 1
    })
    .await;
    eventually(Duration::from_secs(4), "a first renewal", || {
        udr.with(|s| s.puts.len()) == 1
    })
    .await;
    let first_put = udr.with(|s| s.puts[0]);
    eventually(
        Duration::from_secs(4),
        "a second renewal within the lifetime",
        || udr.with(|s| s.puts.len()) >= 2,
    )
    .await;
    assert!(udr.with(|s| s.puts[1]).duration_since(first_put) < Duration::from_secs(4));
    assert_eq!(udr.with(|s| s.posts), 1, "renewed, not re-created");
    udr.server.stop().await.ok();
}

/// An NRF that stops answering discovery must not hold the audit past a due
/// renewal: discovery is bounded, so the PUT still lands within the 8 s lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_nrf_does_not_delay_a_due_renewal() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(Some(8)).await;
    nrf.register_only(udr.port);
    let (_pcfd, _dir) = spawn_pcfd("hungnrf", &nrf, Some(1)).await;
    eventually(Duration::from_secs(30), "the subscription", || {
        udr.with(|s| s.posts) == 1
    })
    .await;
    nrf.hold_discovery(Duration::from_secs(25));
    let (_, confirmed_at) = udr.with(|s| s.confirmed).expect("an expiry");
    eventually(
        Duration::from_secs(8),
        "a renewal within the lifetime",
        || udr.with(|s| s.puts.iter().any(|p| *p > confirmed_at)),
    )
    .await;
    udr.server.stop().await.ok();
}

/// SIGTERM while the subscribe's discovery is in flight: no POST follows it, so
/// there is no subscription at the UDR that the PCF never recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sigterm_during_discovery_creates_no_subscription() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(None).await;
    nrf.register_only(udr.port);
    nrf.hold_discovery(Duration::from_secs(2));
    let (mut pcfd, _dir) = spawn_pcfd("stopdisc", &nrf, None).await;
    eventually(Duration::from_secs(30), "the first UDR discovery", || {
        nrf.udr_discoveries() >= 1
    })
    .await;
    sigterm(&pcfd.0);
    let status = exits_within(&mut pcfd.0, Duration::from_secs(8)).await;
    assert!(status.success(), "{status:?}");
    assert_eq!(
        udr.with(|s| s.posts),
        0,
        "no subscribe once shutdown was requested"
    );
    udr.server.stop().await.ok();
}

/// #1497: the bind loss made deterministic. The first SBI port is held by another
/// socket, here a listener; in the flake it was a sibling pcfd's outbound
/// connection. Either gives EADDRINUSE, so pcfd exits at startup. This proves the
/// harness's answer, not the cause: the spawn sees that exit, moves to another
/// port, and the subscription is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pcfd_that_loses_its_sbi_port_is_spawned_on_another() {
    let nrf = Nrf::start().await;
    let udr = Udr::start(None).await;
    nrf.register_only(udr.port);
    let taken = nextgcore_sbi::test_support::bound_listener();
    let (_pcfd, dir) = spawn_pcfd_with(
        "taken",
        &nrf,
        None,
        Spawn {
            first_port: taken.port(),
            ..Spawn::default()
        },
    )
    .await;
    let log = std::fs::read_to_string(dir.log()).unwrap();
    let listening = log
        .lines()
        .find_map(|l| l.split(SBI_LISTENING).nth(1))
        .expect("the listening line")
        .trim()
        .to_string();
    assert!(
        listening.starts_with("127.0.0.1:") && listening != format!("127.0.0.1:{}", taken.port()),
        "listening on another port than the taken one: {listening}"
    );
    eventually(Duration::from_secs(10), "the subscription", || {
        udr.with(|s| s.posts) == 1
    })
    .await;
    drop(taken);
    udr.server.stop().await.ok();
}

/// #1520 review: a lost bind is still retried when pcfd prints the bind error and
/// exits after the harness last looked at its log. Here the harness pauses 300 ms
/// between asking whether pcfd exited and reading the log, so that exit always
/// falls in the window.
///
/// REVERT-VERIFIED: with the log read before `try_wait` again, this fails with
/// "pcfd exited at startup (exit status: 1)" while the dumped stderr shows the bind
/// error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_bind_seen_late_is_still_retried() {
    let nrf = Nrf::start().await;
    let taken = nextgcore_sbi::test_support::bound_listener();
    let (_pcfd, dir) = spawn_pcfd_with(
        "taken-late",
        &nrf,
        None,
        Spawn {
            first_port: taken.port(),
            pause_after_exit_check: Duration::from_millis(300),
            ..Spawn::default()
        },
    )
    .await;
    let log = std::fs::read_to_string(dir.log()).unwrap();
    assert!(log.contains(SBI_LISTENING), "the respawn listens: {log}");
    drop(taken);
}

/// #1520 review: a startup failure that is not a lost bind fails at once, as the
/// failure it is, rather than being respawned until "lost its SBI port 5 times".
/// The SBI address does not parse, so pcfd exits before it binds anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[should_panic(expected = "pcfd exited at startup")]
async fn a_startup_failure_that_is_not_a_lost_bind_fails_at_once() {
    let nrf = Nrf::start().await;
    let _ = spawn_pcfd_with(
        "badaddr",
        &nrf,
        None,
        Spawn {
            address: "not-an-address",
            ..Spawn::default()
        },
    )
    .await;
}
