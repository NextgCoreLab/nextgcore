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

fn serve(
    handler: impl Fn(SbiRequest) -> SbiResponse + Send + Sync + 'static,
) -> impl std::future::Future<Output = (SbiServer, SocketAddr)> {
    let handler = Arc::new(handler);
    async move {
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
        server
            .start(move |req: SbiRequest| {
                let handler = handler.clone();
                async move { handler(req) }
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
        let (server, addr) = serve(move |req| udr_answer(&s, &req)).await;
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
                    if held {
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
    port: u16,
    _server: SbiServer,
}

impl Nrf {
    async fn start() -> Nrf {
        let udrs: Arc<Mutex<Vec<u16>>> = Arc::default();
        let udr_discoveries: Arc<Mutex<usize>> = Arc::default();
        let (u, d) = (udrs.clone(), udr_discoveries.clone());
        let (server, addr) = serve(move |req| {
            let uri = req.header.uri.clone();
            match req.header.method.as_str() {
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
                    let instances: Vec<serde_json::Value> = if wants_udr {
                        *d.lock().unwrap() += 1;
                        u.lock().unwrap().iter().map(|p| udr_profile(*p)).collect()
                    } else {
                        vec![]
                    };
                    SbiResponse::with_status(200).with_body(
                        serde_json::json!({ "nfInstances": instances }).to_string(),
                        "application/json",
                    )
                }
                _ => SbiResponse::with_status(404),
            }
        })
        .await;
        Nrf {
            udrs,
            udr_discoveries,
            port: addr.port(),
            _server: server,
        }
    }

    fn register_only(&self, udr_port: u16) {
        *self.udrs.lock().unwrap() = vec![udr_port];
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

/// A per-test scratch directory, removed on drop.
struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("pcf.yaml"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn spawn_pcfd(name: &str, nrf: &Nrf, audit_secs: Option<u64>) -> (Killed, Scratch) {
    let dir =
        Scratch(std::env::temp_dir().join(format!("pcfd-1458-{name}-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let config = dir.0.join("pcf.yaml");
    let sbi_port = nextgcore_sbi::test_support::free_port();
    std::fs::write(
        &config,
        format!(
            "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: {sbi_port}\n    \
             client:\n      nrf:\n        - uri: http://127.0.0.1:{}\n",
            nrf.port
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
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(secs) = audit_secs {
        cmd.env("PCF_POLICY_DATA_AUDIT_SECS", secs.to_string());
    }
    (Killed(cmd.spawn().expect("spawn pcfd")), dir)
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
    let (_pcfd, _dir) = spawn_pcfd("late", &nrf, None);
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
    let (_pcfd, _dir) = spawn_pcfd("lost", &nrf, Some(1));
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
    let (_pcfd, _dir) = spawn_pcfd("replaced", &nrf, Some(1));
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
    let (_pcfd, _dir) = spawn_pcfd("expiry", &nrf, None);
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
    let (mut pcfd, _dir) = spawn_pcfd("delete", &nrf, None);
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
    let (mut pcfd, _dir) = spawn_pcfd("nosub", &nrf, None);
    // Several misses, so the backoff has grown past the stop poll.
    eventually(Duration::from_secs(30), "repeated UDR discoveries", || {
        nrf.udr_discoveries() >= 3
    })
    .await;
    sigterm(&pcfd.0);
    let status = exits_within(&mut pcfd.0, Duration::from_secs(3)).await;
    assert!(status.success(), "{status:?}");
}
