//! Test-support helpers shared across the NF crates.
//!
//! Deliberately NOT `#[cfg(test)]`: a `cfg(test)` item in a library is invisible
//! to other crates' test binaries, which is exactly the sharing these helpers
//! exist to provide. Follows the repo's existing `pub mod test_support`
//! convention (see `nextgcore-bsfd`, `-amfd`, `-ausfd`, `-pcfd`, `-udmd`).

use std::collections::HashSet;
use std::future::Future;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::server::{SbiServer, SbiServerConfig};

/// Every port this module has handed out in this process, by either route.
///
/// One set for both [`free_port`] and [`bound_listener`]: a bare-port caller and
/// a reserved-listener caller in the same process must not be given the same
/// number either. Declared at module scope rather than inside `free_port` so the
/// second route can reach it — the same "declare the global beside what guards
/// it" shape #308 imposed on the process-state test locks.
fn issued_ports() -> &'static Mutex<HashSet<u16>> {
    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    ISSUED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Reserve a loopback port for a test server, never handing the same port to
/// two callers in this process.
///
/// # Prefer [`bound_listener`] when the port will be served
///
/// This helper still has the probe-drop window: it binds `127.0.0.1:0`, reads
/// the assigned port, drops the probe and returns a bare number, so between the
/// drop and the caller's real bind the port belongs to nobody. Excluding
/// already-issued ports closes the *in-process* race — the one parallel test
/// threads create — but each test BINARY has its own `ISSUED` set, so under
/// `cargo test --workspace`, which runs one binary per crate at once, two crates
/// can still be handed the same port and one of them then fails to bind. That
/// was #313, and the fix is [`bound_listener`] (plus
/// [`SbiServer::on_listener`]): the port is bound from the moment it is chosen,
/// so there is no window at all.
///
/// What is left for this helper is the callers that need a port but never bind
/// it — a URI in a notification body that is never dialled, a UDP peer. Holding a
/// TCP listener on those would change what the test measures, which is why #313
/// did not delete this function.
///
/// **Not** for a connection-refused test. This doc used to list that as a
/// legitimate use and it is not: the port is free, so a sibling test's
/// `bind(:0)` can be handed it and the refusal never happens. Use
/// [`refused_port`], which explains the flake that came of it.
///
/// The original symptom, for the record: 21 crates each had a private copy of
/// the unguarded probe-drop helper, and under parallel `cargo test` it surfaced
/// as spurious `Address already in use` failures — `nextgcore-scpd` at roughly 1
/// run in 10 before it was mitigated, and `nextgcore-nssfd` on a clean merged
/// main.
///
/// # Panics
///
/// If 256 consecutive probes all return already-issued ports, which would mean
/// the ephemeral range is effectively exhausted.
pub fn free_port() -> u16 {
    let issued = issued_ports();

    for _ in 0..256 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        // insert() returns false when the port was already handed out.
        if issued.lock().expect("issued lock").insert(port) {
            return port;
        }
    }
    panic!("could not obtain an unused ephemeral port in 256 attempts");
}

/// A loopback port that is guaranteed to REFUSE a connection, for a test whose
/// subject is the failure path.
///
/// [`free_port`] is the wrong tool for that, and this exists because using it
/// there is a real flake rather than a theoretical one. `free_port` binds a
/// probe, records the port and **drops** the listener, so the port is free — and
/// nothing stops the kernel handing that same port to a sibling test whose stub
/// server binds `127.0.0.1:0` a moment later. The port the first test picked for
/// "nothing is listening here" then has a server on it, the connection succeeds,
/// and its `assert!(result.is_err())` fails.
///
/// Observed as `nextgcore-amfd`'s `ue_policy_create_unreachable_is_err` failing
/// about **1 workspace run in 7** on a clean `main`. `issued_ports` cannot help:
/// it stops this helper handing the same port out twice, and the collision is
/// with a `bind(:0)` that never goes through this helper at all.
///
/// Port **1** is the answer, and the idiom was already in the tree —
/// `nextgcore-scpd`'s proxy tests use it with the note "Port 1 on loopback
/// refuses immediately (privileged, nothing listening)". It is below the
/// privileged threshold and far below `ip_local_port_range`, so no
/// `bind(:0)` in this process can ever be assigned it, which is what makes the
/// refusal deterministic rather than probable.
///
/// Use [`free_port`] only where the port is genuinely never dialled (a
/// notification URI in a body, a UDP peer). Use [`bound_listener`] where it will
/// be served.
pub fn refused_port() -> u16 {
    1
}

/// A loopback `SocketAddr` that refuses. See [`refused_port`].
pub fn refused_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], refused_port()))
}

/// A loopback `SocketAddr` on a port from [`free_port`], for the callers that
/// want an address rather than a bare port.
///
/// Carries [`free_port`]'s window. Use [`bound_listener`] when the address will
/// actually be served.
pub fn ephemeral_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], free_port()))
}

/// A loopback listener that is **already bound**, together with the address it
/// is bound to (#313).
///
/// The point of the type is that the port and the socket travel together: there
/// is no moment at which the port has been chosen but nothing holds it. Hand the
/// listener to [`SbiServer::on_listener`] (or to
/// [`BoundListener::into_listener`] for anything else that can adopt a
/// `std::net::TcpListener`).
#[derive(Debug)]
pub struct BoundListener {
    listener: TcpListener,
    addr: SocketAddr,
}

impl BoundListener {
    /// The address the listener is bound to. Never port 0.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port the listener is bound to.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Give up the listener, keeping it bound.
    pub fn into_listener(self) -> TcpListener {
        self.listener
    }

    /// Both halves, for a caller that needs the address after moving the
    /// listener.
    pub fn into_parts(self) -> (TcpListener, SocketAddr) {
        (self.listener, self.addr)
    }
}

/// Reserve a loopback port by **keeping it bound**, closing the window
/// [`free_port`] leaves open (#313).
///
/// The returned listener is still bound when it reaches the caller, so no other
/// process — not just no other thread — can take the port in between. The port
/// is also recorded in [`free_port`]'s issued set, so the two helpers cannot
/// hand out the same port to one process.
///
/// # Panics
///
/// If `127.0.0.1:0` cannot be bound, or its local address cannot be read.
pub fn bound_listener() -> BoundListener {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reserved listener");
    let addr = listener.local_addr().expect("reserved listener addr");
    // Share one issued set with free_port(), so a bare-port caller and a
    // reserved-listener caller in the same process cannot be handed the same
    // number either. No retry loop is needed here and having one would be
    // wrong: the port is already held, so a duplicate would mean the OS reissued
    // a port free_port() probed and released — recording it is what stops
    // free_port() returning it a second time.
    issued_ports()
        .lock()
        .expect("issued lock")
        .insert(addr.port());
    BoundListener { listener, addr }
}

/// Build and start an [`SbiServer`] on a reserved loopback port, with no window
/// in which the port is unbound (#313).
///
/// The common shape: `let (server, addr) = sbi_server_on_free_port(handler).await;`
/// replaces `free_port()` plus `SbiServer::new(SbiServerConfig::new(addr))` plus
/// `start()`.
///
/// # Panics
///
/// If the server fails to start, which after this change means a genuine
/// failure rather than a lost race.
pub async fn sbi_server_on_free_port<H: crate::server::SbiRequestHandler>(
    handler: H,
) -> (SbiServer, SocketAddr) {
    sbi_server_on_free_port_with(SbiServerConfig::new, handler).await
}

/// [`sbi_server_on_free_port`] for a caller that needs a customised
/// [`SbiServerConfig`] — TLS, an expected audience, an overload reporter.
///
/// `build` receives the reserved address, so a config that derives anything from
/// its own address still sees the real one.
///
/// # Panics
///
/// If the server fails to start.
pub async fn sbi_server_on_free_port_with<H, F>(build: F, handler: H) -> (SbiServer, SocketAddr)
where
    H: crate::server::SbiRequestHandler,
    F: FnOnce(SocketAddr) -> SbiServerConfig,
{
    let (listener, addr) = bound_listener().into_parts();
    let server = SbiServer::on_listener(build(addr), listener);
    server.start(handler).await.expect("sbi server start");
    (server, addr)
}

/// Poll `probe` until it yields a value or `budget` is spent, then give up and
/// return `None` (#370).
///
/// # Why a budget and not an iteration count
///
/// The shape this replaces is `for _ in 0..200 { ...; sleep(20ms).await }` nested
/// inside a `tokio::time::timeout(Duration::from_secs(20), ..)`. Counting
/// iterations makes the *inner* loop the real bound — 200 × 20 ms is 4 s, five
/// times tighter than the 20 s timeout enclosing it — so the outer timeout can
/// never be the one that fires. The test then reports a failed assertion that
/// reads like a wiring defect when all that happened is that a 2-worker runtime
/// went unscheduled under `cargo test --workspace` oversubscription. Measured on
/// #370: the failing run's group took 4.43 s against a 0.18–0.34 s norm over 25
/// runs under six CPU-burning background loops — exactly the 4 s inner budget,
/// so the thing that expired was patience, not the effect being waited for.
///
/// A budget fixes that by construction rather than by choosing a bigger count:
/// the caller states one duration, the loop honours it whatever the tick
/// interval, and two polls in one test share the enclosing bound instead of each
/// silently imposing its own. Pass the budget derived from the test's outer
/// timeout (see [`Deadline`]) so the inner wait cannot be the tighter of the two.
///
/// This weakens no assertion: a probe that never yields still ends the wait, and
/// the caller still asserts on the value. It only stops a starved runtime from
/// being reported as a missing effect.
pub async fn poll_until<T, F, Fut>(budget: Duration, tick: Duration, mut probe: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(value) = probe().await {
            return Some(value);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return None;
        }
        // Never sleep past the deadline: a long tick must not extend the budget.
        tokio::time::sleep(tick.min(deadline - now)).await;
    }
}

/// One deadline shared by every wait in a test, so no inner poll can be tighter
/// than the bound the test is actually given (#370).
///
/// Construct it once from the test's total budget and call [`Deadline::remaining`]
/// at each [`poll_until`]. Two successive polls then divide one budget between
/// them instead of each getting the whole of its own, which is the property the
/// fixed-count shape lacked: `sm_policy_update_wires_the_bsf_binding_update` had
/// *two* 4 s loops inside one 20 s timeout, so its worst case was neither 4 s nor
/// 20 s but 8 s.
///
/// Prefer this to wrapping the body in `tokio::time::timeout`: a timeout that
/// fires cancels the future at an arbitrary await point and reports only "timed
/// out", whereas a spent budget returns to the caller, which then fails on its
/// own assertion and says which effect never arrived.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: tokio::time::Instant,
}

impl Deadline {
    /// A deadline `budget` from now.
    pub fn after(budget: Duration) -> Self {
        Self {
            at: tokio::time::Instant::now() + budget,
        }
    }

    /// What is left of the budget, saturating at zero once it is spent.
    ///
    /// Zero is a legitimate value to hand [`poll_until`]: the probe still runs
    /// once, so a wait that arrives exactly at the deadline is decided on the
    /// state of the world rather than on the clock.
    pub fn remaining(&self) -> Duration {
        self.at
            .saturating_duration_since(tokio::time::Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet as Set;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The core guarantee: no port is ever issued twice in one process.
    #[test]
    fn free_port_never_repeats() {
        let mut seen = Set::new();
        for _ in 0..300 {
            let p = free_port();
            assert!(p != 0, "port 0 means the probe never bound");
            assert!(seen.insert(p), "port {p} was issued twice");
        }
    }

    /// Concurrent callers must also receive distinct ports -- the parallel
    /// `cargo test` case that produced the original flakes.
    #[test]
    fn free_port_distinct_across_threads() {
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| (0..25).map(|_| free_port()).collect::<Vec<_>>()))
            .collect();
        let mut seen = Set::new();
        for h in handles {
            for p in h.join().expect("thread panicked") {
                assert!(seen.insert(p), "port {p} handed to two threads");
            }
        }
    }

    #[test]
    fn ephemeral_addr_is_loopback_with_a_real_port() {
        let a = ephemeral_addr();
        assert!(a.ip().is_loopback());
        assert_ne!(a.port(), 0);
    }

    /// The whole point of #313, pinned as a **difference** between the two
    /// helpers rather than as a property of one.
    ///
    /// `bound_listener` still holds the port when the caller gets it, so a
    /// competing bind fails; `free_port`/`ephemeral_addr` do not, so the same
    /// bind succeeds. The second half is the defect, and asserting it here is
    /// what makes the first half mean something: a `bound_listener` that had
    /// quietly reverted to the probe-drop shape would make BOTH binds succeed,
    /// and only a test that knows what the broken shape does can tell them
    /// apart.
    #[test]
    fn a_reserved_port_is_bound_and_a_free_port_is_not() {
        let reserved = bound_listener();
        let err = TcpListener::bind(reserved.addr())
            .expect_err("the reserved port must still be held by the reservation");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AddrInUse,
            "expected the reserved port to be in use, got {err}"
        );

        // The window, demonstrated: a free_port address is claimable by whoever
        // asks first. This is why free_port must not be used for a port that
        // will be served.
        let unheld = ephemeral_addr();
        let squatter =
            TcpListener::bind(unheld).expect("a free_port address is unbound, that IS the window");
        drop(squatter);
    }

    /// `free_port` cannot hand back a port a reservation is already holding:
    /// both routes share one issued set.
    #[test]
    fn reserved_ports_are_excluded_from_free_port() {
        let reserved: Vec<_> = (0..16).map(|_| bound_listener()).collect();
        let held: Set<u16> = reserved.iter().map(BoundListener::port).collect();
        for _ in 0..200 {
            let p = free_port();
            assert!(!held.contains(&p), "free_port returned reserved port {p}");
        }
    }

    /// The reservation survives being split from its address.
    #[test]
    fn into_parts_keeps_the_listener_bound() {
        let (listener, addr) = bound_listener().into_parts();
        assert_eq!(listener.local_addr().expect("addr"), addr);
        assert!(TcpListener::bind(addr).is_err());
    }

    /// End to end: a server started on a reservation serves on exactly the
    /// reserved address, and `config.addr` reports that address rather than
    /// whatever placeholder the config was built with.
    #[tokio::test]
    async fn a_server_on_a_reservation_serves_the_reserved_address() {
        async fn ok200(_req: crate::message::SbiRequest) -> crate::message::SbiResponse {
            crate::server::send_error(200, "OK", "OK", None)
        }

        let (server, addr) = sbi_server_on_free_port(ok200).await;
        assert_eq!(server.config().addr, addr, "config must report the socket");
        assert!(server.is_running().await);

        // A real connection, so this is not a claim about configuration only.
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the started server accepts on the reserved address");
        drop(stream);

        server.stop().await.expect("stop");
    }

    /// The happy path: a probe that eventually yields ends the wait with the
    /// value, without spending the budget.
    #[tokio::test(start_paused = true)]
    async fn poll_until_returns_the_first_value_a_probe_yields() {
        let calls = AtomicUsize::new(0);
        let got = poll_until(Duration::from_secs(20), Duration::from_millis(20), || {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move { (n >= 3).then_some(n) }
        })
        .await;
        assert_eq!(
            got,
            Some(3),
            "the third probe yields, so the wait ends there"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3, "and it stops probing");
    }

    /// The budget is the bound, and it is honoured rather than approximated: a
    /// probe that never yields must return `None` at the budget, not before and
    /// not after.
    #[tokio::test(start_paused = true)]
    async fn poll_until_gives_up_at_the_budget() {
        let start = tokio::time::Instant::now();
        let got = poll_until(
            Duration::from_secs(2),
            Duration::from_millis(20),
            || async { None::<()> },
        )
        .await;
        assert_eq!(got, None, "a probe that never yields must give up");
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(2),
            "the budget is the bound; a 20 ms tick must not overshoot it"
        );
    }

    /// A tick longer than the remaining budget must be clamped, not slept in
    /// full. This is the regression guard for the defect the whole helper exists
    /// to remove -- a wait whose real bound is its own tick arithmetic rather than
    /// the budget it was given.
    #[tokio::test(start_paused = true)]
    async fn a_tick_longer_than_the_budget_does_not_extend_it() {
        let start = tokio::time::Instant::now();
        let got = poll_until(
            Duration::from_millis(50),
            Duration::from_secs(30),
            || async { None::<()> },
        )
        .await;
        assert_eq!(got, None);
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(50),
            "a 30 s tick inside a 50 ms budget must be clamped to the budget"
        );
    }

    /// The property the fixed-count shape lacked (#370): two successive waits
    /// DIVIDE one budget instead of each taking the whole of its own, so the
    /// worst case is the budget and not a multiple of it.
    #[tokio::test(start_paused = true)]
    async fn two_waits_on_one_deadline_share_the_budget() {
        let start = tokio::time::Instant::now();
        let deadline = Deadline::after(Duration::from_secs(4));

        let first = poll_until(deadline.remaining(), Duration::from_millis(20), || async {
            None::<()>
        })
        .await;
        assert_eq!(first, None);
        assert_eq!(
            deadline.remaining(),
            Duration::ZERO,
            "the first wait spent it"
        );

        // The second wait still probes once -- a deadline that has just expired
        // decides on the state of the world, not on the clock.
        let second = poll_until(deadline.remaining(), Duration::from_millis(20), || async {
            Some(7)
        })
        .await;
        assert_eq!(second, Some(7));
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(4),
            "two waits on one deadline total the budget, not twice it"
        );
    }

    /// A placeholder address in the config is replaced by the listener's real
    /// one; the config never wins over the socket.
    #[test]
    fn on_listener_overwrites_a_placeholder_config_address() {
        let (listener, addr) = bound_listener().into_parts();
        let placeholder = SocketAddr::from(([127, 0, 0, 1], 0));
        let server = SbiServer::on_listener(SbiServerConfig::new(placeholder), listener);
        assert_eq!(server.config().addr, addr);
    }
}
