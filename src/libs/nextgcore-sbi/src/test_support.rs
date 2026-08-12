//! Test-support helpers shared across the NF crates.
//!
//! Deliberately NOT `#[cfg(test)]`: a `cfg(test)` item in a library is invisible
//! to other crates' test binaries, which is exactly the sharing these helpers
//! exist to provide. Follows the repo's existing `pub mod test_support`
//! convention (see `nextgcore-bsfd`, `-amfd`, `-ausfd`, `-pcfd`, `-udmd`).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

/// Reserve a loopback port for a test server, never handing the same port to
/// two callers in this process.
///
/// # The window this closes, and the one it does not
///
/// The obvious implementation — bind `127.0.0.1:0`, read the assigned port,
/// drop the probe, let the caller bind it — is inherently TOCTOU: between the
/// drop and the caller's real bind the port is unbound, so the OS may hand it
/// to the next probe. Twenty-one crates each had a private copy of exactly that
/// helper, and under parallel `cargo test` it surfaced as spurious
/// `Address already in use` failures: `nextgcore-scpd` at roughly 1 run in 10
/// before it was mitigated, and `nextgcore-nssfd` on a clean merged main.
///
/// Excluding already-issued ports closes the *in-process* race, which is the
/// one parallel test threads create and the only one actually observed here.
///
/// It does NOT close the probe-drop window itself: a foreign process can still
/// claim the port in that gap. Eliminating that requires handing callers a
/// PRE-BOUND `TcpListener` — the port is then never unbound — which in turn
/// requires [`crate::server::SbiServer`] to accept a listener instead of only a
/// `SocketAddr` (it binds internally today). That API change is tracked
/// separately; when it lands, every caller of this helper inherits it, which is
/// the point of having one implementation rather than 21.
///
/// # Panics
///
/// If 256 consecutive probes all return already-issued ports, which would mean
/// the ephemeral range is effectively exhausted.
pub fn free_port() -> u16 {
    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let issued = ISSUED.get_or_init(|| Mutex::new(HashSet::new()));

    for _ in 0..256 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        // insert() returns false when the port was already handed out.
        if issued.lock().expect("issued lock").insert(port) {
            return port;
        }
    }
    panic!("could not obtain an unused ephemeral port in 256 attempts");
}

/// A loopback `SocketAddr` on a port from [`free_port`], for the callers that
/// want an address rather than a bare port.
pub fn ephemeral_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], free_port()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet as Set;

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
}
