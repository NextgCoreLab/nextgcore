//! Which hosts a UP function accepts PFCP from (security, PR #968).
//!
//! PFCP has no authentication of its own: TS 29.244 §6.2.6 scopes an association to a
//! CP/UP function pair and leaves it to the deployment (TS 33.501 §9.9, NDS/IP) to keep
//! strangers off the N4/Sx network. A UP function that accepts an Association Setup
//! Request from any host therefore hands its sessions to any host that can reach its
//! PFCP port. This module holds the pieces both UP functions (upfd and sgwud) use to
//! refuse that:
//!
//! * [`PeerAllowlist`]: the configured CP-function source addresses (IPs and CIDR
//!   prefixes). Only the source IP is compared, never the port: the association is
//!   between Node IDs (§6.2.6), and a CP function may send requests from another port
//!   or, behind NAT, from a binding that changed.
//! * [`is_request_type`] / [`is_response_type`]: Table 7.3-1, so a refused message of
//!   an unknown type is ignored (§7.6) rather than "answered" with type `t + 1`.
//! * [`RefusalLog`]: a rate limit for the refusal log line, so a spoofed flood does not
//!   become a log flood (the refusal counter still counts every datagram).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One allowlist entry: an address prefix. A bare address is a full-length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    fn parse(s: &str) -> Result<Self, String> {
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|e| format!("'{s}' is not an IP address or CIDR prefix: {e}"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(l) => {
                let l: u8 = l
                    .parse()
                    .map_err(|e| format!("'{s}': bad prefix length: {e}"))?;
                if l > max {
                    return Err(format!("'{s}': prefix length {l} exceeds {max}"));
                }
                l
            }
        };
        Ok(Self { addr, len })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// The CP-function hosts a UP function accepts an Association Setup Request from.
///
/// FAIL CLOSED (#968 re-review, operator decision): an EMPTY allowlist permits no
/// host, so a UP function nobody configured refuses every association rather than
/// handing its sessions to the first host that asks. A lab opts out explicitly with
/// `0.0.0.0/0` and/or `::/0`.
///
/// Entries are IP addresses, CIDR prefixes, or host names. A host name (a Kubernetes
/// headless Service, for instance, whose name resolves to the CP pods' current IPs)
/// is resolved off the receive path by [`Self::resolve_hosts`], which the NF calls
/// periodically; [`Self::permits`] only reads the last resolution, so a flood of
/// Setups never turns into a flood of DNS queries. Clones share that resolution.
///
/// A Setup from an address not (yet) resolved can [`Self::kick_refresh`] the
/// resolver, at most once per [`KICK_INTERVAL`], so a CP pod that just restarted at
/// a new IP is admitted on its next attempt instead of after a full interval.
///
/// A name whose lookup FAILS keeps its last good addresses (a DNS blip does not
/// empty the allowlist); one that resolves to nothing is taken at its word.
#[derive(Debug, Clone, Default)]
pub struct PeerAllowlist {
    entries: Vec<Prefix>,
    hosts: Vec<String>,
    resolved: Arc<RwLock<Vec<IpAddr>>>,
    /// Last good addresses per name.
    per_host: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
    /// Set by [`Self::kick_refresh`], cleared by the refresh thread.
    wake: Arc<(Mutex<bool>, Condvar)>,
    /// Milliseconds since the Unix epoch of the last accepted kick.
    last_kick_ms: Arc<AtomicU64>,
}

/// The minimum interval between two early re-resolutions.
pub const KICK_INTERVAL: Duration = Duration::from_secs(1);

/// Whether `s` is a syntactically valid DNS host name (RFC 1123 labels).
fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.trim_end_matches('.').split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        // An all-numeric dotted name is a mistyped address, not a host.
        && !s.split('.').all(|l| l.chars().all(|c| c.is_ascii_digit()))
}

impl PeerAllowlist {
    /// Parse a list of `IP` / `IP/len` / host-name entries separated by commas and/or
    /// whitespace. Empty input yields the empty allowlist, which permits no host.
    pub fn parse(list: &str) -> Result<Self, String> {
        Self::from_entries(
            list.split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty()),
        )
    }

    /// Build from individual `IP` / `IP/len` / host-name entries.
    pub fn from_entries<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Self::default();
        for e in entries {
            let e = e.as_ref().trim();
            if e.is_empty() {
                continue;
            }
            match Prefix::parse(e) {
                Ok(p) => out.entries.push(p),
                Err(_) if !e.contains('/') && is_host_name(e) => out.hosts.push(e.to_string()),
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }

    /// Whether any entry is configured. `false` means NO host is permitted.
    pub fn is_configured(&self) -> bool {
        !self.entries.is_empty() || !self.hosts.is_empty()
    }

    /// Whether `ip` may associate: it is inside a configured prefix, or is a current
    /// address of a configured host name. Never true for an empty allowlist.
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.entries.iter().any(|p| p.contains(ip))
            || self
                .resolved
                .read()
                .map(|r| r.contains(&ip))
                .unwrap_or(false)
    }

    /// The configured host names (resolved by [`Self::resolve_hosts`]).
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Resolve the configured host names now (blocking: call it off the PFCP receive
    /// path, e.g. from the refresh thread) and publish the result to every clone.
    /// Returns the published addresses.
    pub fn resolve_hosts(&self) -> Vec<IpAddr> {
        self.resolve_hosts_with(|h| {
            use std::net::ToSocketAddrs;
            (h, 0u16)
                .to_socket_addrs()
                .map(|it| it.map(|a| a.ip()).collect())
        })
    }

    fn resolve_hosts_with(
        &self,
        lookup: impl Fn(&str) -> std::io::Result<Vec<IpAddr>>,
    ) -> Vec<IpAddr> {
        let mut per_host = self.per_host.lock().unwrap_or_else(|e| e.into_inner());
        for h in &self.hosts {
            match lookup(h) {
                Ok(addrs) => {
                    let mut v: Vec<IpAddr> = Vec::new();
                    for ip in addrs.into_iter().map(|ip| ip.to_canonical()) {
                        if !v.contains(&ip) {
                            v.push(ip);
                        }
                    }
                    per_host.insert(h.clone(), v);
                }
                // Keep the last good addresses: a DNS blip must not refuse a CP
                // function that is still where it was.
                Err(e) => log::warn!(
                    "PFCP allowed peer '{h}' does not resolve ({e}); keeping its last \
                     addresses {:?}",
                    per_host.get(h).cloned().unwrap_or_default()
                ),
            }
        }
        let mut ips: Vec<IpAddr> = Vec::new();
        for v in per_host.values() {
            for ip in v {
                if !ips.contains(ip) {
                    ips.push(*ip);
                }
            }
        }
        if let Ok(mut r) = self.resolved.write() {
            *r = ips.clone();
        }
        ips
    }

    /// Ask the refresh thread to re-resolve now, because a Setup came from an address
    /// the last resolution does not contain. Rate-limited to one kick per
    /// [`KICK_INTERVAL`] and non-blocking, so a flood of strangers costs at most one
    /// lookup a second. Returns whether this call kicked.
    pub fn kick_refresh(&self) -> bool {
        if !self.try_begin_resolution() {
            return false;
        }
        let (flag, cv) = &*self.wake;
        *flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_one();
        true
    }

    /// Take the one early re-resolution allowed per [`KICK_INTERVAL`], shared by
    /// [`Self::kick_refresh`] and a caller that resolves itself before judging an
    /// unlisted address (#1112). `false` when no host name is configured, or when a
    /// resolution began within the interval -- whose answer is then fresh enough to
    /// judge by. So strangers cost at most one lookup per interval.
    pub fn try_begin_resolution(&self) -> bool {
        if self.hosts.is_empty() {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1)
            .max(1);
        let last = self.last_kick_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < KICK_INTERVAL.as_millis() as u64 {
            return false;
        }
        self.last_kick_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Spawn a thread that re-resolves the host names every `interval`, or at once
    /// when kicked (#968): a CP pod that restarts at a new IP is admitted within one
    /// interval, or on its next Setup after a kick. Resolves once before returning,
    /// so the first Setup after startup is judged against real addresses. Does
    /// nothing when no host name is configured.
    pub fn spawn_host_refresh(&self, interval: Duration) {
        if self.hosts.is_empty() {
            return;
        }
        let first = self.resolve_hosts();
        log::info!(
            "PFCP allowed peer names {:?} resolve to {first:?}",
            self.hosts
        );
        let me = self.clone();
        let _ = std::thread::Builder::new()
            .name("pfcp-peer-dns".into())
            .spawn(move || loop {
                {
                    let (flag, cv) = &*me.wake;
                    let guard = flag.lock().unwrap_or_else(|e| e.into_inner());
                    let (mut guard, _) = cv
                        .wait_timeout_while(guard, interval, |kicked| !*kicked)
                        .unwrap_or_else(|e| e.into_inner());
                    *guard = false;
                }
                me.resolve_hosts();
            });
    }

    #[cfg(test)]
    fn set_resolved(&self, ips: Vec<IpAddr>) {
        *self.resolved.write().unwrap() = ips;
    }
}

impl std::fmt::Display for PeerAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.is_configured() {
            return f.write_str("<none: every Association Setup is refused>");
        }
        let mut first = true;
        for p in &self.entries {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{p}")?;
        }
        for h in &self.hosts {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            f.write_str(h)?;
        }
        Ok(())
    }
}

/// Whether two addresses are the same host, ignoring the IPv4-mapped IPv6 form a
/// dual-stack socket reports.
pub fn same_host(a: IpAddr, b: IpAddr) -> bool {
    a.to_canonical() == b.to_canonical()
}

/// A PFCP request message type of TS 29.244 Table 7.3-1 (Rel-18).
pub fn is_request_type(t: u8) -> bool {
    matches!(t, 1 | 3 | 5 | 7 | 9 | 12 | 14 | 16 | 50 | 52 | 54 | 56)
}

/// A PFCP response message type of TS 29.244 Table 7.3-1 (Rel-18), including Version
/// Not Supported Response (11).
pub fn is_response_type(t: u8) -> bool {
    matches!(
        t,
        2 | 4 | 6 | 8 | 10 | 11 | 13 | 15 | 17 | 51 | 53 | 55 | 57
    )
}

/// The minimum interval between two refusal log lines.
pub const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Rate limit for "refused a PFCP message" log lines.
///
/// The first refusal is logged; after that at most one line per
/// [`REFUSAL_LOG_INTERVAL`], carrying how many refusals it stands for. Lock-free and
/// constant-size, so a flood cannot grow it.
#[derive(Debug, Default)]
pub struct RefusalLog {
    /// Milliseconds since the Unix epoch of the last logged line (0 = never).
    last_ms: AtomicU64,
    /// Refusals since the last logged line.
    suppressed: AtomicU64,
}

impl RefusalLog {
    /// A log with nothing logged yet.
    pub const fn new() -> Self {
        Self {
            last_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Record one refusal. Returns `Some(n)` when the caller should log now, `n` being
    /// how many earlier refusals went unlogged; `None` to stay quiet.
    pub fn note(&self) -> Option<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1)
            .max(1);
        self.note_at(now)
    }

    fn note_at(&self, now_ms: u64) -> Option<u64> {
        let last = self.last_ms.load(Ordering::Relaxed);
        let due =
            last == 0 || now_ms.saturating_sub(last) >= REFUSAL_LOG_INTERVAL.as_millis() as u64;
        if due
            && self
                .last_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_and_prefixes_match_on_the_ip_alone() {
        let a = PeerAllowlist::parse("172.23.0.4, 10.0.0.0/8 fd00::/64").unwrap();
        assert!(a.is_configured());
        assert!(a.permits(ip("172.23.0.4")));
        assert!(!a.permits(ip("172.23.0.5")));
        assert!(a.permits(ip("10.200.3.4")));
        assert!(!a.permits(ip("11.0.0.1")));
        assert!(a.permits(ip("fd00::1234")));
        assert!(!a.permits(ip("fd00:0:0:1::1")));
        // A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d.
        assert!(a.permits(ip("::ffff:172.23.0.4")));
        assert_eq!(a.to_string(), "172.23.0.4/32, 10.0.0.0/8, fd00::/64");
    }

    #[test]
    fn an_empty_allowlist_permits_no_one_and_any_is_explicit() {
        let a = PeerAllowlist::parse(" ").unwrap();
        assert!(!a.is_configured());
        assert!(!a.permits(ip("192.0.2.1")), "fail closed");
        assert!(!a.permits(ip("::1")));
        let any = PeerAllowlist::parse("0.0.0.0/0, ::/0").unwrap();
        assert!(any.permits(ip("192.0.2.1")));
        assert!(any.permits(ip("2001:db8::1")));
    }

    #[test]
    fn host_names_are_matched_on_their_last_resolution() {
        let a = PeerAllowlist::parse("smf-pfcp.nextg-system.svc.cluster.local").unwrap();
        assert!(a.is_configured());
        assert_eq!(a.hosts(), ["smf-pfcp.nextg-system.svc.cluster.local"]);
        assert!(!a.permits(ip("10.1.2.3")), "nothing resolved yet");
        let clone = a.clone();
        a.set_resolved(vec![ip("10.1.2.3")]);
        assert!(clone.permits(ip("10.1.2.3")), "clones share the resolution");
        assert!(!clone.permits(ip("10.1.2.4")));

        let local = PeerAllowlist::parse("localhost").unwrap();
        local.resolve_hosts();
        assert!(local.permits(ip("127.0.0.1")), "localhost resolves");
    }

    #[test]
    fn a_failed_lookup_keeps_the_last_good_addresses() {
        let a = PeerAllowlist::parse("smf-pfcp").unwrap();
        a.resolve_hosts_with(|_| Ok(vec![ip("10.1.2.3")]));
        assert!(a.permits(ip("10.1.2.3")));
        a.resolve_hosts_with(|_| Err(std::io::Error::other("SERVFAIL")));
        assert!(
            a.permits(ip("10.1.2.3")),
            "a DNS blip keeps the last addresses"
        );
        a.resolve_hosts_with(|_| Ok(vec![ip("10.1.2.4")]));
        assert!(!a.permits(ip("10.1.2.3")), "a real answer replaces them");
        assert!(a.permits(ip("10.1.2.4")));
    }

    #[test]
    fn a_kick_is_rate_limited_and_needs_a_host_name() {
        assert!(!PeerAllowlist::parse("10.0.0.1").unwrap().kick_refresh());
        let a = PeerAllowlist::parse("smf-pfcp").unwrap();
        assert!(a.kick_refresh(), "the first kick");
        assert!(
            !a.clone().kick_refresh(),
            "a second within the interval is dropped"
        );
    }

    /// #1112: one resolution per interval, shared by the kick and a caller that
    /// resolves before judging; none at all for an IP-only list. A resolution
    /// re-judges a stale address against the fresh answer, and a stranger stays
    /// refused after it.
    #[test]
    fn a_resolution_slot_is_rate_limited_and_refreshes_a_stale_address() {
        let new_pod = ip("10.10.15.26");
        let a = PeerAllowlist::parse("smf-pfcp.nextg.svc").unwrap();
        a.set_resolved(vec![ip("10.10.15.9")]);
        assert!(!a.permits(new_pod));
        assert!(a.try_begin_resolution(), "the first resolution");
        a.resolve_hosts_with(|_| Ok(vec![new_pod]));
        assert!(a.permits(new_pod), "judged against the fresh answer");
        assert!(!a.permits(ip("192.0.2.7")), "fail-closed after the lookup");
        assert!(!a.try_begin_resolution(), "rate-limited");
        assert!(!a.clone().kick_refresh(), "the kick shares the slot");
        assert!(!PeerAllowlist::parse("10.0.0.1")
            .unwrap()
            .try_begin_resolution());
    }

    /// A kick wakes the refresh thread before its interval: a name that resolves to
    /// a new address is admitted within the kick, not a full interval later.
    #[test]
    fn a_kick_re_resolves_before_the_interval() {
        let a = PeerAllowlist::parse("localhost").unwrap();
        a.spawn_host_refresh(Duration::from_secs(3600));
        // Simulate a stale resolution, then kick.
        a.per_host.lock().unwrap().clear();
        a.set_resolved(Vec::new());
        assert!(!a.permits(ip("127.0.0.1")));
        assert!(a.kick_refresh());
        let t0 = std::time::Instant::now();
        while !a.permits(ip("127.0.0.1")) {
            assert!(t0.elapsed() < Duration::from_secs(5), "not re-resolved");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn bad_entries_are_refused() {
        assert!(
            PeerAllowlist::parse("10.0.0.300").is_err(),
            "not an address, not a name"
        );
        assert!(PeerAllowlist::parse("smf/24").is_err());
        assert!(PeerAllowlist::parse("bad_name").is_err());
        assert!(PeerAllowlist::parse("10.0.0.0/33").is_err());
        assert!(PeerAllowlist::parse("::/129").is_err());
        assert!(PeerAllowlist::parse("10.0.0.0/x").is_err());
    }

    #[test]
    fn table_7_3_1_request_and_response_types() {
        for t in [1, 3, 5, 7, 9, 12, 14, 16, 50, 52, 54, 56] {
            assert!(is_request_type(t), "{t}");
            assert!(!is_response_type(t), "{t}");
        }
        for t in [2, 4, 6, 8, 10, 11, 13, 15, 17, 51, 53, 55, 57] {
            assert!(is_response_type(t), "{t}");
            assert!(!is_request_type(t), "{t}");
        }
        for t in [0, 18, 49, 58, 99, 254, 255] {
            assert!(!is_request_type(t) && !is_response_type(t), "{t}");
        }
    }

    #[test]
    fn the_refusal_log_speaks_once_per_interval_and_counts_the_rest() {
        let log = RefusalLog::new();
        let t0 = 1_000_000;
        assert_eq!(log.note_at(t0), Some(0), "the first refusal is logged");
        assert_eq!(log.note_at(t0 + 1), None);
        assert_eq!(log.note_at(t0 + 9_999), None);
        assert_eq!(log.note_at(t0 + 10_000), Some(2), "two were suppressed");
        assert_eq!(log.note_at(t0 + 10_001), None);
    }
}
