//! Spawn a real NF binary on a probed port and wait until it is serving (#1521).
//!
//! A [`free_port`](super::free_port) port is free when it is probed, but nothing
//! holds it afterwards. Only this process's own `free_port()` and
//! `bound_listener()` calls are kept off it. A sibling process connecting out,
//! such as another test's NF dialling its stub NRF, is given an ephemeral source
//! port from the same range, and can take the number before the spawned NF binds
//! it (#1497).
//!
//! For most NFs a lost SBI bind is fatal: the child exits, and a test that
//! "waits for the subscription" waits out its whole timeout for a process that is
//! gone. Some binds are not fatal (pcfd's metrics listener, pcrfd's Diameter
//! listener): the child keeps running without the socket, and the test times out
//! scraping or connecting.
//!
//! [`NfSpawn`] answers both, as #1520 did for one pcfd test:
//! - it waits until the child is ready (a log line, or a TCP accept);
//! - on a lost bind of a port THIS spawn chose (the OS's "Address already in
//!   use" in the child's stderr, whether the child exited or not) it spawns
//!   again with fresh ports;
//! - an in-use error naming any other port (a fixed default such as the 9090
//!   metrics port, held by something outside the test) fails at once and says
//!   which port: respawning cannot help, and pinning the port can (#1575
//!   review);
//! - on any other exit it fails at once and prints the child's stderr.
//!
//! A port "this spawn chose" is the one handed to `configure`, plus any
//! `configure` draws with [`spawn_port`]. An in-use line that names no port
//! (pcfd's SBI bind error carries none) is taken as the spawn's own.

use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// What the OS says when a bind loses its port (`io::ErrorKind::AddrInUse`'s
/// message on Linux and macOS). It reaches the child's stderr however the NF
/// words the error around it.
pub const ADDR_IN_USE: &str = "Address already in use";

/// A port on `ip` that is free now, recorded like [`free_port`](super::free_port)'s
/// so this process does not hand it out twice. For a non-default loopback
/// address such as `127.0.0.2`.
///
/// # Panics
///
/// If `ip` cannot be bound, or 256 probes all return issued ports.
pub fn free_port_on(ip: IpAddr) -> u16 {
    if ip == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return super::free_port();
    }
    for _ in 0..256 {
        let probe = TcpListener::bind((ip, 0)).expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if super::issued_ports()
            .lock()
            .expect("issued lock")
            .insert(port)
        {
            return port;
        }
    }
    panic!("could not obtain an unused port on {ip} in 256 attempts");
}

thread_local! {
    /// The ports the `configure` call running on this thread has claimed with
    /// [`spawn_port`]; `None` outside a `configure` call.
    static CLAIMED: std::cell::RefCell<Option<Vec<u16>>> = const { std::cell::RefCell::new(None) };
}

/// Draw a loopback port for a SECOND listener of the NF being spawned (a
/// metrics port, a second interface) and claim it for this spawn, so a lost
/// bind of it is respawned rather than reported as someone else's port.
///
/// Call it inside an [`NfSpawn`] `configure` closure; each respawn calls
/// `configure` again and so draws a fresh one.
///
/// # Panics
///
/// Outside a `configure` call.
pub fn spawn_port() -> u16 {
    claim_port(super::free_port())
}

/// Claim `port`, chosen by the caller, for the spawn whose `configure` is
/// running: an in-use error naming it is respawned like the spawn's own port.
/// For the helper's own tests, which hand the NF a port they hold.
///
/// # Panics
///
/// Outside a `configure` call.
pub fn claim_port(port: u16) -> u16 {
    CLAIMED.with(|c| {
        c.borrow_mut()
            .as_mut()
            .expect("spawn_port() is only for an NfSpawn configure closure")
            .push(port)
    });
    port
}

/// The ports an "Address already in use" line names: `a.b.c.d:PORT` or
/// `[v6]:PORT`. A timestamp's `T03:24:10` is not one: what precedes its colon
/// has no dots.
fn ports_named(line: &str) -> Vec<u16> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    for (i, &c) in b.iter().enumerate() {
        if c != b':' || i == 0 {
            continue;
        }
        let digits: String = line[i + 1..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.is_empty() {
            continue;
        }
        let host_ok = if b[i - 1] == b']' {
            true
        } else {
            let start = line[..i]
                .rfind(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
                .map_or(0, |k| k + 1);
            line[start..i].matches('.').count() == 3
        };
        if let (true, Ok(port)) = (host_ok, digits.parse::<u16>()) {
            out.push(port);
        }
    }
    out
}

/// What an "Address already in use" in the child's stderr means for this spawn.
#[derive(Debug, PartialEq, Eq)]
enum InUse {
    /// None in the stderr.
    No,
    /// A port this spawn chose, or a line that names no port: respawn.
    Ours,
    /// A port this spawn did not choose: fail, quoting the line.
    Foreign(String),
}

fn in_use(log: &str, claimed: &[u16]) -> InUse {
    let mut seen = InUse::No;
    for line in log.lines().filter(|l| l.contains(ADDR_IN_USE)) {
        let ports = ports_named(line);
        if ports.is_empty() || ports.iter().any(|p| claimed.contains(p)) {
            seen = InUse::Ours;
        } else {
            return InUse::Foreign(line.to_string());
        }
    }
    seen
}

/// When a spawned NF counts as ready: every condition set holds.
#[derive(Debug, Clone, Default)]
struct Ready {
    /// Every one of these lines is in its stderr.
    logged: Vec<String>,
    /// `ip:port` accepts a TCP connection.
    accepting: Option<IpAddr>,
    /// `ip:port` is held by a UDP socket (a bind of it fails).
    udp_bound: Option<IpAddr>,
}

/// A real NF process started by [`NfSpawn`].
///
/// On drop it is killed and reaped. Its scratch directory (config files, stderr)
/// is removed. If the thread is panicking, its stderr is printed first, so a
/// failed test shows why the NF did what it did.
#[derive(Debug)]
pub struct NfProcess {
    child: Child,
    port: u16,
    dir: PathBuf,
    log: PathBuf,
    replaced: Vec<u32>,
}

impl NfProcess {
    /// The port the NF was configured with on the spawn that became ready.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The NF's stderr so far.
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The file the NF's stderr goes to.
    pub fn log_path(&self) -> &Path {
        &self.log
    }

    /// The per-spawn scratch directory, which holds `configure`'s files.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The PIDs of the earlier spawns this one replaced after a lost bind. Each
    /// was killed and reaped before its replacement started.
    pub fn replaced_pids(&self) -> &[u32] {
        &self.replaced
    }

    /// The child, e.g. to signal it or wait for its exit.
    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for NfProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "--- {} stderr ---\n{}",
                self.dir.display(),
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// How to spawn an NF binary and when it is ready. See the [module docs](self).
///
/// ```ignore
/// let nf = NfSpawn::new(env!("CARGO_BIN_EXE_nextgcore-pcfd"), "pcfd-1458")
///     .ready_when_logged("SBI HTTP/2 server listening on")
///     .spawn_async(|cmd, sbi_port, dir| {
///         let config = dir.join("pcf.yaml");
///         std::fs::write(&config, format!("... port: {sbi_port} ...")).unwrap();
///         cmd.arg("-c").arg(config);
///     })
///     .await;
/// ```
#[derive(Debug, Clone)]
pub struct NfSpawn {
    program: PathBuf,
    tag: String,
    ready: Ready,
    first_port: Option<u16>,
    port_ip: IpAddr,
    attempts: usize,
    within: Duration,
    pause_after_exit_check: Duration,
}

impl NfSpawn {
    /// Spawn `program`. `tag` names the scratch directory and the failure
    /// messages; make it unique per test.
    ///
    /// The defaults are: ready on the stderr line `"listening on"`; ports from
    /// [`free_port`](super::free_port) on 127.0.0.1; 5 spawns; 30 s for each
    /// to become ready.
    pub fn new(program: impl AsRef<OsStr>, tag: &str) -> Self {
        NfSpawn {
            program: PathBuf::from(program.as_ref()),
            tag: tag.to_string(),
            ready: Ready::default(),
            first_port: None,
            port_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            attempts: 5,
            within: Duration::from_secs(30),
            pause_after_exit_check: Duration::ZERO,
        }
    }

    /// Ready once `line` is in the NF's stderr. Repeat it to require several
    /// lines (an NF with two listeners). Combines with
    /// [`NfSpawn::ready_when_accepting`]: every condition must hold.
    pub fn ready_when_logged(mut self, line: &str) -> Self {
        self.ready.logged.push(line.to_string());
        self
    }

    /// Ready once `ip:port` accepts a TCP connection, for an NF that logs
    /// nothing at the moment it binds. Ports are then drawn on `ip`.
    ///
    /// This shows that SOMETHING accepts on `ip:port`, not that it is the child.
    /// Pair it with [`NfSpawn::ready_when_logged`] where the NF logs its bind.
    pub fn ready_when_accepting(mut self, ip: IpAddr) -> Self {
        self.ready.accepting = Some(ip);
        self.port_ip = ip;
        self
    }

    /// Ready once `ip:port` is held by a UDP socket (binding it here fails), for
    /// a UDP listener such as amfd's SCTP-over-UDP NGAP. Ports are then drawn
    /// on `ip`.
    pub fn ready_when_udp_bound(mut self, ip: IpAddr) -> Self {
        self.ready.udp_bound = Some(ip);
        self.port_ip = ip;
        self
    }

    /// Use `port` for the first spawn instead of a probed one. For the helper's
    /// own tests, which hold it to force a lost bind.
    pub fn first_port(mut self, port: u16) -> Self {
        self.first_port = Some(port);
        self
    }

    /// How long each spawn has to become ready.
    pub fn within(mut self, within: Duration) -> Self {
        self.within = within;
        self
    }

    /// Pause between asking whether the child exited and reading its stderr.
    /// For the helper's own tests, to widen the window #1520's review found.
    pub fn pause_after_exit_check(mut self, pause: Duration) -> Self {
        self.pause_after_exit_check = pause;
        self
    }

    /// Spawn and block until ready. For a `#[test]`.
    ///
    /// `configure(cmd, port, dir)` runs once per spawn, on a fresh `Command`. It
    /// gets the port to put the NF's listener on, and the scratch directory for
    /// config files. Draw any OTHER port (metrics, a second listener) inside it,
    /// so a respawn after a lost bind gets fresh ones too. stdout is discarded.
    /// stderr is captured; set `RUST_LOG` in `configure` to change the default
    /// `info`.
    ///
    /// # Panics
    ///
    /// - The NF exits for any reason but a lost bind (its stderr is printed).
    /// - It is not ready within the timeout.
    /// - It loses its bind on every attempt.
    pub fn spawn(self, configure: impl FnMut(&mut Command, u16, &Path)) -> NfProcess {
        let mut run = self.start(configure);
        loop {
            match run.poll() {
                Some(nf) => return nf,
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// [`NfSpawn::spawn`] for an async test: waits with `tokio::time::sleep`,
    /// so in-process stubs on the same runtime keep running. Each poll itself
    /// blocks briefly (a readiness connect is bounded at 100 ms), so on a
    /// current-thread runtime the stubs pause for that long once per poll.
    pub async fn spawn_async(self, configure: impl FnMut(&mut Command, u16, &Path)) -> NfProcess {
        let mut run = self.start(configure);
        loop {
            match run.poll() {
                Some(nf) => return nf,
                None => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }

    fn start<F: FnMut(&mut Command, u16, &Path)>(self, configure: F) -> Run<F> {
        let base =
            std::env::temp_dir().join(format!("nf-spawn-{}-{}", self.tag, std::process::id()));
        let mut run = Run {
            spec: self,
            configure,
            base,
            attempt: 0,
            current: None,
            replaced: Vec::new(),
        };
        run.next_attempt();
        run
    }
}

/// One spawn in progress.
struct Attempt {
    nf: NfProcess,
    deadline: Instant,
    claimed: Vec<u16>,
}

struct Run<F> {
    spec: NfSpawn,
    configure: F,
    base: PathBuf,
    attempt: usize,
    current: Option<Attempt>,
    replaced: Vec<u32>,
}

impl<F: FnMut(&mut Command, u16, &Path)> Run<F> {
    fn next_attempt(&mut self) {
        // Drop (kill, reap, clean up) the previous child first: it may still
        // hold the ports a fresh probe could be handed.
        if let Some(old) = self.current.take() {
            self.replaced.push(old.nf.child.id());
        }
        if self.attempt == self.spec.attempts {
            panic!(
                "{}: lost its listening port on all {} spawns",
                self.spec.tag, self.spec.attempts
            );
        }
        self.attempt += 1;
        let port = match (self.attempt, self.spec.first_port) {
            (1, Some(p)) => p,
            _ => free_port_on(self.spec.port_ip),
        };
        let dir = PathBuf::from(format!("{}-{}", self.base.display(), self.attempt));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let log = dir.join("stderr.log");
        let mut cmd = Command::new(&self.spec.program);
        cmd.env("RUST_LOG", "info");
        CLAIMED.with(|c| *c.borrow_mut() = Some(vec![port]));
        (self.configure)(&mut cmd, port, &dir);
        let claimed = CLAIMED.with(|c| c.borrow_mut().take()).unwrap_or_default();
        cmd.stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).expect("stderr file"));
        let child = cmd.spawn().unwrap_or_else(|e| {
            panic!(
                "{}: spawn {}: {e}",
                self.spec.tag,
                self.spec.program.display()
            )
        });
        self.current = Some(Attempt {
            nf: NfProcess {
                child,
                port,
                dir,
                log,
                replaced: Vec::new(),
            },
            deadline: Instant::now() + self.spec.within,
            claimed,
        });
    }

    /// One look at the child. `Some` once it is ready.
    fn poll(&mut self) -> Option<NfProcess> {
        let cur = self.current.as_mut().expect("an attempt in progress");
        // Exit status FIRST, then stderr (#1520 review): once the child has
        // exited its stderr is complete, so a bind error printed just before
        // the exit cannot be missed by a read that came first.
        let exited: Option<ExitStatus> = cur.nf.child.try_wait().expect("try_wait");
        if !self.spec.pause_after_exit_check.is_zero() {
            std::thread::sleep(self.spec.pause_after_exit_check);
        }
        let log = cur.nf.log();
        match in_use(&log, &cur.claimed) {
            InUse::No => {}
            // Lost one of our ports, fatally or not: start over on fresh ones.
            InUse::Ours => {
                self.next_attempt();
                return None;
            }
            InUse::Foreign(line) => panic!(
                "{}: a port this spawn did not choose is in use by another process, \
                 so a respawn would hit it again; pin it in `configure` (e.g. \
                 <NF>_METRICS_PORT=0, or spawn_port()): {line}",
                self.spec.tag
            ),
        }
        if let Some(status) = exited {
            // Fail now, with the reason, rather than wait out a timeout. The
            // NfProcess dropped while panicking prints the child's stderr.
            panic!("{} exited at startup ({status})", self.spec.tag);
        }
        let r = &self.spec.ready;
        let logged = if r.logged.is_empty() && r.accepting.is_none() && r.udp_bound.is_none() {
            log.contains("listening on")
        } else {
            r.logged.iter().all(|l| log.contains(l.as_str()))
        };
        let ready = logged
            && r.accepting.is_none_or(|ip| {
                TcpStream::connect_timeout(
                    &SocketAddr::new(ip, cur.nf.port),
                    Duration::from_millis(100),
                )
                .is_ok()
            })
            && r.udp_bound.is_none_or(|ip| {
                std::net::UdpSocket::bind(SocketAddr::new(ip, cur.nf.port)).is_err()
            });
        if ready {
            return self.current.take().map(|a| {
                let mut nf = a.nf;
                nf.replaced = std::mem::take(&mut self.replaced);
                nf
            });
        }
        if Instant::now() >= cur.deadline {
            panic!(
                "{} not ready within {:?} (spawn {})",
                self.spec.tag, self.spec.within, self.attempt
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ports_an_in_use_line_names() {
        assert_eq!(
            ports_named(
                "[2026-11-16T03:24:10.810Z WARN  m] PCF metrics endpoint on 127.0.0.1:9090 \
                 not available: Address already in use (os error 98)"
            ),
            vec![9090]
        );
        assert_eq!(ports_named("listen [::1]:7777 failed"), vec![7777]);
        assert!(
            ports_named("Error: Failed to bind: Address already in use (os error 98)").is_empty()
        );
        assert!(ports_named("at T03:24:10 and 1.2:5").is_empty());
    }

    #[test]
    fn an_in_use_line_is_ours_only_for_a_claimed_or_unnamed_port() {
        let ours = "Error: Failed to bind: Address already in use (os error 98)";
        let metrics = "metrics endpoint on 127.0.0.1:9090 not available: Address already in use";
        assert_eq!(in_use("all fine", &[1]), InUse::No);
        assert_eq!(in_use(ours, &[1]), InUse::Ours);
        assert_eq!(in_use(metrics, &[9090]), InUse::Ours);
        assert_eq!(in_use(metrics, &[1]), InUse::Foreign(metrics.to_string()));
    }

    #[test]
    #[should_panic(expected = "only for an NfSpawn configure closure")]
    fn spawn_port_outside_configure_panics() {
        let _ = spawn_port();
    }
}
