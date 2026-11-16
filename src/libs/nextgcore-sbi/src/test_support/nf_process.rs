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
//! - on a lost bind (the OS's "Address already in use" in the child's stderr,
//!   whether the child exited or not) it spawns again with fresh ports;
//! - on any other exit it fails at once and prints the child's stderr.

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
    /// so in-process stubs on the same runtime keep running.
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
        };
        run.next_attempt();
        run
    }
}

/// One spawn in progress.
struct Attempt {
    nf: NfProcess,
    deadline: Instant,
}

struct Run<F> {
    spec: NfSpawn,
    configure: F,
    base: PathBuf,
    attempt: usize,
    current: Option<Attempt>,
}

impl<F: FnMut(&mut Command, u16, &Path)> Run<F> {
    fn next_attempt(&mut self) {
        // Drop (kill, reap, clean up) the previous child first: it may still
        // hold the ports a fresh probe could be handed.
        self.current = None;
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
        (self.configure)(&mut cmd, port, &dir);
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
            },
            deadline: Instant::now() + self.spec.within,
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
        if log.contains(ADDR_IN_USE) {
            // Lost a port, fatally or not: start over on fresh ones.
            self.next_attempt();
            return None;
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
            return self.current.take().map(|a| a.nf);
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
