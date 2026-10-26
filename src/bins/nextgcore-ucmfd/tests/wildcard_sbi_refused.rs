//! #1322: ucmfd refuses to start on a wildcard SBI bind with nothing reachable to
//! advertise (before its listener starts), rather than hand peers 0.0.0.0 in a
//! URI. With an advertised host it starts.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn spawn(extra: &[&str]) -> Child {
    let dir = std::env::temp_dir().join(format!("ucmfd-1322-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Command::new(env!("CARGO_BIN_EXE_nextgcore-ucmfd"))
        .arg("-c")
        .arg(dir.join("absent.yaml"))
        .args(extra)
        .env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env_remove("NEXTGCORE_SBI_ADVERTISE")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ucmfd")
}

/// The exit status and stderr within `within`, or `None` if it is still running
/// (then killed).
fn exit_within(mut child: Child, within: Duration) -> Option<(std::process::ExitStatus, String)> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut err);
            }
            return Some((status, err));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn ucmfd_refuses_a_wildcard_sbi_bind_with_nothing_to_advertise() {
    // Port 1: were the check gone, the bind would fail (unprivileged), so no
    // wildcard is ever bound; the stderr says which check refused it.
    let (status, stderr) = exit_within(
        spawn(&["--sbi-addr", "0.0.0.0", "--sbi-port", "1"]),
        Duration::from_secs(20),
    )
    .expect("ucmfd exits instead of advertising 0.0.0.0");
    assert!(!status.success());
    assert!(stderr.contains("refusing to start"), "{stderr}");
}

/// The control: the same daemon on a loopback bind (advertised as itself) keeps running.
#[test]
fn ucmfd_starts_on_a_bind_it_can_advertise() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let status = exit_within(
        spawn(&["--sbi-addr", "127.0.0.1", "--sbi-port", &port]),
        Duration::from_secs(3),
    );
    assert!(status.is_none(), "ucmfd exited: {status:?}");
}
