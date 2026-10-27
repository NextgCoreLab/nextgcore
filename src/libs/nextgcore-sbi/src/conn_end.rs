//! How an HTTP/2 connection driver's end is reported (#1338).
//!
//! Both ends of the SBI spawn a task that drives one hyper HTTP/2 connection to
//! completion. That task used to `eprintln!` any error as
//! `HTTP/2 connection error: {e}`, and hyper's `Display` for an I/O-kind error is
//! the bare string `connection error`: no level, no timestamp, no peer, no cause.
//!
//! On a pod with a kubelet `tcpSocket` probe on the SBI port (the Helm chart's
//! `nextgcore.sbiProbes`: readiness every 10 s, liveness every 30 s, so four
//! probes per 30 s) each probe connects and closes without sending the HTTP/2
//! preface. h2 reports that as `UnexpectedEof` ("connection closed before reading
//! preface"), which is the one line every NF printed every 7.5 s.
//!
//! The rule here: a peer that ended the connection in order (EOF, or a GOAWAY
//! with `NO_ERROR`) is `debug`, anything else is `warn`, and both name the peer
//! and the full cause chain.

use std::error::Error as StdError;
use std::io;

/// How a connection driver ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnEnd {
    /// The peer closed the connection in order: a clean EOF (including a TCP
    /// health probe that never sent the preface), or a GOAWAY with `NO_ERROR`
    /// it sent.
    PeerClosed,
    /// A genuine transport or protocol failure.
    Failed,
}

/// Classify a hyper connection error by walking its cause chain.
pub(crate) fn classify(err: &hyper::Error) -> ConnEnd {
    let mut cause: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(e) = cause {
        if let Some(io) = e.downcast_ref::<io::Error>() {
            return classify_io(io);
        }
        if let Some(h2) = e.downcast_ref::<h2::Error>() {
            if h2.is_go_away() && h2.is_remote() && h2.reason() == Some(h2::Reason::NO_ERROR) {
                return ConnEnd::PeerClosed;
            }
            if let Some(io) = h2.get_io() {
                return classify_io(io);
            }
            return ConnEnd::Failed;
        }
        cause = e.source();
    }
    ConnEnd::Failed
}

/// An I/O cause is an orderly close only when it is how h2 reports a peer's
/// EOF:
///
/// * `UnexpectedEof`: the server side, a connection closed before the HTTP/2
///   preface (h2 `server.rs`, "connection closed before reading preface").
/// * `BrokenPipe` with no OS error code: the client side, h2's synthetic
///   "connection closed because of a broken pipe" on reading EOF
///   (`Streams::recv_eof`). A real `EPIPE` from a write carries errno 32 and
///   stays a failure, as does a reset, a timeout, or anything else.
fn classify_io(io: &io::Error) -> ConnEnd {
    match io.kind() {
        io::ErrorKind::UnexpectedEof => ConnEnd::PeerClosed,
        io::ErrorKind::BrokenPipe if io.raw_os_error().is_none() => ConnEnd::PeerClosed,
        _ => ConnEnd::Failed,
    }
}

/// `err` and every cause under it, joined with `: `. hyper's own `Display`
/// stops at `connection error`, which is what made the old line useless.
fn chain(err: &hyper::Error) -> String {
    let mut out = err.to_string();
    let mut cause = err.source();
    while let Some(e) = cause {
        out.push_str(": ");
        out.push_str(&e.to_string());
        cause = e.source();
    }
    out
}

/// Log the end of an HTTP/2 connection driver. `what` names this end (e.g.
/// `"SBI client HTTP/2"`), `peer` is the remote `host:port`.
pub(crate) fn log_conn_end(what: &str, peer: &str, err: &hyper::Error) -> ConnEnd {
    let end = classify(err);
    match end {
        ConnEnd::PeerClosed => {
            log::debug!(
                "{what} connection with {peer} closed by peer: {}",
                chain(err)
            )
        }
        ConnEnd::Failed => log::warn!("{what} connection with {peer} failed: {}", chain(err)),
    }
    end
}

/// The same rule for a TLS accept that failed before HTTP/2 started: a peer
/// that closed before finishing the handshake (a `tcpSocket` probe on an `https`
/// SBI port) is `debug`, any other handshake failure is `warn`.
pub(crate) fn log_tls_accept_error(peer: &str, err: &io::Error) {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        log::debug!("SBI server TLS accept from {peer}: peer closed before the handshake: {err}");
    } else {
        log::warn!("SBI server TLS accept from {peer} failed: {err}");
    }
}
