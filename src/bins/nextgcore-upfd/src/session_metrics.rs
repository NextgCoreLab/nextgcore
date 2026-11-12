//! `--session-metrics`: per-session byte counters on `/metrics` (#1455).
//!
//! `DataPlaneSession` has always counted its forwarded inner bytes (`ul_bytes`,
//! `dl_bytes`); this renders them as `upf_session_ul_bytes_total` and
//! `upf_session_dl_bytes_total`, one series per live session.
//!
//! Off by default, and then `/metrics` is byte-identical to before. When on, a
//! series is labelled by the UPF SEID (`seid="0x.."`, the form upfd logs), and in
//! `seid-ue-ip` mode also by the UE's IPv4 address, for a deployment that must join
//! a session to the source address a DN server saw. Never by SUPI: the UPF does
//! not hold one (TS 29.244 carries none), and resolving a UE address to a
//! subscriber is the NEF's job. The series count is bounded by `--max-sessions`.

use crate::data_plane::DataPlaneSession;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// What `/metrics` shows per session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Nothing (the default).
    Off,
    /// `{seid}`.
    Seid,
    /// `{seid, ue_ipv4}`.
    SeidUeIp,
}

impl Mode {
    /// The `--session-metrics` setting: the flag, else `UPF_SESSION_METRICS`, else
    /// `off`. An unknown value is an error, so a typo does not silently disable it.
    pub fn setting(flag: Option<&str>, env: Option<String>) -> Result<Self, String> {
        let value = match flag {
            Some(f) => f.to_string(),
            None => env.unwrap_or_default(),
        };
        match value.trim() {
            "" | "off" => Ok(Self::Off),
            "seid" => Ok(Self::Seid),
            "seid-ue-ip" => Ok(Self::SeidUeIp),
            other => Err(format!(
                "--session-metrics '{other}' is not one of off, seid, seid-ue-ip"
            )),
        }
    }
}

/// The process's mode, set once at startup. Test lock: [`MODE_TEST_LOCK`].
static MODE: AtomicU8 = AtomicU8::new(0);

/// Serialises the tests that set [`MODE`] (declared beside it).
#[cfg(test)]
pub static MODE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn set_mode(mode: Mode) {
    MODE.store(
        match mode {
            Mode::Off => 0,
            Mode::Seid => 1,
            Mode::SeidUeIp => 2,
        },
        Ordering::Relaxed,
    );
}

pub fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        1 => Mode::Seid,
        2 => Mode::SeidUeIp,
        _ => Mode::Off,
    }
}

/// The two families for `sessions` in `mode`; empty when `Off`. Sorted by SEID
/// so a scrape is stable.
pub fn render(mode: Mode, sessions: &[Arc<DataPlaneSession>]) -> String {
    if mode == Mode::Off {
        return String::new();
    }
    let mut sessions: Vec<&Arc<DataPlaneSession>> = sessions.iter().collect();
    sessions.sort_by_key(|s| s.upf_seid);
    let labels = |s: &DataPlaneSession| match (mode, s.ue_ipv4) {
        (Mode::SeidUeIp, Some(ip)) => format!("seid=\"0x{:x}\",ue_ipv4=\"{ip}\"", s.upf_seid),
        _ => format!("seid=\"0x{:x}\"", s.upf_seid),
    };
    let mut out = String::new();
    for (name, help, ul) in [
        (
            "upf_session_ul_bytes_total",
            "Inner IP bytes of the uplink packets of one PFCP session written to the TUN",
            true,
        ),
        (
            "upf_session_dl_bytes_total",
            "Inner IP bytes of the downlink packets of one PFCP session sent as G-PDUs",
            false,
        ),
    ] {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
        for s in &sessions {
            let v = if ul { &s.ul_bytes } else { &s.dl_bytes }.load(Ordering::Relaxed);
            out.push_str(&format!("{name}{{{}}} {v}\n", labels(s)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn session(seid: u64, ip: Option<Ipv4Addr>, ul: u64, dl: u64) -> Arc<DataPlaneSession> {
        let s = DataPlaneSession::new_empty(
            seid,
            7,
            ip,
            0x100 + seid as u32,
            0x200,
            SocketAddr::from(([127, 0, 0, 1], 2152)),
            Some(1),
            Some(9),
        );
        s.ul_bytes.store(ul, Ordering::Relaxed);
        s.dl_bytes.store(dl, Ordering::Relaxed);
        Arc::new(s)
    }

    #[test]
    fn off_renders_nothing() {
        let s = [session(1, Some(Ipv4Addr::new(10, 45, 0, 2)), 5, 6)];
        assert_eq!(render(Mode::Off, &s), "");
    }

    #[test]
    fn seid_mode_labels_by_seid_only() {
        let s = [
            session(0x2a, Some(Ipv4Addr::new(10, 45, 0, 3)), 1500, 40),
            session(0x07, Some(Ipv4Addr::new(10, 45, 0, 2)), 84, 0),
        ];
        let body = render(Mode::Seid, &s);
        assert_eq!(
            body,
            "# HELP upf_session_ul_bytes_total Inner IP bytes of the uplink packets of one PFCP session written to the TUN\n\
             # TYPE upf_session_ul_bytes_total counter\n\
             upf_session_ul_bytes_total{seid=\"0x7\"} 84\n\
             upf_session_ul_bytes_total{seid=\"0x2a\"} 1500\n\
             # HELP upf_session_dl_bytes_total Inner IP bytes of the downlink packets of one PFCP session sent as G-PDUs\n\
             # TYPE upf_session_dl_bytes_total counter\n\
             upf_session_dl_bytes_total{seid=\"0x7\"} 0\n\
             upf_session_dl_bytes_total{seid=\"0x2a\"} 40\n"
        );
        assert!(!body.contains("10.45."), "no address in seid mode");
    }

    #[test]
    fn seid_ue_ip_mode_adds_the_ue_address() {
        let s = [
            session(3, Some(Ipv4Addr::new(10, 45, 0, 9)), 10, 20),
            session(4, None, 1, 2),
        ];
        let body = render(Mode::SeidUeIp, &s);
        assert!(
            body.contains("upf_session_ul_bytes_total{seid=\"0x3\",ue_ipv4=\"10.45.0.9\"} 10\n")
        );
        assert!(
            body.contains("upf_session_dl_bytes_total{seid=\"0x3\",ue_ipv4=\"10.45.0.9\"} 20\n")
        );
        assert!(
            body.contains("upf_session_ul_bytes_total{seid=\"0x4\"} 1\n"),
            "a session without an IPv4 address keeps the seid label alone: {body}"
        );
    }

    #[test]
    fn the_setting_is_off_by_default_and_refuses_unknown_values() {
        assert_eq!(Mode::setting(None, None), Ok(Mode::Off));
        assert_eq!(Mode::setting(None, Some("seid".into())), Ok(Mode::Seid));
        assert_eq!(
            Mode::setting(Some("seid-ue-ip"), Some("off".into())),
            Ok(Mode::SeidUeIp)
        );
        assert_eq!(
            Mode::setting(Some("off"), Some("seid".into())),
            Ok(Mode::Off)
        );
        assert!(Mode::setting(Some("supi"), None).is_err());
    }
}
