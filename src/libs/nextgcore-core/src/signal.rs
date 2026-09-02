//! Signal handling utilities
//!
//! Exact port of lib/core/nextgcore-signal.h and nextgcore-signal.c

use std::sync::OnceLock;

use crate::errno::{NEXTGCORE_ERROR, NEXTGCORE_OK};

/// Number of signals
#[cfg(target_os = "linux")]
const NEXTGCORE_NUMSIG: usize = 65;
#[cfg(target_os = "macos")]
const NEXTGCORE_NUMSIG: usize = 32;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const NEXTGCORE_NUMSIG: usize = 33;

/// Signal descriptions
static SIGNAL_DESCRIPTIONS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Signal function type
pub type NextgcoreSigfunc = fn(i32);

/// Initialize signal descriptions (identical to nextgcore_signal_init)
pub fn nextgcore_signal_init() {
    SIGNAL_DESCRIPTIONS.get_or_init(|| {
        let mut descriptions = vec!["unknown signal (number)"; NEXTGCORE_NUMSIG];

        descriptions[0] = "Signal 0";

        #[cfg(unix)]
        {
            use libc::*;

            if (SIGHUP as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGHUP as usize] = "Hangup";
            }
            if (SIGINT as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGINT as usize] = "Interrupt";
            }
            if (SIGQUIT as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGQUIT as usize] = "Quit";
            }
            if (SIGILL as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGILL as usize] = "Illegal instruction";
            }
            if (SIGTRAP as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGTRAP as usize] = "Trace/BPT trap";
            }
            if (SIGABRT as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGABRT as usize] = "Abort";
            }
            if (SIGFPE as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGFPE as usize] = "Arithmetic exception";
            }
            if (SIGKILL as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGKILL as usize] = "Killed";
            }
            if (SIGBUS as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGBUS as usize] = "Bus error";
            }
            if (SIGSEGV as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGSEGV as usize] = "Segmentation fault";
            }
            if (SIGSYS as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGSYS as usize] = "Bad system call";
            }
            if (SIGPIPE as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGPIPE as usize] = "Broken pipe";
            }
            if (SIGALRM as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGALRM as usize] = "Alarm clock";
            }
            if (SIGTERM as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGTERM as usize] = "Terminated";
            }
            if (SIGUSR1 as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGUSR1 as usize] = "User defined signal 1";
            }
            if (SIGUSR2 as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGUSR2 as usize] = "User defined signal 2";
            }
            if (SIGCHLD as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGCHLD as usize] = "Child status change";
            }
            #[cfg(target_os = "linux")]
            if (SIGPWR as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGPWR as usize] = "Power-fail restart";
            }
            if (SIGWINCH as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGWINCH as usize] = "Window changed";
            }
            if (SIGURG as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGURG as usize] = "urgent socket condition";
            }
            #[cfg(target_os = "linux")]
            if (SIGPOLL as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGPOLL as usize] = "Pollable event occurred";
            }
            if (SIGIO as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGIO as usize] = "socket I/O possible";
            }
            if (SIGSTOP as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGSTOP as usize] = "Stopped (signal)";
            }
            if (SIGTSTP as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGTSTP as usize] = "Stopped";
            }
            if (SIGCONT as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGCONT as usize] = "Continued";
            }
            if (SIGTTIN as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGTTIN as usize] = "Stopped (tty input)";
            }
            if (SIGTTOU as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGTTOU as usize] = "Stopped (tty output)";
            }
            if (SIGVTALRM as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGVTALRM as usize] = "virtual timer expired";
            }
            if (SIGPROF as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGPROF as usize] = "profiling timer expired";
            }
            if (SIGXCPU as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGXCPU as usize] = "exceeded cpu limit";
            }
            if (SIGXFSZ as usize) < NEXTGCORE_NUMSIG {
                descriptions[SIGXFSZ as usize] = "exceeded file size limit";
            }
        }

        descriptions
    });
}

/// Get signal description (identical to nextgcore_signal_description_get)
pub fn nextgcore_signal_description_get(signum: i32) -> &'static str {
    let descriptions = SIGNAL_DESCRIPTIONS.get_or_init(|| {
        nextgcore_signal_init();
        SIGNAL_DESCRIPTIONS
            .get()
            .expect("signal init completed")
            .clone()
    });

    if signum >= 0 && (signum as usize) < descriptions.len() {
        descriptions[signum as usize]
    } else {
        "unknown signal (number)"
    }
}

/// Set up signal handling for threads (identical to nextgcore_setup_signal_thread)
#[cfg(unix)]
pub fn nextgcore_setup_signal_thread() -> i32 {
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigfillset(sig_mask.as_mut_ptr());

        // Remove synchronous signals that cannot be blocked
        remove_sync_sigs(sig_mask.as_mut_ptr());

        let rv = libc::pthread_sigmask(libc::SIG_SETMASK, sig_mask.as_ptr(), std::ptr::null_mut());

        if rv != 0 {
            return NEXTGCORE_ERROR;
        }
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_setup_signal_thread() -> i32 {
    NEXTGCORE_OK
}

/// Remove synchronous signals from mask
#[cfg(unix)]
unsafe fn remove_sync_sigs(sig_mask: *mut libc::sigset_t) {
    libc::sigdelset(sig_mask, libc::SIGABRT);
    libc::sigdelset(sig_mask, libc::SIGBUS);
    libc::sigdelset(sig_mask, libc::SIGFPE);
    libc::sigdelset(sig_mask, libc::SIGILL);
    libc::sigdelset(sig_mask, libc::SIGSEGV);
    libc::sigdelset(sig_mask, libc::SIGSYS);
    libc::sigdelset(sig_mask, libc::SIGTRAP);
    // Note: SIGPIPE is NOT removed (NextGCore ignores SIGPIPE)
}

/// Signal thread that waits for signals (identical to nextgcore_signal_thread)
#[cfg(unix)]
pub fn nextgcore_signal_thread<F>(signal_handler: F) -> i32
where
    F: Fn(i32) -> i32,
{
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigfillset(sig_mask.as_mut_ptr());

        // Remove unblockable signals
        libc::sigdelset(sig_mask.as_mut_ptr(), libc::SIGKILL);
        libc::sigdelset(sig_mask.as_mut_ptr(), libc::SIGSTOP);
        libc::sigdelset(sig_mask.as_mut_ptr(), libc::SIGCONT);

        // Remove synchronous signals
        remove_sync_sigs(sig_mask.as_mut_ptr());

        loop {
            let mut signal_received: i32 = 0;
            let rv = libc::sigwait(sig_mask.as_ptr(), &mut signal_received);

            if rv != 0 {
                continue;
            }

            if signal_handler(signal_received) == 1 {
                return NEXTGCORE_OK;
            }
        }
    }
}

#[cfg(not(unix))]
pub fn nextgcore_signal_thread<F>(_signal_handler: F) -> i32
where
    F: Fn(i32) -> i32,
{
    NEXTGCORE_ERROR
}

/// Block a signal (identical to nextgcore_signal_block)
#[cfg(unix)]
pub fn nextgcore_signal_block(signum: i32) -> i32 {
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigemptyset(sig_mask.as_mut_ptr());
        libc::sigaddset(sig_mask.as_mut_ptr(), signum);

        let rv = libc::pthread_sigmask(libc::SIG_BLOCK, sig_mask.as_ptr(), std::ptr::null_mut());

        if rv != 0 {
            return NEXTGCORE_ERROR;
        }
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_signal_block(_signum: i32) -> i32 {
    NEXTGCORE_ERROR
}

/// Unblock a signal (identical to nextgcore_signal_unblock)
#[cfg(unix)]
pub fn nextgcore_signal_unblock(signum: i32) -> i32 {
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigemptyset(sig_mask.as_mut_ptr());
        libc::sigaddset(sig_mask.as_mut_ptr(), signum);

        let rv = libc::pthread_sigmask(libc::SIG_UNBLOCK, sig_mask.as_ptr(), std::ptr::null_mut());

        if rv != 0 {
            return NEXTGCORE_ERROR;
        }
    }

    NEXTGCORE_OK
}

#[cfg(not(unix))]
pub fn nextgcore_signal_unblock(_signum: i32) -> i32 {
    NEXTGCORE_ERROR
}

/// Set a signal handler (identical to nextgcore_signal)
#[cfg(unix)]
pub fn nextgcore_signal(signum: i32, handler: libc::sighandler_t) -> libc::sighandler_t {
    use std::mem::MaybeUninit;

    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        let mut oact: MaybeUninit<libc::sigaction> = MaybeUninit::uninit();

        act.sa_sigaction = handler;
        libc::sigemptyset(&mut act.sa_mask);
        act.sa_flags = 0;

        #[cfg(target_os = "macos")]
        {
            // Handle SIGCHLD specially on macOS/NetBSD
            if signum == libc::SIGCHLD && handler == libc::SIG_IGN {
                // Use a custom handler to avoid zombies
                extern "C" fn avoid_zombies(_signo: i32) {
                    unsafe { while libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) > 0 {} }
                }
                let h: extern "C" fn(i32) = avoid_zombies;
                act.sa_sigaction = h as usize as libc::sighandler_t;
            }
        }

        if libc::sigaction(signum, &act, oact.as_mut_ptr()) < 0 {
            return libc::SIG_ERR;
        }

        oact.assume_init().sa_sigaction
    }
}

#[cfg(not(unix))]
pub fn nextgcore_signal(_signum: i32, _handler: usize) -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_init() {
        nextgcore_signal_init();
    }

    #[test]
    fn test_signal_description() {
        nextgcore_signal_init();

        #[cfg(unix)]
        {
            assert_eq!(nextgcore_signal_description_get(libc::SIGINT), "Interrupt");
            assert_eq!(
                nextgcore_signal_description_get(libc::SIGTERM),
                "Terminated"
            );
            assert_eq!(
                nextgcore_signal_description_get(libc::SIGSEGV),
                "Segmentation fault"
            );
        }

        assert_eq!(
            nextgcore_signal_description_get(-1),
            "unknown signal (number)"
        );
        assert_eq!(
            nextgcore_signal_description_get(1000),
            "unknown signal (number)"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_signal_block_unblock() {
        let rv = nextgcore_signal_block(libc::SIGUSR1);
        assert_eq!(rv, NEXTGCORE_OK);

        let rv = nextgcore_signal_unblock(libc::SIGUSR1);
        assert_eq!(rv, NEXTGCORE_OK);
    }
}

// ---------------------------------------------------------------------------
// `--kill` handling shared by every NF daemon
// ---------------------------------------------------------------------------

/// Message returned when a daemon is invoked with `-k`/`--kill`.
///
/// Kept as a constant so the twelve daemons that accept the flag cannot drift
/// apart in what they tell an operator.
pub const KILL_UNSUPPORTED_MESSAGE: &str = concat!(
    "--kill is not supported: this daemon cannot signal another instance. ",
    "It has no pidfile and no way to identify a sibling process. ",
    "Stop the NF through whatever supervises it -- `docker compose stop <svc>`, ",
    "`kubectl delete pod`, `systemctl stop`, or send SIGTERM to the process directly. ",
    "The daemon handles SIGTERM/SIGINT for graceful shutdown."
);

/// Report that `--kill` cannot be honoured.
///
/// Every NF declares `-k/--kill` (documented "Kill running instance") and NOT ONE
/// implements it: each logged "would send SIGTERM to running instance" at info
/// level and returned success. So `nextgcore-<nf> --kill` exited **0** while the
/// instance kept serving traffic. A restart script that killed-then-started got two
/// instances contending for the same SBI port or SCTP association, and an operator
/// checking the exit status was told the NF was down when it was not.
///
/// This is the operator-facing form of the same defect issue #167 fixed on a
/// protocol path: a stub whose `Ok` a caller converts into a success claim.
///
/// Deliberately an ERROR rather than an implementation. These are container
/// workloads -- the compose healthchecks use `kill -0 1` and Kubernetes sends
/// SIGTERM itself -- so process lifecycle belongs to the supervisor, and adding a
/// pidfile so a container could kill a sibling it cannot see would be the wrong
/// feature. Nothing in the tree scripts `--kill`, and any script that did was
/// already silently broken, so failing loudly cannot break a working workflow: it
/// converts a silent no-op into a visible one.
pub fn kill_unsupported() -> std::io::Error {
    log::error!("{KILL_UNSUPPORTED_MESSAGE}");
    std::io::Error::new(std::io::ErrorKind::Unsupported, KILL_UNSUPPORTED_MESSAGE)
}

#[cfg(test)]
mod kill_flag_tests {
    use super::*;

    /// Every daemon that accepts `--kill` must route it through
    /// [`kill_unsupported`], and none may keep a hand-rolled stub.
    ///
    /// This existed as twelve independent copies of the same fictional log line,
    /// which is how it stayed wrong in twelve places at once. The guard reads the
    /// daemon sources so a thirteenth copy cannot be added quietly, and so a new NF
    /// that adds the flag has to opt into the shared behaviour.
    #[test]
    fn every_daemon_routes_kill_through_the_shared_helper() {
        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-core")
            .join("bins");
        assert!(bins.is_dir(), "expected {} to exist", bins.display());

        let mut declaring = Vec::new();
        let mut routed = Vec::new();
        let mut stubbed = Vec::new();

        for entry in std::fs::read_dir(&bins).expect("read bins/") {
            let dir = entry.expect("dir entry").path().join("src");
            if !dir.is_dir() {
                continue;
            }
            let name = dir
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut declares = false;
            let mut uses_helper = false;
            let mut has_stub = false;
            for file in std::fs::read_dir(&dir).expect("read src/") {
                let path = file.expect("file entry").path();
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let src = std::fs::read_to_string(&path).unwrap_or_default();
                if src.contains("kill: bool") {
                    declares = true;
                }
                if src.contains("kill_unsupported") {
                    uses_helper = true;
                }
                // The fictional wording, in any daemon.
                if src.contains("would send SIGTERM") {
                    has_stub = true;
                }
            }
            if declares {
                declaring.push(name.clone());
                if uses_helper {
                    routed.push(name.clone());
                }
            }
            if has_stub {
                stubbed.push(name);
            }
        }

        assert!(
            stubbed.is_empty(),
            "these daemons still claim to send SIGTERM without doing so: {stubbed:?}"
        );
        assert!(
            !declaring.is_empty(),
            "expected to find daemons declaring --kill; the guard found none, so it \
             is no longer checking anything"
        );
        declaring.sort();
        routed.sort();
        assert_eq!(
            declaring, routed,
            "every daemon declaring --kill must route it through kill_unsupported()"
        );
    }

    /// `--kill` must fail, and must say what to do instead. The load-bearing part
    /// is that this is an Err at all: it used to be `Ok(())` with an info log, so
    /// the process exited 0 without signalling anything.
    #[test]
    fn kill_is_reported_as_unsupported_not_success() {
        let err = kill_unsupported();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        let text = err.to_string();
        assert!(
            text.contains("not supported"),
            "the message must say the flag is unsupported: {text}"
        );
        // It must point the operator somewhere real rather than just refusing.
        for hint in ["SIGTERM", "compose", "kubectl"] {
            assert!(
                text.contains(hint),
                "the message should name {hint} as the supported route: {text}"
            );
        }
        // And it must not claim anything was signalled.
        assert!(
            !text.contains("would send"),
            "the old fictional 'would send SIGTERM' wording must be gone: {text}"
        );
    }
}
