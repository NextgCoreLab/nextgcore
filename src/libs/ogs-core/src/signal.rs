//! Signal handling utilities
//!
//! Exact port of lib/core/ogs-signal.h and ogs-signal.c

use std::sync::OnceLock;

use crate::errno::{OGS_ERROR, OGS_OK};

/// Number of signals
#[cfg(target_os = "linux")]
const OGS_NUMSIG: usize = 65;
#[cfg(target_os = "macos")]
const OGS_NUMSIG: usize = 32;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const OGS_NUMSIG: usize = 33;

/// Signal descriptions
static SIGNAL_DESCRIPTIONS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Signal function type
pub type OgsSigfunc = fn(i32);

/// Initialize signal descriptions (identical to ogs_signal_init)
pub fn ogs_signal_init() {
    SIGNAL_DESCRIPTIONS.get_or_init(|| {
        let mut descriptions = vec!["unknown signal (number)"; OGS_NUMSIG];

        descriptions[0] = "Signal 0";

        #[cfg(unix)]
        {
            use libc::*;

            if (SIGHUP as usize) < OGS_NUMSIG {
                descriptions[SIGHUP as usize] = "Hangup";
            }
            if (SIGINT as usize) < OGS_NUMSIG {
                descriptions[SIGINT as usize] = "Interrupt";
            }
            if (SIGQUIT as usize) < OGS_NUMSIG {
                descriptions[SIGQUIT as usize] = "Quit";
            }
            if (SIGILL as usize) < OGS_NUMSIG {
                descriptions[SIGILL as usize] = "Illegal instruction";
            }
            if (SIGTRAP as usize) < OGS_NUMSIG {
                descriptions[SIGTRAP as usize] = "Trace/BPT trap";
            }
            if (SIGABRT as usize) < OGS_NUMSIG {
                descriptions[SIGABRT as usize] = "Abort";
            }
            if (SIGFPE as usize) < OGS_NUMSIG {
                descriptions[SIGFPE as usize] = "Arithmetic exception";
            }
            if (SIGKILL as usize) < OGS_NUMSIG {
                descriptions[SIGKILL as usize] = "Killed";
            }
            if (SIGBUS as usize) < OGS_NUMSIG {
                descriptions[SIGBUS as usize] = "Bus error";
            }
            if (SIGSEGV as usize) < OGS_NUMSIG {
                descriptions[SIGSEGV as usize] = "Segmentation fault";
            }
            if (SIGSYS as usize) < OGS_NUMSIG {
                descriptions[SIGSYS as usize] = "Bad system call";
            }
            if (SIGPIPE as usize) < OGS_NUMSIG {
                descriptions[SIGPIPE as usize] = "Broken pipe";
            }
            if (SIGALRM as usize) < OGS_NUMSIG {
                descriptions[SIGALRM as usize] = "Alarm clock";
            }
            if (SIGTERM as usize) < OGS_NUMSIG {
                descriptions[SIGTERM as usize] = "Terminated";
            }
            if (SIGUSR1 as usize) < OGS_NUMSIG {
                descriptions[SIGUSR1 as usize] = "User defined signal 1";
            }
            if (SIGUSR2 as usize) < OGS_NUMSIG {
                descriptions[SIGUSR2 as usize] = "User defined signal 2";
            }
            if (SIGCHLD as usize) < OGS_NUMSIG {
                descriptions[SIGCHLD as usize] = "Child status change";
            }
            #[cfg(target_os = "linux")]
            if (SIGPWR as usize) < OGS_NUMSIG {
                descriptions[SIGPWR as usize] = "Power-fail restart";
            }
            if (SIGWINCH as usize) < OGS_NUMSIG {
                descriptions[SIGWINCH as usize] = "Window changed";
            }
            if (SIGURG as usize) < OGS_NUMSIG {
                descriptions[SIGURG as usize] = "urgent socket condition";
            }
            #[cfg(target_os = "linux")]
            if (SIGPOLL as usize) < OGS_NUMSIG {
                descriptions[SIGPOLL as usize] = "Pollable event occurred";
            }
            if (SIGIO as usize) < OGS_NUMSIG {
                descriptions[SIGIO as usize] = "socket I/O possible";
            }
            if (SIGSTOP as usize) < OGS_NUMSIG {
                descriptions[SIGSTOP as usize] = "Stopped (signal)";
            }
            if (SIGTSTP as usize) < OGS_NUMSIG {
                descriptions[SIGTSTP as usize] = "Stopped";
            }
            if (SIGCONT as usize) < OGS_NUMSIG {
                descriptions[SIGCONT as usize] = "Continued";
            }
            if (SIGTTIN as usize) < OGS_NUMSIG {
                descriptions[SIGTTIN as usize] = "Stopped (tty input)";
            }
            if (SIGTTOU as usize) < OGS_NUMSIG {
                descriptions[SIGTTOU as usize] = "Stopped (tty output)";
            }
            if (SIGVTALRM as usize) < OGS_NUMSIG {
                descriptions[SIGVTALRM as usize] = "virtual timer expired";
            }
            if (SIGPROF as usize) < OGS_NUMSIG {
                descriptions[SIGPROF as usize] = "profiling timer expired";
            }
            if (SIGXCPU as usize) < OGS_NUMSIG {
                descriptions[SIGXCPU as usize] = "exceeded cpu limit";
            }
            if (SIGXFSZ as usize) < OGS_NUMSIG {
                descriptions[SIGXFSZ as usize] = "exceeded file size limit";
            }
        }

        descriptions
    });
}

/// Get signal description (identical to ogs_signal_description_get)
pub fn ogs_signal_description_get(signum: i32) -> &'static str {
    let descriptions = SIGNAL_DESCRIPTIONS.get_or_init(|| {
        ogs_signal_init();
        SIGNAL_DESCRIPTIONS.get().unwrap().clone()
    });

    if signum >= 0 && (signum as usize) < descriptions.len() {
        descriptions[signum as usize]
    } else {
        "unknown signal (number)"
    }
}

/// Set up signal handling for threads (identical to ogs_setup_signal_thread)
#[cfg(unix)]
pub fn ogs_setup_signal_thread() -> i32 {
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigfillset(sig_mask.as_mut_ptr());

        // Remove synchronous signals that cannot be blocked
        remove_sync_sigs(sig_mask.as_mut_ptr());

        let rv = libc::pthread_sigmask(
            libc::SIG_SETMASK,
            sig_mask.as_ptr(),
            std::ptr::null_mut(),
        );

        if rv != 0 {
            return OGS_ERROR;
        }
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_setup_signal_thread() -> i32 {
    OGS_OK
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

/// Signal thread that waits for signals (identical to ogs_signal_thread)
#[cfg(unix)]
pub fn ogs_signal_thread<F>(signal_handler: F) -> i32
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
                return OGS_OK;
            }
        }
    }
}

#[cfg(not(unix))]
pub fn ogs_signal_thread<F>(_signal_handler: F) -> i32
where
    F: Fn(i32) -> i32,
{
    OGS_ERROR
}

/// Block a signal (identical to ogs_signal_block)
#[cfg(unix)]
pub fn ogs_signal_block(signum: i32) -> i32 {
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigemptyset(sig_mask.as_mut_ptr());
        libc::sigaddset(sig_mask.as_mut_ptr(), signum);

        let rv = libc::pthread_sigmask(
            libc::SIG_BLOCK,
            sig_mask.as_ptr(),
            std::ptr::null_mut(),
        );

        if rv != 0 {
            return OGS_ERROR;
        }
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_signal_block(_signum: i32) -> i32 {
    OGS_ERROR
}

/// Unblock a signal (identical to ogs_signal_unblock)
#[cfg(unix)]
pub fn ogs_signal_unblock(signum: i32) -> i32 {
    use std::mem::MaybeUninit;

    unsafe {
        let mut sig_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
        libc::sigemptyset(sig_mask.as_mut_ptr());
        libc::sigaddset(sig_mask.as_mut_ptr(), signum);

        let rv = libc::pthread_sigmask(
            libc::SIG_UNBLOCK,
            sig_mask.as_ptr(),
            std::ptr::null_mut(),
        );

        if rv != 0 {
            return OGS_ERROR;
        }
    }

    OGS_OK
}

#[cfg(not(unix))]
pub fn ogs_signal_unblock(_signum: i32) -> i32 {
    OGS_ERROR
}

/// Set a signal handler (identical to ogs_signal)
#[cfg(unix)]
pub fn ogs_signal(signum: i32, handler: libc::sighandler_t) -> libc::sighandler_t {
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
                    unsafe {
                        while libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
                    }
                }
                act.sa_sigaction = avoid_zombies as libc::sighandler_t;
            }
        }

        if libc::sigaction(signum, &act, oact.as_mut_ptr()) < 0 {
            return libc::SIG_ERR;
        }

        oact.assume_init().sa_sigaction
    }
}

#[cfg(not(unix))]
pub fn ogs_signal(_signum: i32, _handler: usize) -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_init() {
        ogs_signal_init();
    }

    #[test]
    fn test_signal_description() {
        ogs_signal_init();

        #[cfg(unix)]
        {
            assert_eq!(ogs_signal_description_get(libc::SIGINT), "Interrupt");
            assert_eq!(ogs_signal_description_get(libc::SIGTERM), "Terminated");
            assert_eq!(ogs_signal_description_get(libc::SIGSEGV), "Segmentation fault");
        }

        assert_eq!(ogs_signal_description_get(-1), "unknown signal (number)");
        assert_eq!(ogs_signal_description_get(1000), "unknown signal (number)");
    }

    #[test]
    #[cfg(unix)]
    fn test_signal_block_unblock() {
        let rv = ogs_signal_block(libc::SIGUSR1);
        assert_eq!(rv, OGS_OK);

        let rv = ogs_signal_unblock(libc::SIGUSR1);
        assert_eq!(rv, OGS_OK);
    }
}
