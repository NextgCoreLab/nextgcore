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
            assert_eq!(nextgcore_signal_description_get(libc::SIGTERM), "Terminated");
            assert_eq!(
                nextgcore_signal_description_get(libc::SIGSEGV),
                "Segmentation fault"
            );
        }

        assert_eq!(nextgcore_signal_description_get(-1), "unknown signal (number)");
        assert_eq!(nextgcore_signal_description_get(1000), "unknown signal (number)");
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
