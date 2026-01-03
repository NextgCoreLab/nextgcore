//! Thread utilities
//!
//! Exact port of lib/core/ogs-thread.h and ogs-thread.c

use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::errno::{OGS_ERROR, OGS_OK, OGS_TIMEUP};
use crate::time::{ogs_get_monotonic_time, OgsTime};

/// Mutex type (wrapper around std::sync::Mutex)
pub type OgsThreadMutex<T> = Mutex<T>;

/// Condition variable type (wrapper around std::sync::Condvar)
pub type OgsThreadCond = Condvar;

/// Thread ID type
pub type OgsThreadId = JoinHandle<()>;

/// Initialize a mutex (no-op in Rust, mutex is initialized on creation)
#[inline]
pub fn ogs_thread_mutex_init<T>(data: T) -> OgsThreadMutex<T> {
    Mutex::new(data)
}

/// Lock a mutex and return the guard
#[inline]
pub fn ogs_thread_mutex_lock<T>(mutex: &OgsThreadMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Initialize a condition variable
#[inline]
pub fn ogs_thread_cond_init() -> OgsThreadCond {
    Condvar::new()
}

/// Wait on a condition variable
#[inline]
pub fn ogs_thread_cond_wait<'a, T>(
    cond: &OgsThreadCond,
    guard: std::sync::MutexGuard<'a, T>,
) -> std::sync::MutexGuard<'a, T> {
    cond.wait(guard).unwrap_or_else(|e| e.into_inner())
}

/// Timed wait on a condition variable
/// Returns OGS_OK on success, OGS_TIMEUP on timeout, OGS_ERROR on error
#[inline]
pub fn ogs_thread_cond_timedwait<'a, T>(
    cond: &OgsThreadCond,
    guard: std::sync::MutexGuard<'a, T>,
    timeout: OgsTime,
) -> (std::sync::MutexGuard<'a, T>, i32) {
    let duration = Duration::from_micros(timeout as u64);
    let result = cond.wait_timeout(guard, duration);
    match result {
        Ok((guard, timeout_result)) => {
            if timeout_result.timed_out() {
                (guard, OGS_TIMEUP)
            } else {
                (guard, OGS_OK)
            }
        }
        Err(e) => (e.into_inner().0, OGS_ERROR),
    }
}

/// Signal a condition variable (wake one waiter)
#[inline]
pub fn ogs_thread_cond_signal(cond: &OgsThreadCond) {
    cond.notify_one();
}

/// Broadcast to a condition variable (wake all waiters)
#[inline]
pub fn ogs_thread_cond_broadcast(cond: &OgsThreadCond) {
    cond.notify_all();
}

/// Thread state shared between main thread and worker
struct ThreadState {
    running: bool,
}

/// Thread structure (identical to ogs_thread_t)
pub struct OgsThread {
    handle: Option<JoinHandle<()>>,
    state: Arc<(Mutex<ThreadState>, Condvar)>,
}

impl OgsThread {
    /// Create a new thread (identical to ogs_thread_create)
    pub fn create<F>(func: F) -> Option<Self>
    where
        F: FnOnce() + Send + 'static,
    {
        let state = Arc::new((
            Mutex::new(ThreadState { running: false }),
            Condvar::new(),
        ));
        let state_clone = Arc::clone(&state);

        // Lock before spawning to wait for signal
        let mut guard = state.0.lock().unwrap_or_else(|e| e.into_inner());

        let handle = thread::spawn(move || {
            // Signal that thread is running
            {
                let (lock, cond) = &*state_clone;
                let mut state_guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                state_guard.running = true;
                cond.notify_one();
            }

            // Execute the user function
            func();

            // Mark thread as not running
            {
                let (lock, _cond) = &*state_clone;
                let mut state_guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                state_guard.running = false;
            }
        });

        // Wait for thread to signal it's running
        let (_lock, cond) = &*state;
        guard = cond.wait(guard).unwrap_or_else(|e| e.into_inner());
        drop(guard);

        Some(OgsThread {
            handle: Some(handle),
            state,
        })
    }

    /// Check if thread is running
    pub fn is_running(&self) -> bool {
        let guard = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.running
    }

    /// Destroy the thread (identical to ogs_thread_destroy)
    /// Waits up to 5 seconds for thread to finish
    pub fn destroy(mut self) {
        let deadline = ogs_get_monotonic_time() + 5 * 1000 * 1000; // 5 seconds

        // Wait for thread to finish (up to 5 seconds)
        while ogs_get_monotonic_time() <= deadline {
            {
                let guard = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
                if !guard.running {
                    break;
                }
            }
            std::thread::sleep(Duration::from_micros(1000));
        }

        // Check if still running after timeout
        {
            let guard = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
            if guard.running {
                panic!("thread still running after 5 seconds");
            }
        }

        // Join the thread
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for OgsThread {
    fn drop(&mut self) {
        // If handle is still present, join it
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Create a thread (C-style API)
pub fn ogs_thread_create<F>(func: F) -> Option<OgsThread>
where
    F: FnOnce() + Send + 'static,
{
    OgsThread::create(func)
}

/// Destroy a thread (C-style API)
pub fn ogs_thread_destroy(thread: OgsThread) {
    thread.destroy();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_thread_create_destroy() {
        let executed = Arc::new(AtomicBool::new(false));
        let executed_clone = Arc::clone(&executed);

        let thread = OgsThread::create(move || {
            executed_clone.store(true, Ordering::SeqCst);
        });

        assert!(thread.is_some());
        let thread = thread.unwrap();

        // Give thread time to execute
        std::thread::sleep(Duration::from_millis(10));

        assert!(executed.load(Ordering::SeqCst));
        thread.destroy();
    }

    #[test]
    fn test_mutex_lock() {
        let mutex = ogs_thread_mutex_init(42);
        {
            let guard = ogs_thread_mutex_lock(&mutex);
            assert_eq!(*guard, 42);
        }
    }

    #[test]
    fn test_condvar_signal() {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let thread = thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            let (lock, cond) = &*pair_clone;
            let mut guard = lock.lock().unwrap();
            *guard = true;
            cond.notify_one();
        });

        let (lock, cond) = &*pair;
        let mut guard = lock.lock().unwrap();
        while !*guard {
            guard = cond.wait(guard).unwrap();
        }
        assert!(*guard);

        thread.join().unwrap();
    }
}
