//! Thread-safe queue
//!
//! Exact port of lib/core/ogs-queue.h and ogs-queue.c

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::errno::{OGS_DONE, OGS_ERROR, OGS_OK, OGS_RETRY, OGS_TIMEUP};
use crate::time::OgsTime;

/// Infinite time constant for blocking operations
pub const OGS_INFINITE_TIME: OgsTime = -1;

/// Thread-safe queue (identical to ogs_queue_t)
pub struct OgsQueue<T> {
    inner: Mutex<QueueInner<T>>,
    not_empty: Condvar,
    not_full: Condvar,
}

struct QueueInner<T> {
    data: VecDeque<T>,
    bounds: usize,
    terminated: bool,
    full_waiters: u32,
    empty_waiters: u32,
}

impl<T> OgsQueue<T> {
    /// Create a new queue with specified capacity (identical to ogs_queue_create)
    pub fn create(capacity: usize) -> Self {
        OgsQueue {
            inner: Mutex::new(QueueInner {
                data: VecDeque::with_capacity(capacity),
                bounds: capacity,
                terminated: false,
                full_waiters: 0,
                empty_waiters: 0,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        }
    }

    /// Check if queue is full (not thread-safe, must be called with lock held)
    #[inline]
    fn is_full(inner: &QueueInner<T>) -> bool {
        inner.data.len() == inner.bounds
    }

    /// Check if queue is empty (not thread-safe, must be called with lock held)
    #[inline]
    fn is_empty(inner: &QueueInner<T>) -> bool {
        inner.data.is_empty()
    }

    /// Push data onto the queue with timeout
    fn queue_push(&self, data: T, timeout: OgsTime) -> i32 {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if guard.terminated {
            return OGS_DONE;
        }

        // Wait if queue is full
        if Self::is_full(&guard) {
            if timeout == 0 {
                return OGS_RETRY;
            }

            if !guard.terminated {
                guard.full_waiters += 1;

                if timeout > 0 {
                    let duration = Duration::from_micros(timeout as u64);
                    let result = self.not_full.wait_timeout(guard, duration);
                    let (new_guard, timeout_result) = result.unwrap_or_else(|e| e.into_inner());
                    guard = new_guard;
                    guard.full_waiters -= 1;

                    if timeout_result.timed_out() {
                        return OGS_TIMEUP;
                    }
                } else {
                    // Infinite wait
                    guard = self.not_full.wait(guard).unwrap_or_else(|e| e.into_inner());
                    guard.full_waiters -= 1;
                }
            }

            // If we wake up and it's still full, we were interrupted
            if Self::is_full(&guard) {
                if guard.terminated {
                    return OGS_DONE;
                } else {
                    return OGS_ERROR;
                }
            }
        }

        // Push data
        guard.data.push_back(data);

        // Signal waiters
        if guard.empty_waiters > 0 {
            self.not_empty.notify_one();
        }

        OGS_OK
    }

    /// Push data onto the queue, blocking until space is available (identical to ogs_queue_push)
    pub fn push(&self, data: T) -> i32 {
        self.queue_push(data, OGS_INFINITE_TIME)
    }

    /// Try to push data onto the queue without blocking (identical to ogs_queue_trypush)
    pub fn trypush(&self, data: T) -> i32 {
        self.queue_push(data, 0)
    }

    /// Push data onto the queue with timeout (identical to ogs_queue_timedpush)
    pub fn timedpush(&self, data: T, timeout: OgsTime) -> i32 {
        self.queue_push(data, timeout)
    }

    /// Pop data from the queue with timeout
    fn queue_pop(&self, timeout: OgsTime) -> (i32, Option<T>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if guard.terminated {
            return (OGS_DONE, None);
        }

        // Wait if queue is empty
        if Self::is_empty(&guard) {
            if timeout == 0 {
                return (OGS_RETRY, None);
            }

            if !guard.terminated {
                guard.empty_waiters += 1;

                if timeout > 0 {
                    let duration = Duration::from_micros(timeout as u64);
                    let result = self.not_empty.wait_timeout(guard, duration);
                    let (new_guard, timeout_result) = result.unwrap_or_else(|e| e.into_inner());
                    guard = new_guard;
                    guard.empty_waiters -= 1;

                    if timeout_result.timed_out() {
                        return (OGS_TIMEUP, None);
                    }
                } else {
                    // Infinite wait
                    guard = self.not_empty.wait(guard).unwrap_or_else(|e| e.into_inner());
                    guard.empty_waiters -= 1;
                }
            }

            // If we wake up and it's still empty, we were interrupted
            if Self::is_empty(&guard) {
                if guard.terminated {
                    return (OGS_DONE, None);
                } else {
                    return (OGS_ERROR, None);
                }
            }
        }

        // Pop data
        let data = guard.data.pop_front();

        // Signal waiters
        if guard.full_waiters > 0 {
            self.not_full.notify_one();
        }

        (OGS_OK, data)
    }

    /// Pop data from the queue, blocking until data is available (identical to ogs_queue_pop)
    pub fn pop(&self) -> (i32, Option<T>) {
        self.queue_pop(OGS_INFINITE_TIME)
    }

    /// Try to pop data from the queue without blocking (identical to ogs_queue_trypop)
    pub fn trypop(&self) -> (i32, Option<T>) {
        self.queue_pop(0)
    }

    /// Pop data from the queue with timeout (identical to ogs_queue_timedpop)
    pub fn timedpop(&self, timeout: OgsTime) -> (i32, Option<T>) {
        self.queue_pop(timeout)
    }

    /// Get the current size of the queue (not thread-safe) (identical to ogs_queue_size)
    pub fn size(&self) -> usize {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.data.len()
    }

    /// Interrupt all waiting threads (identical to ogs_queue_interrupt_all)
    pub fn interrupt_all(&self) -> i32 {
        let _guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.not_empty.notify_all();
        self.not_full.notify_all();
        OGS_OK
    }

    /// Terminate the queue (identical to ogs_queue_term)
    pub fn term(&self) -> i32 {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.terminated = true;
        }
        self.interrupt_all()
    }

    /// Check if queue is terminated
    pub fn is_terminated(&self) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.terminated
    }
}

/// Create a queue (C-style API)
pub fn ogs_queue_create<T>(capacity: usize) -> OgsQueue<T> {
    OgsQueue::create(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_queue_create() {
        let queue: OgsQueue<i32> = OgsQueue::create(10);
        assert_eq!(queue.size(), 0);
    }

    #[test]
    fn test_queue_push_pop() {
        let queue: OgsQueue<i32> = OgsQueue::create(10);

        assert_eq!(queue.push(42), OGS_OK);
        assert_eq!(queue.size(), 1);

        let (rv, data) = queue.pop();
        assert_eq!(rv, OGS_OK);
        assert_eq!(data, Some(42));
        assert_eq!(queue.size(), 0);
    }

    #[test]
    fn test_queue_trypush_trypop() {
        let queue: OgsQueue<i32> = OgsQueue::create(2);

        assert_eq!(queue.trypush(1), OGS_OK);
        assert_eq!(queue.trypush(2), OGS_OK);
        assert_eq!(queue.trypush(3), OGS_RETRY); // Queue full

        let (rv, data) = queue.trypop();
        assert_eq!(rv, OGS_OK);
        assert_eq!(data, Some(1));

        let (rv, data) = queue.trypop();
        assert_eq!(rv, OGS_OK);
        assert_eq!(data, Some(2));

        let (rv, _) = queue.trypop();
        assert_eq!(rv, OGS_RETRY); // Queue empty
    }

    #[test]
    fn test_queue_timedpop_timeout() {
        let queue: OgsQueue<i32> = OgsQueue::create(10);

        let start = std::time::Instant::now();
        let (rv, _) = queue.timedpop(10000); // 10ms timeout
        let elapsed = start.elapsed();

        assert_eq!(rv, OGS_TIMEUP);
        assert!(elapsed.as_millis() >= 10);
    }

    #[test]
    fn test_queue_term() {
        let queue: OgsQueue<i32> = OgsQueue::create(10);

        queue.term();
        assert!(queue.is_terminated());

        assert_eq!(queue.push(42), OGS_DONE);
        let (rv, _) = queue.pop();
        assert_eq!(rv, OGS_DONE);
    }

    #[test]
    fn test_queue_multithreaded() {
        let queue = Arc::new(OgsQueue::create(100));
        let queue_producer = Arc::clone(&queue);
        let queue_consumer = Arc::clone(&queue);

        let producer = thread::spawn(move || {
            for i in 0..50 {
                queue_producer.push(i);
            }
        });

        let consumer = thread::spawn(move || {
            let mut sum = 0;
            for _ in 0..50 {
                let (rv, data) = queue_consumer.pop();
                assert_eq!(rv, OGS_OK);
                sum += data.unwrap();
            }
            sum
        });

        producer.join().unwrap();
        let sum = consumer.join().unwrap();
        assert_eq!(sum, (0..50).sum::<i32>());
    }
}
