//! Event polling
//!
//! Exact port of lib/core/ogs-poll.h and ogs-poll.c

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::errno::{OGS_ERROR, OGS_OK};
use crate::socket::OgsSocket;
use crate::sockopt::{ogs_closeonexec, ogs_nonblocking};
use crate::time::OgsTime;

/// Poll event flags
pub const OGS_POLLIN: i16 = 0x01;
pub const OGS_POLLOUT: i16 = 0x02;

/// Poll handler function type
pub type OgsPollHandler = Box<dyn FnMut(i16, OgsSocket, *mut std::ffi::c_void) + Send>;

/// Poll structure (identical to ogs_poll_t)
pub struct OgsPoll {
    pub id: usize,
    pub when: i16,
    pub fd: OgsSocket,
    pub handler: OgsPollHandler,
    pub data: *mut std::ffi::c_void,
}

// Safety: OgsPoll is Send because we manage the raw pointer carefully
unsafe impl Send for OgsPoll {}

/// Pollset structure (identical to ogs_pollset_t)
pub struct OgsPollset {
    polls: HashMap<usize, OgsPoll>,
    next_id: AtomicUsize,
    capacity: usize,

    // Notify pipe for waking up poll
    notify_read_fd: OgsSocket,
    notify_write_fd: OgsSocket,

    // Platform-specific context
    #[cfg(target_os = "linux")]
    epoll_fd: RawFd,

    #[cfg(target_os = "macos")]
    kqueue_fd: RawFd,

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    poll_fds: Vec<libc::pollfd>,
}

impl OgsPollset {
    /// Create a new pollset (identical to ogs_pollset_create)
    pub fn create(capacity: usize) -> Option<Self> {
        // Create notify pipe
        let mut pipe_fds: [RawFd; 2] = [-1, -1];
        let rv = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if rv != 0 {
            return None;
        }

        let notify_read_fd = pipe_fds[0];
        let notify_write_fd = pipe_fds[1];

        // Set non-blocking and close-on-exec
        ogs_nonblocking(notify_read_fd);
        ogs_closeonexec(notify_read_fd);
        ogs_nonblocking(notify_write_fd);
        ogs_closeonexec(notify_write_fd);

        #[cfg(target_os = "linux")]
        {
            let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if epoll_fd < 0 {
                unsafe {
                    libc::close(notify_read_fd);
                    libc::close(notify_write_fd);
                }
                return None;
            }

            // Add notify pipe to epoll
            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: 0, // Special ID for notify
            };
            unsafe {
                libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, notify_read_fd, &mut event);
            }

            Some(OgsPollset {
                polls: HashMap::with_capacity(capacity),
                next_id: AtomicUsize::new(1),
                capacity,
                notify_read_fd,
                notify_write_fd,
                epoll_fd,
            })
        }

        #[cfg(target_os = "macos")]
        {
            let kqueue_fd = unsafe { libc::kqueue() };
            if kqueue_fd < 0 {
                unsafe {
                    libc::close(notify_read_fd);
                    libc::close(notify_write_fd);
                }
                return None;
            }

            // Add notify pipe to kqueue
            let event = libc::kevent {
                ident: notify_read_fd as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            unsafe {
                libc::kevent(kqueue_fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null());
            }

            Some(OgsPollset {
                polls: HashMap::with_capacity(capacity),
                next_id: AtomicUsize::new(1),
                capacity,
                notify_read_fd,
                notify_write_fd,
                kqueue_fd,
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Some(OgsPollset {
                polls: HashMap::with_capacity(capacity),
                next_id: AtomicUsize::new(1),
                capacity,
                notify_read_fd,
                notify_write_fd,
                poll_fds: Vec::with_capacity(capacity + 1),
            })
        }
    }

    /// Add a poll to the pollset (identical to ogs_pollset_add)
    pub fn add<F>(&mut self, when: i16, fd: OgsSocket, handler: F, data: *mut std::ffi::c_void) -> Option<usize>
    where
        F: FnMut(i16, OgsSocket, *mut std::ffi::c_void) + Send + 'static,
    {
        if self.polls.len() >= self.capacity {
            return None;
        }

        // Set non-blocking and close-on-exec
        ogs_nonblocking(fd);
        ogs_closeonexec(fd);

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        #[cfg(target_os = "linux")]
        {
            let mut events: u32 = 0;
            if (when & OGS_POLLIN) != 0 {
                events |= libc::EPOLLIN as u32;
            }
            if (when & OGS_POLLOUT) != 0 {
                events |= libc::EPOLLOUT as u32;
            }

            let mut event = libc::epoll_event {
                events,
                u64: id as u64,
            };

            let rv = unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) };
            if rv != 0 {
                return None;
            }
        }

        #[cfg(target_os = "macos")]
        {
            if (when & OGS_POLLIN) != 0 {
                let event = libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: id as *mut std::ffi::c_void,
                };
                unsafe {
                    libc::kevent(self.kqueue_fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null());
                }
            }
            if (when & OGS_POLLOUT) != 0 {
                let event = libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: libc::EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: id as *mut std::ffi::c_void,
                };
                unsafe {
                    libc::kevent(self.kqueue_fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null());
                }
            }
        }

        let poll = OgsPoll {
            id,
            when,
            fd,
            handler: Box::new(handler),
            data,
        };

        self.polls.insert(id, poll);
        Some(id)
    }

    /// Remove a poll from the pollset (identical to ogs_pollset_remove)
    pub fn remove(&mut self, id: usize) -> i32 {
        if let Some(poll) = self.polls.remove(&id) {
            #[cfg(target_os = "linux")]
            {
                unsafe {
                    libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_DEL, poll.fd, std::ptr::null_mut());
                }
            }

            #[cfg(target_os = "macos")]
            {
                if (poll.when & OGS_POLLIN) != 0 {
                    let event = libc::kevent {
                        ident: poll.fd as usize,
                        filter: libc::EVFILT_READ,
                        flags: libc::EV_DELETE,
                        fflags: 0,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    };
                    unsafe {
                        libc::kevent(self.kqueue_fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null());
                    }
                }
                if (poll.when & OGS_POLLOUT) != 0 {
                    let event = libc::kevent {
                        ident: poll.fd as usize,
                        filter: libc::EVFILT_WRITE,
                        flags: libc::EV_DELETE,
                        fflags: 0,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    };
                    unsafe {
                        libc::kevent(self.kqueue_fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null());
                    }
                }
            }

            OGS_OK
        } else {
            OGS_ERROR
        }
    }

    /// Poll for events (identical to ogs_pollset_poll)
    pub fn poll(&mut self, timeout: OgsTime) -> i32 {
        let timeout_ms = if timeout < 0 {
            -1
        } else {
            (timeout / 1000) as i32 // Convert microseconds to milliseconds
        };

        #[cfg(target_os = "linux")]
        {
            let mut events: [libc::epoll_event; 64] = unsafe { std::mem::zeroed() };

            let nfds = unsafe {
                libc::epoll_wait(self.epoll_fd, events.as_mut_ptr(), events.len() as i32, timeout_ms)
            };

            if nfds < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    return OGS_OK;
                }
                return OGS_ERROR;
            }

            // Collect events to process (to avoid borrow issues)
            let mut to_process: Vec<(usize, i16)> = Vec::new();

            for i in 0..nfds as usize {
                let id = events[i].u64 as usize;

                // Skip notify pipe (id 0)
                if id == 0 {
                    // Drain the notify pipe
                    let mut buf = [0u8; 64];
                    unsafe { libc::read(self.notify_read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    continue;
                }

                let mut when: i16 = 0;
                if (events[i].events & libc::EPOLLIN as u32) != 0 {
                    when |= OGS_POLLIN;
                }
                if (events[i].events & libc::EPOLLOUT as u32) != 0 {
                    when |= OGS_POLLOUT;
                }

                to_process.push((id, when));
            }

            // Process events
            for (id, when) in to_process {
                if let Some(poll) = self.polls.get_mut(&id) {
                    (poll.handler)(when, poll.fd, poll.data);
                }
            }

            OGS_OK
        }

        #[cfg(target_os = "macos")]
        {
            let mut events: [libc::kevent; 64] = unsafe { std::mem::zeroed() };

            let timeout_spec = if timeout_ms < 0 {
                std::ptr::null()
            } else {
                &libc::timespec {
                    tv_sec: (timeout_ms / 1000) as i64,
                    tv_nsec: ((timeout_ms % 1000) * 1_000_000) as i64,
                }
            };

            let nfds = unsafe {
                libc::kevent(
                    self.kqueue_fd,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    timeout_spec,
                )
            };

            if nfds < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    return OGS_OK;
                }
                return OGS_ERROR;
            }

            // Collect events to process
            let mut to_process: Vec<(usize, i16)> = Vec::new();

            for i in 0..nfds as usize {
                // Check if this is the notify pipe
                if events[i].ident == self.notify_read_fd as usize {
                    // Drain the notify pipe
                    let mut buf = [0u8; 64];
                    unsafe { libc::read(self.notify_read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    continue;
                }

                let id = events[i].udata as usize;
                let mut when: i16 = 0;

                if events[i].filter == libc::EVFILT_READ {
                    when |= OGS_POLLIN;
                }
                if events[i].filter == libc::EVFILT_WRITE {
                    when |= OGS_POLLOUT;
                }

                to_process.push((id, when));
            }

            // Process events
            for (id, when) in to_process {
                if let Some(poll) = self.polls.get_mut(&id) {
                    (poll.handler)(when, poll.fd, poll.data);
                }
            }

            OGS_OK
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // Fallback to poll()
            self.poll_fds.clear();

            // Add notify pipe
            self.poll_fds.push(libc::pollfd {
                fd: self.notify_read_fd,
                events: libc::POLLIN,
                revents: 0,
            });

            // Build poll fd array
            let poll_ids: Vec<usize> = self.polls.keys().cloned().collect();
            for id in &poll_ids {
                if let Some(poll) = self.polls.get(id) {
                    let mut events: i16 = 0;
                    if (poll.when & OGS_POLLIN) != 0 {
                        events |= libc::POLLIN;
                    }
                    if (poll.when & OGS_POLLOUT) != 0 {
                        events |= libc::POLLOUT;
                    }
                    self.poll_fds.push(libc::pollfd {
                        fd: poll.fd,
                        events,
                        revents: 0,
                    });
                }
            }

            let nfds = unsafe {
                libc::poll(self.poll_fds.as_mut_ptr(), self.poll_fds.len() as libc::nfds_t, timeout_ms)
            };

            if nfds < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    return OGS_OK;
                }
                return OGS_ERROR;
            }

            // Check notify pipe
            if self.poll_fds[0].revents != 0 {
                let mut buf = [0u8; 64];
                unsafe { libc::read(self.notify_read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            }

            // Process events
            for (i, id) in poll_ids.iter().enumerate() {
                let pfd = &self.poll_fds[i + 1]; // +1 to skip notify pipe
                if pfd.revents != 0 {
                    let mut when: i16 = 0;
                    if (pfd.revents & libc::POLLIN) != 0 {
                        when |= OGS_POLLIN;
                    }
                    if (pfd.revents & libc::POLLOUT) != 0 {
                        when |= OGS_POLLOUT;
                    }

                    if let Some(poll) = self.polls.get_mut(id) {
                        (poll.handler)(when, poll.fd, poll.data);
                    }
                }
            }

            OGS_OK
        }
    }

    /// Notify the pollset to wake up (identical to ogs_pollset_notify)
    pub fn notify(&self) -> i32 {
        let buf = [1u8];
        let rv = unsafe { libc::write(self.notify_write_fd, buf.as_ptr() as *const _, 1) };

        if rv < 0 {
            return OGS_ERROR;
        }

        OGS_OK
    }
}

impl Drop for OgsPollset {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::close(self.epoll_fd);
        }

        #[cfg(target_os = "macos")]
        unsafe {
            libc::close(self.kqueue_fd);
        }

        unsafe {
            libc::close(self.notify_read_fd);
            libc::close(self.notify_write_fd);
        }
    }
}

/// Create a pollset (C-style API)
pub fn ogs_pollset_create(capacity: usize) -> Option<OgsPollset> {
    OgsPollset::create(capacity)
}

/// Destroy a pollset (C-style API)
pub fn ogs_pollset_destroy(pollset: OgsPollset) {
    drop(pollset);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    

    #[test]
    fn test_pollset_create() {
        let pollset = OgsPollset::create(10);
        assert!(pollset.is_some());
    }

    #[test]
    fn test_pollset_notify() {
        let pollset = OgsPollset::create(10).unwrap();
        let rv = pollset.notify();
        assert_eq!(rv, OGS_OK);
    }

    #[test]
    fn test_pollset_add_remove() {
        let mut pollset = OgsPollset::create(10).unwrap();

        // Create a pipe for testing
        let mut pipe_fds: [RawFd; 2] = [-1, -1];
        unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };

        let id = pollset.add(
            OGS_POLLIN,
            pipe_fds[0],
            |_when, _fd, _data| {},
            std::ptr::null_mut(),
        );
        assert!(id.is_some());

        let rv = pollset.remove(id.unwrap());
        assert_eq!(rv, OGS_OK);

        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }

    #[test]
    fn test_pollset_poll_timeout() {
        let mut pollset = OgsPollset::create(10).unwrap();

        let start = std::time::Instant::now();
        let rv = pollset.poll(10000); // 10ms timeout
        let elapsed = start.elapsed();

        assert_eq!(rv, OGS_OK);
        assert!(elapsed.as_millis() >= 10);
    }
}

//
// Async I/O Support (B2.1)
//

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll as TaskPoll, Waker};

/// Async event notification
struct AsyncEvent {
    waker: Option<Waker>,
    ready: bool,
    event_mask: i16,
}

impl AsyncEvent {
    fn new() -> Self {
        Self {
            waker: None,
            ready: false,
            event_mask: 0,
        }
    }
}

/// Async pollset manager wrapping OgsPollset
pub struct AsyncPollManager {
    pollset: Arc<Mutex<OgsPollset>>,
    running: Arc<Mutex<bool>>,
}

impl AsyncPollManager {
    /// Create a new async poll manager
    pub fn new(capacity: usize) -> Option<Self> {
        let pollset = OgsPollset::create(capacity)?;
        Some(AsyncPollManager {
            pollset: Arc::new(Mutex::new(pollset)),
            running: Arc::new(Mutex::new(false)),
        })
    }

    /// Add an async socket to the pollset
    pub fn add_async<F>(
        &self,
        when: i16,
        fd: OgsSocket,
        handler: F,
        data: *mut std::ffi::c_void,
    ) -> Option<AsyncPollHandle>
    where
        F: FnMut(i16, OgsSocket, *mut std::ffi::c_void) + Send + 'static,
    {
        let mut pollset = self.pollset.lock().unwrap();
        let id = pollset.add(when, fd, handler, data)?;

        Some(AsyncPollHandle {
            id,
            fd,
            pollset: Arc::clone(&self.pollset),
            event: Arc::new(Mutex::new(AsyncEvent::new())),
        })
    }

    /// Remove a socket from the pollset
    pub fn remove(&self, id: usize) -> i32 {
        let mut pollset = self.pollset.lock().unwrap();
        pollset.remove(id)
    }

    /// Run the poll loop in the background
    pub fn spawn_poll_loop(&self, timeout: OgsTime) {
        let pollset = Arc::clone(&self.pollset);
        let running = Arc::clone(&self.running);

        *running.lock().unwrap() = true;

        std::thread::spawn(move || {
            while *running.lock().unwrap() {
                let mut ps = pollset.lock().unwrap();
                ps.poll(timeout);
            }
        });
    }

    /// Stop the poll loop
    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
        // Wake up the poll loop
        let pollset = self.pollset.lock().unwrap();
        pollset.notify();
    }

    /// Notify the pollset to wake up
    pub fn notify(&self) -> i32 {
        let pollset = self.pollset.lock().unwrap();
        pollset.notify()
    }
}

/// Handle for an async poll operation
pub struct AsyncPollHandle {
    id: usize,
    fd: OgsSocket,
    pollset: Arc<Mutex<OgsPollset>>,
    event: Arc<Mutex<AsyncEvent>>,
}

impl AsyncPollHandle {
    /// Get the poll ID
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the file descriptor
    pub fn fd(&self) -> OgsSocket {
        self.fd
    }

    /// Wait for readable event
    pub fn readable(&self) -> AsyncPollFuture {
        AsyncPollFuture {
            event: Arc::clone(&self.event),
            mask: OGS_POLLIN,
        }
    }

    /// Wait for writable event
    pub fn writable(&self) -> AsyncPollFuture {
        AsyncPollFuture {
            event: Arc::clone(&self.event),
            mask: OGS_POLLOUT,
        }
    }

    /// Mark event as ready (called from poll handler)
    pub fn mark_ready(&self, event_mask: i16) {
        let mut event = self.event.lock().unwrap();
        event.ready = true;
        event.event_mask = event_mask;
        if let Some(waker) = event.waker.take() {
            waker.wake();
        }
    }
}

impl Drop for AsyncPollHandle {
    fn drop(&mut self) {
        let mut pollset = self.pollset.lock().unwrap();
        pollset.remove(self.id);
    }
}

/// Future for async poll operations
pub struct AsyncPollFuture {
    event: Arc<Mutex<AsyncEvent>>,
    mask: i16,
}

impl Future for AsyncPollFuture {
    type Output = i16;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> TaskPoll<Self::Output> {
        let mut event = self.event.lock().unwrap();

        if event.ready && (event.event_mask & self.mask) != 0 {
            let result = event.event_mask;
            event.ready = false;
            event.event_mask = 0;
            TaskPoll::Ready(result)
        } else {
            event.waker = Some(cx.waker().clone());
            TaskPoll::Pending
        }
    }
}

#[cfg(test)]
mod async_tests {
    use super::*;

    #[test]
    fn test_async_poll_manager_create() {
        let manager = AsyncPollManager::new(10);
        assert!(manager.is_some());
    }

    #[test]
    fn test_async_poll_manager_notify() {
        let manager = AsyncPollManager::new(10).unwrap();
        let rv = manager.notify();
        assert_eq!(rv, OGS_OK);
    }

    #[tokio::test]
    async fn test_async_poll_handle() {
        let manager = AsyncPollManager::new(10).unwrap();

        // Create a pipe for testing
        let mut pipe_fds: [RawFd; 2] = [-1, -1];
        unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };

        let handle = manager
            .add_async(
                OGS_POLLIN,
                pipe_fds[0],
                |_when, _fd, _data| {},
                std::ptr::null_mut(),
            )
            .unwrap();

        // Simulate event
        handle.mark_ready(OGS_POLLIN);

        // Wait for readable
        let result = handle.readable().await;
        assert_eq!(result & OGS_POLLIN, OGS_POLLIN);

        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }
}
