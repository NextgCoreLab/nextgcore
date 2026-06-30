//! NextGCore Core Utilities Library
//!
//! This crate provides fundamental data structures and utilities used throughout
//! the NextGCore codebase. It is a direct port of lib/core/ from the C implementation.

pub mod async_timer; // Async timer manager for NF event loops
pub mod conv; // Conversion utilities (nextgcore-conv.h)
pub mod distributed_timer;
pub mod errno; // Error codes (nextgcore-errno.h)
pub mod fsm; // Finite state machine (nextgcore-fsm.h)
pub mod hash; // Hash table (nextgcore-hash.h)
pub mod list; // Doubly-linked list (nextgcore-list.h)
pub mod lockfree; // Lock-free data structures (B2.4 - 6G advanced research)
pub mod log; // Logging (nextgcore-log.h)
pub mod memory; // Memory management (nextgcore-memory.h)
pub mod otel_log; // OTel structured logging (B2.1 - 6G observability)
pub mod pkbuf; // Packet buffer (nextgcore-pkbuf.h)
pub mod poll; // Event polling (nextgcore-poll.h)
pub mod pool; // Object pool (nextgcore-pool.h)
pub mod queue; // Thread-safe queue (nextgcore-queue.h)
pub mod rand; // Random number generation (nextgcore-rand.h)
pub mod rbtree; // Red-black tree (nextgcore-rbtree.h)
pub mod signal; // Signal handling (nextgcore-signal.h)
pub mod sockaddr; // Socket address (nextgcore-sockaddr.h)
pub mod socket; // Socket operations (nextgcore-socket.h)
pub mod sockopt; // Socket options (nextgcore-sockopt.h)
pub mod strings; // String utilities (nextgcore-strings.h)
pub mod tcp; // TCP server/client (nextgcore-tcp.h)
pub mod thread; // Thread utilities (nextgcore-thread.h)
pub mod time; // Time utilities (nextgcore-time.h)
pub mod timer; // Timer wheel (nextgcore-timer.h)
pub mod tlv; // TLV encoding (nextgcore-tlv.h)
pub mod udp; // UDP server/client (nextgcore-udp.h)
pub mod uuid; // UUID generation (nextgcore-uuid.h) // Distributed timer coordination (B2.1 - 6G)

// Re-export commonly used types
pub use async_timer::{compute_poll_interval, AsyncTimerEntry, AsyncTimerMgr, TimerMode};
pub use distributed_timer::{
    ClockSyncInfo, ClockSyncState, DistTimerEntry, DistTimerId, DistTimerManager, TimerScope,
};
pub use errno::{NextgcoreError, NEXTGCORE_ERROR, NEXTGCORE_OK};
#[allow(deprecated)]
pub use fsm::{FsmResult, NextgcoreFsm, StateMachine};
pub use hash::{nextgcore_hashfunc_default, NextgcoreHash, NextgcoreHashIter, NextgcoreHashMap, NEXTGCORE_HASH_KEY_STRING};
pub use list::{NextgcoreList, NextgcoreLnode};
pub use lockfree::{LockFreeHashMap, LockFreeQueue, LockFreeStack};
pub use otel_log::{
    detect_resource_attributes, BatchExportConfig, BatchLogExporter, ExportTarget, LogValue,
    OtelSeverity, StructuredLogEntry, StructuredLogger,
};
pub use pkbuf::NextgcorePkbuf;
pub use poll::{NextgcorePollset, NEXTGCORE_POLLIN, NEXTGCORE_POLLOUT};
pub use pool::{
    NextgcorePool, NextgcorePoolId, NextgcorePoolWithId, PoolItem, NEXTGCORE_INVALID_POOL_ID, NEXTGCORE_MAX_POOL_ID,
    NEXTGCORE_MIN_POOL_ID,
};
pub use queue::NextgcoreQueue;
pub use rbtree::{NextgcoreRbnode, NextgcoreRbtree, NextgcoreRbtreeColor};
pub use sockaddr::NextgcoreSockaddr;
pub use socket::{NextgcoreSock, NextgcoreSocket, INVALID_SOCKET};
pub use sockopt::NextgcoreSockopt;
pub use thread::NextgcoreThread;
pub use tlv::{NextgcoreTlv, NextgcoreTlvMsg, TlvError};
pub use uuid::NextgcoreUuid;
