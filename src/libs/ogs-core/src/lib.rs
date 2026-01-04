//! NextGCore Core Utilities Library
//!
//! This crate provides fundamental data structures and utilities used throughout
//! the NextGCore codebase. It is a direct port of lib/core/ from the C implementation.

pub mod list;      // Doubly-linked list (ogs-list.h)
pub mod hash;      // Hash table (ogs-hash.h)
pub mod pool;      // Object pool (ogs-pool.h)
pub mod pkbuf;     // Packet buffer (ogs-pkbuf.h)
pub mod timer;     // Timer wheel (ogs-timer.h)
pub mod fsm;       // Finite state machine (ogs-fsm.h)
pub mod tlv;       // TLV encoding (ogs-tlv.h)
pub mod errno;     // Error codes (ogs-errno.h)
pub mod log;       // Logging (ogs-log.h)
pub mod memory;    // Memory management (ogs-memory.h)
pub mod strings;   // String utilities (ogs-strings.h)
pub mod time;      // Time utilities (ogs-time.h)
pub mod conv;      // Conversion utilities (ogs-conv.h)
pub mod rand;      // Random number generation (ogs-rand.h)
pub mod uuid;      // UUID generation (ogs-uuid.h)
pub mod rbtree;    // Red-black tree (ogs-rbtree.h)
pub mod thread;    // Thread utilities (ogs-thread.h)
pub mod queue;     // Thread-safe queue (ogs-queue.h)
pub mod signal;    // Signal handling (ogs-signal.h)
pub mod sockaddr;  // Socket address (ogs-sockaddr.h)
pub mod socket;    // Socket operations (ogs-socket.h)
pub mod sockopt;   // Socket options (ogs-sockopt.h)
pub mod poll;      // Event polling (ogs-poll.h)
pub mod tcp;       // TCP server/client (ogs-tcp.h)
pub mod udp;       // UDP server/client (ogs-udp.h)

// Re-export commonly used types
pub use list::{OgsList, OgsLnode};
pub use pool::{OgsPool, OgsPoolId, OgsPoolWithId, PoolItem, OGS_INVALID_POOL_ID, OGS_MIN_POOL_ID, OGS_MAX_POOL_ID};
pub use hash::{OgsHash, OgsHashMap, OgsHashIter, ogs_hashfunc_default, OGS_HASH_KEY_STRING};
pub use pkbuf::OgsPkbuf;
pub use fsm::OgsFsm;
pub use errno::{OgsError, OGS_OK, OGS_ERROR};
pub use tlv::{OgsTlv, OgsTlvMsg, TlvError};
pub use uuid::OgsUuid;
pub use rbtree::{OgsRbtree, OgsRbnode, OgsRbtreeColor};
pub use thread::OgsThread;
pub use queue::OgsQueue;
pub use sockaddr::OgsSockaddr;
pub use socket::{OgsSock, OgsSocket, INVALID_SOCKET};
pub use sockopt::OgsSockopt;
pub use poll::{OgsPollset, OGS_POLLIN, OGS_POLLOUT};
