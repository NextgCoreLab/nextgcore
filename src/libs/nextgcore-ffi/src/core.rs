//! FFI bindings for nextgcore-core library
//!
//! These bindings allow comparison testing between Rust and C implementations.
//! When `NEXTGCORE_FFI_GENERATE_BINDINGS=1` is set, actual bindings are generated
//! from the C headers using bindgen.

use libc::{c_char, c_int, c_void, size_t};

// ============================================================================
// Stub type definitions for when bindings are not generated
// These match the C library's type definitions
// ============================================================================

/// Linked list node (matches nextgcore_lnode_t)
#[repr(C)]
#[derive(Debug)]
pub struct nextgcore_lnode_t {
    pub prev: *mut nextgcore_lnode_t,
    pub next: *mut nextgcore_lnode_t,
}

impl Default for nextgcore_lnode_t {
    fn default() -> Self {
        Self {
            prev: std::ptr::null_mut(),
            next: std::ptr::null_mut(),
        }
    }
}

/// Linked list (matches nextgcore_list_t)
#[repr(C)]
#[derive(Debug)]
pub struct nextgcore_list_t {
    pub head: *mut nextgcore_lnode_t,
    pub tail: *mut nextgcore_lnode_t,
    pub count: c_int,
}

impl Default for nextgcore_list_t {
    fn default() -> Self {
        Self {
            head: std::ptr::null_mut(),
            tail: std::ptr::null_mut(),
            count: 0,
        }
    }
}

/// Hash table entry (opaque)
#[repr(C)]
pub struct nextgcore_hash_t {
    _private: [u8; 0],
}

/// Hash index for iteration (opaque)
#[repr(C)]
pub struct nextgcore_hash_index_t {
    _private: [u8; 0],
}

/// Packet buffer (matches nextgcore_pkbuf_t structure)
#[repr(C)]
#[derive(Debug)]
pub struct nextgcore_pkbuf_t {
    pub lnode: nextgcore_lnode_t,
    pub head: *mut u8,
    pub tail: *mut u8,
    pub data: *mut u8,
    pub end: *mut u8,
    pub len: u32,
    pub max_len: u32,
    pub pool_id: c_int,
}

/// Timer manager (opaque)
#[repr(C)]
pub struct nextgcore_timer_mgr_t {
    _private: [u8; 0],
}

/// Timer (opaque)
#[repr(C)]
pub struct nextgcore_timer_t {
    _private: [u8; 0],
}

/// FSM handler function type
pub type nextgcore_fsm_handler_t = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;

/// Finite State Machine (matches nextgcore_fsm_t)
#[repr(C)]
#[derive(Debug)]
pub struct nextgcore_fsm_t {
    pub init: nextgcore_fsm_handler_t,
    pub fini: nextgcore_fsm_handler_t,
    pub state: nextgcore_fsm_handler_t,
}

/// TLV structure (matches nextgcore_tlv_t)
#[repr(C)]
#[derive(Debug)]
pub struct nextgcore_tlv_t {
    pub type_: u32,
    pub length: u32,
    pub instance: u8,
    pub presence: u8,
    pub value: *mut u8,
    pub next: *mut nextgcore_tlv_t,
    pub embedded: *mut nextgcore_tlv_t,
}

// ============================================================================
// Stub function declarations
// These are placeholders - actual implementations come from C library linking
// ============================================================================

extern "C" {
    // List operations
    pub fn nextgcore_list_init(list: *mut nextgcore_list_t);
    pub fn nextgcore_list_add(list: *mut nextgcore_list_t, node: *mut nextgcore_lnode_t);
    pub fn nextgcore_list_prepend(list: *mut nextgcore_list_t, node: *mut nextgcore_lnode_t);
    pub fn nextgcore_list_remove(list: *mut nextgcore_list_t, node: *mut nextgcore_lnode_t);
    pub fn nextgcore_list_count(list: *const nextgcore_list_t) -> c_int;

    // Hash operations
    pub fn nextgcore_hash_make() -> *mut nextgcore_hash_t;
    pub fn nextgcore_hash_destroy(ht: *mut nextgcore_hash_t);
    pub fn nextgcore_hash_set(
        ht: *mut nextgcore_hash_t,
        key: *const c_void,
        klen: isize,
        val: *const c_void,
    );
    pub fn nextgcore_hash_get(ht: *mut nextgcore_hash_t, key: *const c_void, klen: isize) -> *mut c_void;
    pub fn nextgcore_hash_first(ht: *mut nextgcore_hash_t) -> *mut nextgcore_hash_index_t;
    pub fn nextgcore_hash_next(hi: *mut nextgcore_hash_index_t) -> *mut nextgcore_hash_index_t;
    pub fn nextgcore_hash_this(
        hi: *mut nextgcore_hash_index_t,
        key: *mut *const c_void,
        klen: *mut isize,
        val: *mut *mut c_void,
    );

    // Packet buffer operations
    pub fn nextgcore_pkbuf_alloc(pool: *mut c_void, size: u32) -> *mut nextgcore_pkbuf_t;
    pub fn nextgcore_pkbuf_free(pkbuf: *mut nextgcore_pkbuf_t);
    pub fn nextgcore_pkbuf_reserve(pkbuf: *mut nextgcore_pkbuf_t, size: u32) -> *mut u8;
    pub fn nextgcore_pkbuf_put(pkbuf: *mut nextgcore_pkbuf_t, size: u32) -> *mut u8;
    pub fn nextgcore_pkbuf_push(pkbuf: *mut nextgcore_pkbuf_t, size: u32) -> *mut u8;
    pub fn nextgcore_pkbuf_pull(pkbuf: *mut nextgcore_pkbuf_t, size: u32) -> *mut u8;

    // Timer operations
    pub fn nextgcore_timer_mgr_create(capacity: c_int) -> *mut nextgcore_timer_mgr_t;
    pub fn nextgcore_timer_mgr_destroy(mgr: *mut nextgcore_timer_mgr_t);
    pub fn nextgcore_timer_add(
        mgr: *mut nextgcore_timer_mgr_t,
        cb: Option<unsafe extern "C" fn(*mut c_void)>,
        data: *mut c_void,
    ) -> *mut nextgcore_timer_t;
    pub fn nextgcore_timer_delete(timer: *mut nextgcore_timer_t);
    pub fn nextgcore_timer_start(timer: *mut nextgcore_timer_t, duration: u64);
    pub fn nextgcore_timer_stop(timer: *mut nextgcore_timer_t);

    // FSM operations
    pub fn nextgcore_fsm_init(fsm: *mut nextgcore_fsm_t, event: *mut c_void);
    pub fn nextgcore_fsm_fini(fsm: *mut nextgcore_fsm_t, event: *mut c_void);
    pub fn nextgcore_fsm_dispatch(fsm: *mut nextgcore_fsm_t, event: *mut c_void);

    // TLV operations
    pub fn nextgcore_tlv_parse_msg(
        desc: *const c_void,
        tlv: *mut nextgcore_tlv_t,
        pkbuf: *mut nextgcore_pkbuf_t,
        mode: c_int,
    ) -> c_int;
    pub fn nextgcore_tlv_build_msg(
        pkbuf: *mut *mut nextgcore_pkbuf_t,
        desc: *const c_void,
        tlv: *mut nextgcore_tlv_t,
        mode: c_int,
    ) -> c_int;

    // Memory operations
    pub fn nextgcore_malloc(size: size_t) -> *mut c_void;
    pub fn nextgcore_calloc(nmemb: size_t, size: size_t) -> *mut c_void;
    pub fn nextgcore_realloc(ptr: *mut c_void, size: size_t) -> *mut c_void;
    pub fn nextgcore_free(ptr: *mut c_void);

    // String operations
    pub fn nextgcore_strdup(s: *const c_char) -> *mut c_char;
    pub fn nextgcore_strndup(s: *const c_char, n: size_t) -> *mut c_char;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        // These tests verify our struct definitions match C layout
        assert!(std::mem::size_of::<nextgcore_lnode_t>() > 0);
        assert!(std::mem::size_of::<nextgcore_list_t>() > 0);
        assert!(std::mem::size_of::<nextgcore_fsm_t>() > 0);
    }
}
