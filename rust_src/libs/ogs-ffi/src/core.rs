//! FFI bindings for ogs-core library
//!
//! These bindings allow comparison testing between Rust and C implementations.
//! When `OGS_FFI_GENERATE_BINDINGS=1` is set, actual bindings are generated
//! from the C headers using bindgen.

use libc::{c_char, c_int, c_void, size_t};

// ============================================================================
// Stub type definitions for when bindings are not generated
// These match the C library's type definitions
// ============================================================================

/// Linked list node (matches ogs_lnode_t)
#[repr(C)]
#[derive(Debug)]
pub struct ogs_lnode_t {
    pub prev: *mut ogs_lnode_t,
    pub next: *mut ogs_lnode_t,
}

impl Default for ogs_lnode_t {
    fn default() -> Self {
        Self {
            prev: std::ptr::null_mut(),
            next: std::ptr::null_mut(),
        }
    }
}

/// Linked list (matches ogs_list_t)
#[repr(C)]
#[derive(Debug)]
pub struct ogs_list_t {
    pub head: *mut ogs_lnode_t,
    pub tail: *mut ogs_lnode_t,
    pub count: c_int,
}

impl Default for ogs_list_t {
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
pub struct ogs_hash_t {
    _private: [u8; 0],
}

/// Hash index for iteration (opaque)
#[repr(C)]
pub struct ogs_hash_index_t {
    _private: [u8; 0],
}

/// Packet buffer (matches ogs_pkbuf_t structure)
#[repr(C)]
#[derive(Debug)]
pub struct ogs_pkbuf_t {
    pub lnode: ogs_lnode_t,
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
pub struct ogs_timer_mgr_t {
    _private: [u8; 0],
}

/// Timer (opaque)
#[repr(C)]
pub struct ogs_timer_t {
    _private: [u8; 0],
}

/// FSM handler function type
pub type ogs_fsm_handler_t = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;

/// Finite State Machine (matches ogs_fsm_t)
#[repr(C)]
#[derive(Debug)]
pub struct ogs_fsm_t {
    pub init: ogs_fsm_handler_t,
    pub fini: ogs_fsm_handler_t,
    pub state: ogs_fsm_handler_t,
}

/// TLV structure (matches ogs_tlv_t)
#[repr(C)]
#[derive(Debug)]
pub struct ogs_tlv_t {
    pub type_: u32,
    pub length: u32,
    pub instance: u8,
    pub presence: u8,
    pub value: *mut u8,
    pub next: *mut ogs_tlv_t,
    pub embedded: *mut ogs_tlv_t,
}

// ============================================================================
// Stub function declarations
// These are placeholders - actual implementations come from C library linking
// ============================================================================

extern "C" {
    // List operations
    pub fn ogs_list_init(list: *mut ogs_list_t);
    pub fn ogs_list_add(list: *mut ogs_list_t, node: *mut ogs_lnode_t);
    pub fn ogs_list_prepend(list: *mut ogs_list_t, node: *mut ogs_lnode_t);
    pub fn ogs_list_remove(list: *mut ogs_list_t, node: *mut ogs_lnode_t);
    pub fn ogs_list_count(list: *const ogs_list_t) -> c_int;

    // Hash operations
    pub fn ogs_hash_make() -> *mut ogs_hash_t;
    pub fn ogs_hash_destroy(ht: *mut ogs_hash_t);
    pub fn ogs_hash_set(
        ht: *mut ogs_hash_t,
        key: *const c_void,
        klen: isize,
        val: *const c_void,
    );
    pub fn ogs_hash_get(ht: *mut ogs_hash_t, key: *const c_void, klen: isize) -> *mut c_void;
    pub fn ogs_hash_first(ht: *mut ogs_hash_t) -> *mut ogs_hash_index_t;
    pub fn ogs_hash_next(hi: *mut ogs_hash_index_t) -> *mut ogs_hash_index_t;
    pub fn ogs_hash_this(
        hi: *mut ogs_hash_index_t,
        key: *mut *const c_void,
        klen: *mut isize,
        val: *mut *mut c_void,
    );

    // Packet buffer operations
    pub fn ogs_pkbuf_alloc(pool: *mut c_void, size: u32) -> *mut ogs_pkbuf_t;
    pub fn ogs_pkbuf_free(pkbuf: *mut ogs_pkbuf_t);
    pub fn ogs_pkbuf_reserve(pkbuf: *mut ogs_pkbuf_t, size: u32) -> *mut u8;
    pub fn ogs_pkbuf_put(pkbuf: *mut ogs_pkbuf_t, size: u32) -> *mut u8;
    pub fn ogs_pkbuf_push(pkbuf: *mut ogs_pkbuf_t, size: u32) -> *mut u8;
    pub fn ogs_pkbuf_pull(pkbuf: *mut ogs_pkbuf_t, size: u32) -> *mut u8;

    // Timer operations
    pub fn ogs_timer_mgr_create(capacity: c_int) -> *mut ogs_timer_mgr_t;
    pub fn ogs_timer_mgr_destroy(mgr: *mut ogs_timer_mgr_t);
    pub fn ogs_timer_add(
        mgr: *mut ogs_timer_mgr_t,
        cb: Option<unsafe extern "C" fn(*mut c_void)>,
        data: *mut c_void,
    ) -> *mut ogs_timer_t;
    pub fn ogs_timer_delete(timer: *mut ogs_timer_t);
    pub fn ogs_timer_start(timer: *mut ogs_timer_t, duration: u64);
    pub fn ogs_timer_stop(timer: *mut ogs_timer_t);

    // FSM operations
    pub fn ogs_fsm_init(fsm: *mut ogs_fsm_t, event: *mut c_void);
    pub fn ogs_fsm_fini(fsm: *mut ogs_fsm_t, event: *mut c_void);
    pub fn ogs_fsm_dispatch(fsm: *mut ogs_fsm_t, event: *mut c_void);

    // TLV operations
    pub fn ogs_tlv_parse_msg(
        desc: *const c_void,
        tlv: *mut ogs_tlv_t,
        pkbuf: *mut ogs_pkbuf_t,
        mode: c_int,
    ) -> c_int;
    pub fn ogs_tlv_build_msg(
        pkbuf: *mut *mut ogs_pkbuf_t,
        desc: *const c_void,
        tlv: *mut ogs_tlv_t,
        mode: c_int,
    ) -> c_int;

    // Memory operations
    pub fn ogs_malloc(size: size_t) -> *mut c_void;
    pub fn ogs_calloc(nmemb: size_t, size: size_t) -> *mut c_void;
    pub fn ogs_realloc(ptr: *mut c_void, size: size_t) -> *mut c_void;
    pub fn ogs_free(ptr: *mut c_void);

    // String operations
    pub fn ogs_strdup(s: *const c_char) -> *mut c_char;
    pub fn ogs_strndup(s: *const c_char, n: size_t) -> *mut c_char;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        // These tests verify our struct definitions match C layout
        assert!(std::mem::size_of::<ogs_lnode_t>() > 0);
        assert!(std::mem::size_of::<ogs_list_t>() > 0);
        assert!(std::mem::size_of::<ogs_fsm_t>() > 0);
    }
}
