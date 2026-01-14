//! Memory management utilities
//!
//! Exact port of lib/core/ogs-memory.h and ogs-memory.c

use std::alloc::{alloc, dealloc, Layout};

/// Allocate memory (identical to ogs_malloc)
/// 
/// # Safety
/// Returns raw pointer that must be freed with ogs_free
pub unsafe fn ogs_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    let layout = Layout::from_size_align(size, 8).unwrap();
    alloc(layout)
}

/// Allocate zeroed memory (identical to ogs_calloc)
/// 
/// # Safety
/// Returns raw pointer that must be freed with ogs_free
pub unsafe fn ogs_calloc(count: usize, size: usize) -> *mut u8 {
    let total = count * size;
    let ptr = ogs_malloc(total);
    if !ptr.is_null() {
        std::ptr::write_bytes(ptr, 0, total);
    }
    ptr
}

/// Reallocate memory (identical to ogs_realloc)
/// 
/// # Safety
/// ptr must have been allocated by ogs_malloc/ogs_calloc
pub unsafe fn ogs_realloc(ptr: *mut u8, old_size: usize, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return ogs_malloc(new_size);
    }
    if new_size == 0 {
        ogs_free(ptr, old_size);
        return std::ptr::null_mut();
    }
    
    let new_ptr = ogs_malloc(new_size);
    if !new_ptr.is_null() {
        let copy_size = std::cmp::min(old_size, new_size);
        std::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
        ogs_free(ptr, old_size);
    }
    new_ptr
}

/// Free memory (identical to ogs_free)
/// 
/// # Safety
/// ptr must have been allocated by ogs_malloc/ogs_calloc
pub unsafe fn ogs_free(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        let layout = Layout::from_size_align(size, 8).unwrap();
        dealloc(ptr, layout);
    }
}

/// Duplicate memory block
/// 
/// # Safety
/// Returns raw pointer that must be freed with ogs_free
pub unsafe fn ogs_memdup(src: *const u8, size: usize) -> *mut u8 {
    if src.is_null() || size == 0 {
        return std::ptr::null_mut();
    }
    let ptr = ogs_malloc(size);
    if !ptr.is_null() {
        std::ptr::copy_nonoverlapping(src, ptr, size);
    }
    ptr
}
