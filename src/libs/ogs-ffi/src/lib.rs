//! NextGCore FFI Bindings for C Comparison Testing
//!
//! This crate provides FFI bindings to the original C implementation
//! for property-based testing to verify algorithm parity.
//!
//! # Usage
//!
//! By default, this crate provides stub bindings that allow the Rust code
//! to compile without the C library. To generate actual bindings from the
//! C headers, set the environment variable:
//!
//! ```bash
//! OGS_FFI_GENERATE_BINDINGS=1 cargo build
//! ```
//!
//! # Linking
//!
//! When using actual bindings, you must also link against the compiled
//! NextGCore C libraries. This is typically done by building NextGCore first
//! and setting the appropriate library paths.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod core;
pub mod crypt;

// Include generated bindings when available
#[cfg(has_core_bindings)]
mod core_bindings {
    include!(concat!(env!("OUT_DIR"), "/core_bindings.rs"));
}

#[cfg(has_crypt_bindings)]
mod crypt_bindings {
    include!(concat!(env!("OUT_DIR"), "/crypt_bindings.rs"));
}

/// Check if C library bindings are available for comparison testing
pub fn c_library_available() -> bool {
    #[cfg(all(has_core_bindings, has_crypt_bindings))]
    {
        true
    }
    #[cfg(not(all(has_core_bindings, has_crypt_bindings)))]
    {
        false
    }
}

/// Re-export core bindings when available
#[cfg(has_core_bindings)]
pub use core_bindings::*;

/// Re-export crypt bindings when available  
#[cfg(has_crypt_bindings)]
pub use crypt_bindings::*;
