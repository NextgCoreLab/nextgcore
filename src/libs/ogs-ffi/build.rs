//! Build script for generating FFI bindings
//!
//! This script uses bindgen to generate Rust bindings from NextGCore C headers.
//! It enables comparison testing between Rust and C implementations.

use std::env;
use std::path::PathBuf;

fn main() {
    // Declare custom cfg flags to suppress warnings
    println!("cargo::rustc-check-cfg=cfg(has_core_bindings)");
    println!("cargo::rustc-check-cfg=cfg(has_crypt_bindings)");
    // Get the project root directory (parent of rust_src)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(&manifest_dir)
        .parent() // libs
        .unwrap()
        .parent() // rust_src
        .unwrap()
        .parent() // project root
        .unwrap()
        .to_path_buf();

    let lib_dir = project_root.join("lib");
    let core_dir = lib_dir.join("core");
    let crypt_dir = lib_dir.join("crypt");

    // Tell cargo to rerun if headers change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", core_dir.display());
    println!("cargo:rerun-if-changed={}", crypt_dir.display());

    // Check if we should generate bindings (controlled by feature flag)
    // By default, we use pre-generated bindings for faster builds
    let generate_bindings = env::var("OGS_FFI_GENERATE_BINDINGS").is_ok();

    if !generate_bindings {
        // Use stub bindings for now - actual bindings will be generated
        // when OGS_FFI_GENERATE_BINDINGS=1 is set
        println!("cargo:warning=Using stub FFI bindings. Set OGS_FFI_GENERATE_BINDINGS=1 to generate from C headers.");
        return;
    }

    // Verify the C library headers exist
    if !core_dir.exists() {
        println!("cargo:warning=C library headers not found at {}. FFI bindings will be stubs.", core_dir.display());
        return;
    }

    // Generate bindings for core library
    generate_core_bindings(&core_dir, &lib_dir);

    // Generate bindings for crypt library
    if crypt_dir.exists() {
        generate_crypt_bindings(&crypt_dir, &lib_dir);
    }
}

fn generate_core_bindings(core_dir: &PathBuf, lib_dir: &PathBuf) {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Create a wrapper header that includes all core headers
    let wrapper_content = r#"
// Wrapper header for NextGCore core library bindings
#include "ogs-core.h"
"#;

    let wrapper_path = out_path.join("core_wrapper.h");
    std::fs::write(&wrapper_path, wrapper_content).expect("Failed to write wrapper header");

    let bindings = bindgen::Builder::default()
        .header(wrapper_path.to_str().unwrap())
        .clang_arg(format!("-I{}", core_dir.display()))
        .clang_arg(format!("-I{}", lib_dir.display()))
        // Parse all ogs_ prefixed functions and types
        .allowlist_function("ogs_.*")
        .allowlist_type("ogs_.*")
        .allowlist_var("OGS_.*")
        // Generate Rust enums for C enums
        .rustified_enum("ogs_.*")
        // Use core types
        .use_core()
        // Generate Debug trait implementations
        .derive_debug(true)
        .derive_default(true)
        // Handle size_t properly
        .size_t_is_usize(true)
        // Generate comments from C headers
        .generate_comments(true)
        .generate()
        .expect("Unable to generate core bindings");

    bindings
        .write_to_file(out_path.join("core_bindings.rs"))
        .expect("Couldn't write core bindings!");

    println!("cargo:rustc-cfg=has_core_bindings");
}

fn generate_crypt_bindings(crypt_dir: &PathBuf, lib_dir: &PathBuf) {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let core_dir = lib_dir.join("core");

    // Create a wrapper header for crypt library
    let wrapper_content = r#"
// Wrapper header for NextGCore crypt library bindings
#include "ogs-crypt.h"
#include "milenage.h"
#include "kasumi.h"
#include "snow-3g.h"
#include "zuc.h"
"#;

    let wrapper_path = out_path.join("crypt_wrapper.h");
    std::fs::write(&wrapper_path, wrapper_content).expect("Failed to write crypt wrapper header");

    let bindings = bindgen::Builder::default()
        .header(wrapper_path.to_str().unwrap())
        .clang_arg(format!("-I{}", crypt_dir.display()))
        .clang_arg(format!("-I{}", core_dir.display()))
        .clang_arg(format!("-I{}", lib_dir.display()))
        // Parse crypto functions
        .allowlist_function("ogs_.*")
        .allowlist_function("milenage_.*")
        .allowlist_function("kasumi_.*")
        .allowlist_function("snow_3g_.*")
        .allowlist_function("zuc_.*")
        .allowlist_type("ogs_.*")
        .allowlist_var("OGS_.*")
        .use_core()
        .derive_debug(true)
        .derive_default(true)
        .size_t_is_usize(true)
        .generate_comments(true)
        .generate()
        .expect("Unable to generate crypt bindings");

    bindings
        .write_to_file(out_path.join("crypt_bindings.rs"))
        .expect("Couldn't write crypt bindings!");

    println!("cargo:rustc-cfg=has_crypt_bindings");
}
