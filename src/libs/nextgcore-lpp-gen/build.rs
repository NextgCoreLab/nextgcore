//! Generate the LPP UPER codec from the vendored TS 37.355 ASN.1 modules.

use std::env;
use std::path::PathBuf;

use asn1_compiler::generator::{Codec, Derive, Visibility};
use asn1_compiler::Asn1Compiler;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let schema = manifest_dir.join("asn").join("lpp-19.3.0.asn");
    let output = out_dir.join("lpp.rs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", schema.display());

    // TS 37.355 §6.1: LPP PDUs are encoded with the basic UNALIGNED PER.
    let mut compiler = Asn1Compiler::new(
        output.to_str().expect("OUT_DIR is valid UTF-8"),
        &Visibility::Public,
        vec![Codec::Uper],
        vec![Derive::Debug, Derive::Clone, Derive::PartialEq],
    );
    let schema_str = schema.to_str().expect("schema path is valid UTF-8");
    if let Err(e) = compiler.compile_files(&[schema_str]) {
        panic!("failed to compile the LPP ASN.1 schema {schema_str}: {e}");
    }
}
