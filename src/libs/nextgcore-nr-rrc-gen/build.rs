//! Generate the TS 38.331 UPER codec from the vendored ASN.1 modules (#585).

use std::env;
use std::path::PathBuf;

use asn1_compiler::generator::{Codec, Derive, Visibility};
use asn1_compiler::Asn1Compiler;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let output = out_dir.join("nr_rrc.rs");
    let schemas: Vec<PathBuf> = ["rrc-19.3.0.asn1"]
        .iter()
        .map(|f| manifest_dir.join("asn").join(f))
        .collect();

    println!("cargo:rerun-if-changed=build.rs");
    for s in &schemas {
        println!("cargo:rerun-if-changed={}", s.display());
    }

    // RRC is encoded with the basic UNALIGNED PER (TS 38.331 §8).
    let mut compiler = Asn1Compiler::new(
        output.to_str().expect("OUT_DIR is valid UTF-8"),
        &Visibility::Public,
        vec![Codec::Uper],
        vec![Derive::Debug, Derive::Clone, Derive::PartialEq],
    );
    let paths: Vec<&str> = schemas
        .iter()
        .map(|s| s.to_str().expect("schema path is valid UTF-8"))
        .collect();
    if let Err(e) = compiler.compile_files(&paths) {
        panic!("failed to compile the TS 38.331 ASN.1 schema: {e}");
    }
}
