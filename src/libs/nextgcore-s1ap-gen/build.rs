//! Generate the S1AP APER codec from the TS 36.413 ASN.1 module.

use std::env;
use std::path::PathBuf;

use asn1_compiler::generator::{Codec, Derive, Visibility};
use asn1_compiler::Asn1Compiler;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let schema = manifest_dir.join("asn").join("s1ap-19.2.0.asn");
    let output = out_dir.join("s1ap.rs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", schema.display());

    // The same generator settings as nextgcore-ngap-gen and nextgsim-s1ap: S1AP,
    // like NGAP, is BASIC-PER Aligned (TS 36.413 §9.4).
    let mut compiler = Asn1Compiler::new(
        output.to_str().expect("OUT_DIR is valid UTF-8"),
        &Visibility::Public,
        vec![Codec::Aper],
        vec![Derive::Debug, Derive::Clone, Derive::PartialEq],
    );
    let schema_str = schema.to_str().expect("schema path is valid UTF-8");
    if let Err(e) = compiler.compile_files(&[schema_str]) {
        panic!("failed to compile the S1AP ASN.1 schema {schema_str}: {e}");
    }
}
