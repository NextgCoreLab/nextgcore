//! Generate the NGAP APER codec from the vendored TS 38.413 ASN.1 module.

use std::env;
use std::path::PathBuf;

use asn1_compiler::generator::{Codec, Derive, Visibility};
use asn1_compiler::Asn1Compiler;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let schema = manifest_dir.join("asn").join("ngap-17.9.asn");
    let output = out_dir.join("ngap.rs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", schema.display());

    // The same generator settings as nextgsim-ngap/build.rs, so the two repos
    // generate identical NGAP types rather than merely compatible ones.
    let mut compiler = Asn1Compiler::new(
        output.to_str().expect("OUT_DIR is valid UTF-8"),
        &Visibility::Public,
        vec![Codec::Aper],
        vec![Derive::Debug, Derive::Clone, Derive::PartialEq],
    );
    let schema_str = schema.to_str().expect("schema path is valid UTF-8");
    if let Err(e) = compiler.compile_files(&[schema_str]) {
        panic!("failed to compile the NGAP ASN.1 schema {schema_str}: {e}");
    }
}
