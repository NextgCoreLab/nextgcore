//! Generate the SLPP UPER codec from the vendored TS 38.355 ASN.1 modules.
//!
//! TS 38.355's eight modules import from each other in a cycle:
//! `SLPP-PDU-Definitions` imports the method contents, and every contents
//! module imports `maxNrOfUEs` and friends back from `SLPP-PDU-Definitions`.
//! The forked asn1-compiler orders MODULES topologically
//! (`compiler.rs::sorted_modules`), and `TopologicalSort::pop_all` returns
//! nothing for a strongly connected set, so seven of the eight modules were
//! dropped silently and only `NR-DiscoveryMessageMetaDataContents` came out.
//!
//! So this script compiles one module made by concatenating the eight module
//! bodies with their IMPORTS clauses removed. The vendored file stays
//! byte-for-byte what `extract_asn1.py` produced (its sha256 is in
//! `asn/PROVENANCE.md`). The merge changes no encoding. Every module is
//! `AUTOMATIC TAGS`, none has an EXPORTS clause (so each exports everything),
//! and no name is assigned twice. PER does not encode tags in any case. The
//! script checks the last two of those conditions and stops the build if one
//! fails, along with two more: exactly eight modules are present, and every
//! imported name is defined in the module it names.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use asn1_compiler::generator::{Codec, Derive, Visibility};
use asn1_compiler::Asn1Compiler;

/// The module count TS 38.355 V19.2.0 §6 defines.
const EXPECTED_MODULES: usize = 8;

struct Module {
    name: String,
    /// Body lines after BEGIN and the IMPORTS clause, before END.
    body: Vec<String>,
    /// (imported name, source module).
    imports: Vec<(String, String)>,
}

/// Strip an X.680 §12.6 comment. The schema uses only the end-of-line form,
/// so a line is cut at its first `--`.
fn code_of(line: &str) -> &str {
    line.find("--").map_or(line, |i| &line[..i])
}

/// Parse one IMPORTS line. `FROM` and its module name may sit on separate
/// lines (TS 38.355 puts them so), hence the carried `expect_module`.
fn parse_imports(
    code: &str,
    expect_module: &mut bool,
    pending: &mut Vec<String>,
    imports: &mut Vec<(String, String)>,
) {
    for w in code
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|w| !w.is_empty())
    {
        match w {
            "IMPORTS" => {}
            "FROM" => *expect_module = true,
            _ if *expect_module => {
                let module = w.trim_end_matches(';').to_string();
                for imported in pending.drain(..) {
                    imports.push((imported, module.clone()));
                }
                *expect_module = false;
            }
            _ => pending.push(w.trim_end_matches(';').to_string()),
        }
    }
}

fn parse_modules(text: &str) -> Vec<Module> {
    let lines: Vec<&str> = text.lines().collect();
    let mut modules = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let code = code_of(lines[i]).trim();
        let Some(name) = code.strip_suffix("DEFINITIONS AUTOMATIC TAGS ::=") else {
            assert!(
                !code.contains("DEFINITIONS"),
                "module header with tagging other than AUTOMATIC TAGS at line {}: {code}",
                i + 1
            );
            i += 1;
            continue;
        };
        let name = name.trim().to_string();
        i += 1;
        while code_of(lines[i]).trim().is_empty() {
            i += 1;
        }
        assert_eq!(code_of(lines[i]).trim(), "BEGIN", "{name}: BEGIN expected");
        i += 1;
        let mut body = Vec::new();
        let mut imports = Vec::new();
        let mut pending = Vec::new();
        let mut in_imports = false;
        let mut expect_module = false;
        loop {
            let line = lines[i];
            let code = code_of(line).trim();
            if code == "END" {
                break;
            }
            assert!(
                !code.starts_with("EXPORTS"),
                "{name}: EXPORTS clause unsupported"
            );
            if code.starts_with("IMPORTS") {
                in_imports = true;
            }
            if in_imports {
                parse_imports(code, &mut expect_module, &mut pending, &mut imports);
                if code.ends_with(';') {
                    in_imports = false;
                    assert!(
                        pending.is_empty() && !expect_module,
                        "{name}: names imported without FROM"
                    );
                }
            } else {
                body.push(line.to_string());
            }
            i += 1;
        }
        modules.push(Module {
            name,
            body,
            imports,
        });
        i += 1;
    }
    modules
}

/// The names a module assigns at the start of a line (`Name ::=` or
/// `value Type ::=`).
fn assigned_names(module: &Module) -> Vec<String> {
    module
        .body
        .iter()
        .filter_map(|l| {
            let code = code_of(l);
            if code.starts_with(char::is_whitespace) || !code.contains("::=") {
                return None;
            }
            code.split_whitespace().next().map(str::to_string)
        })
        .collect()
}

fn merged_schema(text: &str) -> String {
    let modules = parse_modules(text);
    assert_eq!(
        modules.len(),
        EXPECTED_MODULES,
        "TS 38.355 V19.2.0 defines {EXPECTED_MODULES} modules, found {}",
        modules.len()
    );
    let mut defined: BTreeMap<String, String> = BTreeMap::new();
    for m in &modules {
        for n in assigned_names(m) {
            if let Some(prev) = defined.insert(n.clone(), m.name.clone()) {
                panic!(
                    "{n} is assigned in both {prev} and {}; a merge would collide",
                    m.name
                );
            }
        }
    }
    for m in &modules {
        for (n, from) in &m.imports {
            assert_eq!(
                defined.get(n),
                Some(from),
                "{}: {n} imported FROM {from} is not defined there",
                m.name
            );
        }
    }
    let mut out =
        String::from("-- Generated by build.rs: the TS 38.355 modules, IMPORTS removed.\n");
    out.push_str("SLPP-Merged DEFINITIONS AUTOMATIC TAGS ::=\nBEGIN\n");
    for m in &modules {
        out.push_str(&format!("-- module {}\n", m.name));
        for l in &m.body {
            out.push_str(l);
            out.push('\n');
        }
    }
    out.push_str("END\n");
    out
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let schema = manifest_dir.join("asn").join("slpp-19.2.0.asn");
    let merged = out_dir.join("slpp-merged.asn");
    let output = out_dir.join("slpp.rs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", schema.display());

    let text = fs::read_to_string(&schema).expect("read the vendored SLPP schema");
    fs::write(&merged, merged_schema(&text)).expect("write the merged SLPP schema");

    // TS 38.355 §6.1: SLPP messages and IEs use BASIC-PER, unaligned variant.
    let mut compiler = Asn1Compiler::new(
        output.to_str().expect("OUT_DIR is valid UTF-8"),
        &Visibility::Public,
        vec![Codec::Uper],
        vec![Derive::Debug, Derive::Clone, Derive::PartialEq],
    );
    let merged_str = merged.to_str().expect("merged path is valid UTF-8");
    if let Err(e) = compiler.compile_files(&[merged_str]) {
        panic!("failed to compile the SLPP ASN.1 schema {merged_str}: {e}");
    }
}
