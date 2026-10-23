//! The TS 36.413 criticality oracle (#737).
//!
//! Every IE criticality an S1AP builder writes is chosen by hand in an
//! `ie(ID, CRIT, ...)` call; nothing in the generated codec derives it, and the
//! receiving eNB acts on it (TS 36.413 §10.3.4). After #560 deleted the
//! hand-written encoder, no test compared those choices with anything.
//!
//! This module reads the object sets of `asn/s1ap-19.2.0.asn` (TS 36.413
//! §9.3, V19.2.0) and checks every `(id, criticality)` an encoded PDU carries
//! against the set its container is defined with: the message's protocol IEs,
//! each list's items, and each type's extensions. [`assert_matches_ts_36_413`]
//! runs on every PDU a production builder encodes under `cfg(test)`
//! (`s1ap_gen::encode_pdu`), so the whole test suite pins the criticalities of
//! every message it builds.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The S1AP schema, as compiled into the codec.
const ASN: &str = include_str!("../../../../libs/nextgcore-s1ap-gen/asn/s1ap-19.2.0.asn");

struct Oracle {
    /// Object set name -> (IE id -> criticality: 0 reject, 1 ignore, 2 notify).
    sets: HashMap<String, HashMap<u16, u8>>,
    /// Generated container type name (`PathSwitchRequestAcknowledgeProtocolIEs`,
    /// `E_RABToBeSwitchedULList`, `CGIIE_Extensions`) -> object set name.
    containers: HashMap<String, String>,
}

fn rust_name(asn_name: &str) -> String {
    asn_name.replace('-', "_")
}

fn criticality(word: &str) -> Option<u8> {
    match word {
        "reject" => Some(0),
        "ignore" => Some(1),
        "notify" => Some(2),
        _ => None,
    }
}

/// The text between the outermost `{ {` and `} }` of a container reference.
fn set_ref(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let inner = text[start + 1..].trim_start();
    let inner = inner.strip_prefix('{')?;
    let end = inner.find('}')?;
    Some(inner[..end].trim().to_string())
}

fn parse() -> Oracle {
    // Strip comments, then split into top-level definitions (`Name ::= ...`).
    let text: String = ASN
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    let mut ids: HashMap<String, u16> = HashMap::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let [name, "ProtocolIE-ID", "::=", value] = words[..] {
            if let Ok(v) = value.parse() {
                ids.insert(name.to_string(), v);
            }
        }
    }

    let mut defs: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        // Every definition, and only a definition, has `::=` (some are
        // indented, some have no space before it: `TAIList::= ...`).
        let name = line
            .split("::=")
            .next()
            .and_then(|lhs| lhs.split_whitespace().next())
            .filter(|_| line.contains("::="));
        if let Some(name) = name {
            defs.push((name.to_string(), line.to_string()));
        } else if let Some(last) = defs.last_mut() {
            last.1.push('\n');
            last.1.push_str(line);
        }
    }

    let mut sets = HashMap::new();
    let mut containers = HashMap::new();
    for (name, body) in &defs {
        let header = body.lines().next().unwrap_or("");
        if header.contains("S1AP-PROTOCOL-IES ::=")
            || header.contains("S1AP-PROTOCOL-EXTENSION ::=")
        {
            let mut set = HashMap::new();
            for entry in body.split("ID ").skip(1) {
                let words: Vec<&str> = entry.split_whitespace().collect();
                let (Some(id_name), Some(pos)) = (
                    words.first(),
                    words.iter().position(|w| *w == "CRITICALITY"),
                ) else {
                    continue;
                };
                let (Some(id), Some(crit)) = (
                    ids.get(*id_name),
                    words.get(pos + 1).and_then(|w| criticality(w)),
                ) else {
                    continue;
                };
                set.insert(*id, crit);
            }
            sets.insert(name.clone(), set);
            continue;
        }
        // A list or single container defined directly: `L ::= ...{ {XIEs} }`.
        let rhs = header.split("::=").nth(1).unwrap_or("");
        if rhs.contains("Container") {
            if let Some(set) = set_ref(&body[body.find("::=").unwrap()..]) {
                containers.insert(rust_name(name), set);
            }
        }
        // A SEQUENCE with protocol IEs and/or extensions.
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with("protocolIEs") && t.contains("ProtocolIE-Container") {
                if let Some(set) = set_ref(t) {
                    containers.insert(format!("{}ProtocolIEs", rust_name(name)), set);
                }
            } else if t.starts_with("iE-Extensions") && t.contains("ProtocolExtensionContainer") {
                if let Some(set) = set_ref(t) {
                    containers.insert(format!("{}IE_Extensions", rust_name(name)), set);
                }
            }
        }
    }
    Oracle { sets, containers }
}

fn oracle() -> &'static Oracle {
    static ORACLE: OnceLock<Oracle> = OnceLock::new();
    ORACLE.get_or_init(parse)
}

/// Every `(container, id, criticality)` an encoded PDU carries, read from its
/// `Debug` form (each protocol IE field is a `<Container>_Entry { id:
/// ProtocolIE_ID(n), criticality: Criticality(c), .. }`).
pub(crate) fn entries(debug: &str) -> Vec<(String, u16, u8)> {
    const ID: &str = "_Entry { id: ProtocolIE_ID(";
    let mut out = Vec::new();
    let mut rest = debug;
    while let Some(at) = rest.find(ID) {
        let container_start = rest[..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |p| p + 1);
        let container = rest[container_start..at].to_string();
        let after = &rest[at + ID.len()..];
        let id: u16 = after[..after.find(')').unwrap()].parse().unwrap();
        let crit_at =
            after.find("criticality: Criticality(").unwrap() + "criticality: Criticality(".len();
        let crit: u8 = after[crit_at..crit_at + after[crit_at..].find(')').unwrap()]
            .parse()
            .unwrap();
        out.push((container, id, crit));
        rest = &after[crit_at..];
    }
    out
}

/// The criticality TS 36.413 gives IE `id` in `container`, or why it has none.
pub(crate) fn expected(container: &str, id: u16) -> Result<u8, String> {
    let o = oracle();
    let set = o
        .containers
        .get(container)
        .ok_or_else(|| format!("container {container} is not in the schema"))?;
    let ies = o
        .sets
        .get(set)
        .ok_or_else(|| format!("object set {set} (of {container}) is not in the schema"))?;
    ies.get(&id)
        .copied()
        .ok_or_else(|| format!("IE id {id} is not in object set {set} (of {container})"))
}

/// Panic unless every IE criticality of `pdu` is the one TS 36.413 §9.3 gives
/// it in its container's object set.
pub(crate) fn assert_matches_ts_36_413(pdu: &nextgcore_s1ap_gen::generated::S1AP_PDU) {
    let debug = format!("{pdu:?}");
    for (container, id, crit) in entries(&debug) {
        match expected(&container, id) {
            Ok(want) => assert_eq!(
                crit, want,
                "IE id {id} in {container} has criticality {crit}; TS 36.413 §9.3 gives {want} \
                 (0 reject, 1 ignore, 2 notify)"
            ),
            Err(why) => panic!("S1AP builder wrote an IE outside the schema: {why}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse finds the sets and containers it needs, with the values
    /// TS 36.413 §9.1.5.9 states for PATH SWITCH REQUEST ACKNOWLEDGE.
    #[test]
    fn the_schema_is_parsed() {
        let o = oracle();
        assert!(o.sets.len() > 300, "{} object sets", o.sets.len());
        assert!(
            o.containers.len() > 300,
            "{} containers",
            o.containers.len()
        );
        let c = "PathSwitchRequestAcknowledgeProtocolIEs";
        assert_eq!(expected(c, 0), Ok(1), "MME-UE-S1AP-ID ignore");
        assert_eq!(expected(c, 40), Ok(0), "SecurityContext reject");
        assert_eq!(expected(c, 66), Ok(1), "UE-AMBR ignore");
        assert_eq!(expected("E_RABToBeSwitchedULList", 94), Ok(1));
        assert!(expected(c, 9999).is_err());
        assert!(expected("NoSuchContainer", 0).is_err());
    }

    /// #737's two revert-checks, as tests: changing the Security Context of
    /// PATH SWITCH REQUEST ACKNOWLEDGE to ignore, or the UE-AMBR of UE CONTEXT
    /// MODIFICATION REQUEST to reject, is caught.
    #[test]
    fn a_wrong_criticality_is_caught() {
        let ok = "PathSwitchRequestAcknowledgeProtocolIEs_Entry { id: ProtocolIE_ID(40), \
                  criticality: Criticality(0), value: X }";
        let wrong = ok.replace("Criticality(0)", "Criticality(1)");
        let got = entries(ok);
        assert_eq!(
            got,
            vec![("PathSwitchRequestAcknowledgeProtocolIEs".to_string(), 40, 0)]
        );
        assert_eq!(expected(&got[0].0, got[0].1), Ok(0));
        let got = entries(&wrong);
        assert_ne!(expected(&got[0].0, got[0].1), Ok(got[0].2));
        assert_eq!(
            expected("UEContextModificationRequestProtocolIEs", 66),
            Ok(1)
        );
    }
}
