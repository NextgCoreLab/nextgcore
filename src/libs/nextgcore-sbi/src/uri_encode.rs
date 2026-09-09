//! Percent-encoding and -decoding for SBI URIs and form bodies (issues #101,
//! #65).
//!
//! # Why there are two functions and not one
//!
//! Before this module the repo carried two hand-rolled encoders:
//!
//! | | space | used for |
//! |---|---|---|
//! | `oauth::url_encode` (private) | `+` | the `application/x-www-form-urlencoded` token-request body |
//! | `pcfd::sbi_path::percent_encode` | `%20` | an RFC 3986 query component |
//!
//! They look redundant, and the obvious cleanup — pick one, share it, delete the
//! other — **would introduce a bug**. The `+`-for-space convention belongs to
//! `application/x-www-form-urlencoded`; in a strict RFC 3986 query component `+`
//! is a **literal plus**, not a space. So encoding a discovery factor with the
//! form encoder corrupts every value containing a space the moment a conformant
//! NRF parses it, and encoding a form body with the query encoder sends `%20`
//! where a form parser expects `+`.
//!
//! The two copies were therefore not duplication — they were two different
//! encodings that resembled each other. This module keeps both, names them for
//! the surface they belong to, and [`tests::query_and_form_encoders_differ_on_space`]
//! pins the difference so a later tidy-up cannot merge them.
//!
//! Both share the RFC 3986 *unreserved* set (`ALPHA / DIGIT / "-" / "." / "_" /
//! "~"`) and encode everything else, which is deliberately conservative: a
//! sub-delimiter that would be legal unencoded in some position is still safe
//! encoded, whereas the reverse is not true.

/// Percent-encode a value for use in an RFC 3986 **query component**.
///
/// Space becomes `%20`. Use this for anything going into a URI — query
/// parameters, path segments, `Location` values.
///
/// This is what makes a structured SBI discovery factor survive: an
/// `3gpp-Sbi-Discovery-snssais` header carrying a JSON list
/// (`[{"sst":1,"sd":"000001"}]`) contains `[`, `{`, `"` and `:`, every one of
/// which makes `Uri::parse` reject the assembled URI. Before #101 the SCP's
/// delegated discovery died with 502 before the query ever left the process.
pub fn encode_query_value(s: &str) -> String {
    encode_with(s, SpaceAs::Percent20)
}

/// Percent-encode a value for an `application/x-www-form-urlencoded` **body**.
///
/// Space becomes `+`. Use this only for form bodies — notably the NRF
/// access-token request, whose media type mandates this encoding.
pub fn encode_form_value(s: &str) -> String {
    encode_with(s, SpaceAs::Plus)
}

/// How a space is represented — the single point on which the two encodings
/// differ, kept as an explicit choice rather than a duplicated loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpaceAs {
    /// RFC 3986 query component.
    Percent20,
    /// `application/x-www-form-urlencoded`.
    Plus,
}

/// Percent-**decode** a value taken from an RFC 3986 **query component**
/// (issue #65).
///
/// `+` is a **literal plus**, not a space — the exact mirror of
/// [`encode_query_value`], and the reason this is a separate function from
/// [`decode_form_value`]. Getting this wrong is not theoretical: a query value
/// carrying an RFC 3339 timestamp (`2026-01-01T00:00:00+02:00`, TS 29.571
/// `DateTime`) or a base64 token is silently corrupted by the form decoder.
///
/// Invalid escapes are left verbatim rather than rejected: a trailing `%`, or a
/// `%zz` that is not two hex digits, passes through as written. A query
/// parameter is attacker-controlled input on a network-facing path, and the
/// alternative — failing the whole request — turns a cosmetically malformed
/// value into a 400 for a request that may not even read that parameter.
pub fn decode_query_value(s: &str) -> String {
    decode_with(s, SpaceAs::Percent20)
}

/// Percent-**decode** a value taken from an `application/x-www-form-urlencoded`
/// **body** (issue #65).
///
/// `+` decodes to a space, per the media type. Use this only for form bodies —
/// notably the NRF access-token request (`grant_type`, `scope`, `nfInstanceId`).
pub fn decode_form_value(s: &str) -> String {
    decode_with(s, SpaceAs::Plus)
}

fn decode_with(s: &str, space: SpaceAs) -> String {
    // Decode over BYTES and build the result as bytes: a percent-escape names an
    // OCTET, and a multi-byte UTF-8 scalar arrives as several independent
    // escapes (RFC 3986 §2.5) that only form a character once reassembled.
    // Decoding per-char would make `%C3%A9` two replacement characters.
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    // Not a valid escape: emit the '%' verbatim and continue, so
                    // `100%` and `%zz` survive unchanged.
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' if space == SpaceAs::Plus => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // A percent-escape can name an octet that is not valid UTF-8 (a truncated
    // sequence, or a deliberately malformed one). Lossy conversion keeps the
    // decoder infallible; the alternative is a `Result` at ~40 call sites for an
    // input no conformant peer produces.
    String::from_utf8_lossy(&out).into_owned()
}

/// Value of a single hex digit, or `None` when the byte is not one.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn encode_with(s: &str, space: SpaceAs) -> String {
    let mut out = String::with_capacity(s.len());
    // Iterate BYTES, not chars: a multi-byte UTF-8 scalar must be encoded one
    // octet at a time (RFC 3986 §2.5), and `for b in s.bytes()` gives exactly
    // that without a per-char re-encode buffer.
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' if space == SpaceAs::Plus => out.push('+'),
            _ => {
                out.push('%');
                // Uppercase hex: RFC 3986 §2.1 says producers should use it.
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The anti-deduplication guard.** These two functions exist because they
    /// disagree on exactly one input, and merging them would silently corrupt one
    /// of the two surfaces. If this test is failing because someone unified them,
    /// read the module docs before "fixing" it.
    #[test]
    fn query_and_form_encoders_differ_on_space() {
        assert_eq!(encode_query_value("a b"), "a%20b");
        assert_eq!(encode_form_value("a b"), "a+b");
        // ...and agree on everything else.
        for input in ["", "plain", "a=b&c", "[{\"sst\":1}]", "café", "a+b", "~-._"] {
            assert_eq!(
                encode_query_value(input).replace("%20", "+"),
                encode_form_value(input),
                "the encoders must differ ONLY on space, input {input:?}"
            );
        }
    }

    /// The unreserved set passes through untouched; a literal `+` is encoded by
    /// both, so a form value cannot be confused with a space on decode.
    #[test]
    fn unreserved_passes_through_and_plus_is_escaped() {
        let unreserved = "abcXYZ019-._~";
        assert_eq!(encode_query_value(unreserved), unreserved);
        assert_eq!(encode_form_value(unreserved), unreserved);
        assert_eq!(encode_query_value("a+b"), "a%2Bb");
        assert_eq!(
            encode_form_value("a+b"),
            "a%2Bb",
            "a literal plus must not decode back to a space"
        );
    }

    /// The #101 breaker: a JSON discovery factor. Every one of `[ { \" : , } ]`
    /// is encoded, so the assembled URI parses.
    #[test]
    fn a_json_discovery_factor_is_fully_encoded() {
        let snssais = r#"[{"sst":1,"sd":"000001"}]"#;
        let encoded = encode_query_value(snssais);
        for illegal in ['[', ']', '{', '}', '"', ' '] {
            assert!(
                !encoded.contains(illegal),
                "{illegal:?} must not survive encoding, got {encoded}"
            );
        }
        assert_eq!(
            encoded,
            "%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D%5D"
        );
    }

    /// Multi-byte UTF-8 is encoded per octet, uppercase hex (RFC 3986 §2.1/§2.5).
    #[test]
    fn multibyte_utf8_is_encoded_per_octet() {
        assert_eq!(encode_query_value("é"), "%C3%A9");
        assert_eq!(encode_query_value("日"), "%E6%97%A5");
        // Uppercase, not lowercase.
        assert_eq!(encode_query_value("\u{7f}"), "%7F");
    }

    /// **The decoder's anti-deduplication guard** (issue #65), mirroring
    /// [`query_and_form_encoders_differ_on_space`]. The two decoders disagree on
    /// exactly one input for the same reason the encoders do.
    #[test]
    fn query_and_form_decoders_differ_on_plus() {
        assert_eq!(decode_query_value("a+b"), "a+b");
        assert_eq!(decode_form_value("a+b"), "a b");
        // %20 is a space for both.
        assert_eq!(decode_query_value("a%20b"), "a b");
        assert_eq!(decode_form_value("a%20b"), "a b");
    }

    /// The concrete corruption the split prevents: an RFC 3339 `DateTime` and a
    /// base64 value both carry a meaningful literal `+`. Decoding either with the
    /// form decoder silently changes the value — for the timestamp, into
    /// something the RFC 3339 parser rejects, which every consumer in this tree
    /// reads as "no deadline".
    #[test]
    fn a_literal_plus_in_a_query_value_is_not_a_space() {
        assert_eq!(
            decode_query_value("2026-01-01T00:00:00+02:00"),
            "2026-01-01T00:00:00+02:00"
        );
        assert_eq!(decode_query_value("YWJj+ZGVm"), "YWJj+ZGVm");
        // What the form decoder would have done to them.
        assert_eq!(
            decode_form_value("2026-01-01T00:00:00+02:00"),
            "2026-01-01T00:00:00 02:00"
        );
    }

    /// Encode-then-decode is the identity for every value in this tree's query
    /// vocabulary, INCLUDING one already containing a percent-escape — the case
    /// that a double-decode (server decodes, then an NF's leftover local shim
    /// decodes again) gets wrong.
    #[test]
    fn query_encode_decode_round_trips() {
        for input in [
            "",
            "plain",
            r#"[{"sst":1,"sd":"000001"}]"#,
            "a=b&c",
            "café",
            "a+b",
            "~-._",
            "100%",
            // Already-escaped text: encoding gives %2520, and ONE decode must
            // return the literal %20 rather than a space.
            "a%20b",
            "2026-01-01T00:00:00+02:00",
        ] {
            assert_eq!(
                decode_query_value(&encode_query_value(input)),
                input,
                "round trip must be the identity for {input:?}"
            );
        }
        // The double-decode hazard, stated as an assertion: decoding twice does
        // NOT give the input back once the value contained an escape.
        let twice = decode_query_value(&decode_query_value(&encode_query_value("a%20b")));
        assert_eq!(twice, "a b", "second decode corrupts an escaped value");
    }

    /// A conformant percent-encoded JSON array — the MBS `tmgi-list` shape the
    /// issue names — decodes back to parseable JSON.
    #[test]
    fn an_encoded_json_array_decodes_to_parseable_json() {
        let encoded = "%5B%7B%22sst%22%3A1%7D%5D";
        let decoded = decode_query_value(encoded);
        assert_eq!(decoded, r#"[{"sst":1}]"#);
        let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("valid JSON");
        assert_eq!(parsed[0]["sst"], 1);
    }

    /// Malformed escapes pass through verbatim rather than failing the decode.
    /// nrfd's local decoder behaved this way and its tests pinned it; the shared
    /// decoder keeps the behaviour so removing that copy is not a change.
    #[test]
    fn malformed_escapes_pass_through() {
        assert_eq!(decode_query_value("100%"), "100%");
        assert_eq!(decode_query_value("%zz"), "%zz");
        assert_eq!(decode_query_value("%2"), "%2");
        assert_eq!(decode_query_value("%"), "%");
        assert_eq!(decode_query_value("a%2"), "a%2");
        // A valid escape after a malformed one still decodes.
        assert_eq!(decode_query_value("%zz%20"), "%zz ");
    }

    /// Multi-byte UTF-8 is reassembled from its per-octet escapes.
    #[test]
    fn multibyte_utf8_decodes_from_per_octet_escapes() {
        assert_eq!(decode_query_value("%C3%A9"), "é");
        assert_eq!(decode_query_value("%E6%97%A5"), "日");
        // Lowercase hex decodes too (RFC 3986 §2.1: producers SHOULD uppercase,
        // recipients MUST accept both).
        assert_eq!(decode_query_value("%c3%a9"), "é");
    }
}
