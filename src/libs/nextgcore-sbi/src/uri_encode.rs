//! Percent-encoding for SBI URIs and form bodies (issue #101).
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
}
