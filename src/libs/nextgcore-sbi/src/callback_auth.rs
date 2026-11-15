//! Callback routes that authenticate by their own token instead of an OAuth2
//! bearer (#1421).
//!
//! TS 33.501 §13.4.1: "The OAuth 2.0 framework does not apply to the
//! notification operation"; TS 29.500 §6.7.3: for the notify operation "OAuth
//! 2.0 access token is not used". A conformant notification sender therefore
//! sends no bearer, and a listener with `require_oauth2` answered 401 to every
//! notification its own NF subscribed for.
//!
//! An NF lists, per server, the callback routes it serves whose URI ends in an
//! unguessable per-subscription token it minted (the #940 / #753 pattern, the
//! segments in [`crate::log_redact::CALLBACK_TOKEN_SEGMENTS`]). Each entry is an
//! exact route shape plus the NF's own check that the token in the path is one
//! it currently holds. The server skips bearer verification only when the
//! method matches, the raw path matches the shape segment for segment, and the
//! NF's check accepts the token. Anything else (another route, a variant
//! spelling of this one, a wrong, stale or missing token) is held to the bearer
//! check exactly as before, so the default stays "every route requires a
//! token".
//!
//! The match is deliberately strict, so that a request the matcher admits is
//! routed by the NF's router to the callback arm and nowhere else:
//! - exact segment count; no empty segment (so no `//` and no trailing `/`);
//! - literal segments compared byte for byte against the raw (still
//!   percent-encoded) path, so `%2D` for `-` is a different, non-exempt path;
//! - variable and token segments drawn from a small unreserved charset with no
//!   `%`, and never `.` or `..`.
//!
//! The query string is not part of the match: the server matches on the path
//! alone and the NF routers route on the path alone.

use std::fmt;
use std::sync::Arc;

/// The variable parts of a matched callback path, handed to the NF's check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackPath<'a> {
    /// The `{var}` segments, in path order.
    pub vars: Vec<&'a str>,
    /// The `{token}` segment (always the last one).
    pub token: &'a str,
}

/// The NF's verdict on a callback token: `true` only for a token it holds now.
pub type CallbackTokenCheck = Arc<dyn Fn(&CallbackPath<'_>) -> bool + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Var,
    Token,
}

/// One callback route exempt from bearer verification, authenticated by the
/// token in its last path segment instead.
#[derive(Clone)]
pub struct OAuth2CallbackExemption {
    method: String,
    pattern: String,
    segments: Vec<Segment>,
    check: CallbackTokenCheck,
}

impl fmt::Debug for OAuth2CallbackExemption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.pattern)
    }
}

/// Longest variable or token segment the matcher considers.
const MAX_SEGMENT_LEN: usize = 256;

fn is_literal(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A `{var}` segment, such as a SUPI (`imsi-…`, `nai-user@realm`) or an id.
fn is_var(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SEGMENT_LEN
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// A `{token}` segment: the NFs mint simple-form UUIDs (32 hex digits).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SEGMENT_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl OAuth2CallbackExemption {
    /// A callback route `method pattern`, admitted without a bearer when
    /// `check` accepts the token in its path.
    ///
    /// `pattern` is an absolute path of `/`-separated segments: lowercase
    /// literals (`[a-z0-9-]+`), `{var}` placeholders, and exactly one `{token}`,
    /// which must be the last segment. The first segment must be a literal.
    ///
    /// # Panics
    /// On a malformed pattern or method: both are fixed at the NF's
    /// composition root, so a bad one is a programming error that must not
    /// start a server with an exemption nobody meant.
    pub fn new(
        method: &str,
        pattern: impl Into<String>,
        check: impl Fn(&CallbackPath<'_>) -> bool + Send + Sync + 'static,
    ) -> Self {
        let pattern = pattern.into();
        assert!(
            !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase()),
            "callback exemption {pattern:?}: method {method:?} is not an HTTP method"
        );
        let body = pattern
            .strip_prefix('/')
            .unwrap_or_else(|| panic!("callback exemption {pattern:?} must start with '/'"));
        let segments: Vec<Segment> = body
            .split('/')
            .map(|s| match s {
                "{var}" => Segment::Var,
                "{token}" => Segment::Token,
                lit if is_literal(lit) => Segment::Literal(lit.to_string()),
                bad => panic!("callback exemption {pattern:?}: bad segment {bad:?}"),
            })
            .collect();
        assert!(
            matches!(segments.first(), Some(Segment::Literal(_))),
            "callback exemption {pattern:?} must start with a literal segment"
        );
        assert!(
            segments.iter().filter(|s| **s == Segment::Token).count() == 1
                && segments.last() == Some(&Segment::Token),
            "callback exemption {pattern:?} needs exactly one {{token}}, as its last segment"
        );
        Self {
            method: method.to_string(),
            pattern,
            segments,
            check: Arc::new(check),
        }
    }

    /// The route, as `METHOD /pattern`.
    pub fn route(&self) -> String {
        format!("{} {}", self.method, self.pattern)
    }

    /// The variable parts of `path` when `method path` has this route's exact
    /// shape; `None` otherwise. Does not consult the token check.
    pub fn match_path<'a>(&self, method: &str, path: &'a str) -> Option<CallbackPath<'a>> {
        if method != self.method {
            return None;
        }
        let body = path.strip_prefix('/')?;
        let mut parts = body.split('/');
        let mut vars = Vec::new();
        let mut token = None;
        for seg in &self.segments {
            let part = parts.next()?;
            match seg {
                Segment::Literal(lit) if part == lit => {}
                Segment::Literal(_) => return None,
                Segment::Var if is_var(part) => vars.push(part),
                Segment::Token if is_token(part) => token = Some(part),
                Segment::Var | Segment::Token => return None,
            }
        }
        if parts.next().is_some() {
            return None;
        }
        Some(CallbackPath {
            vars,
            token: token?,
        })
    }

    /// Whether `method path` is this route AND carries a token the NF holds.
    pub fn admits(&self, method: &str, path: &str) -> bool {
        self.match_path(method, path)
            .is_some_and(|cb| (self.check)(&cb))
    }
}

/// `a == b`, without an early exit on the first differing byte: for an NF's
/// check of a callback token against the one it holds.
pub fn token_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Whether any of `exemptions` admits `method path` without a bearer.
pub fn admits_without_bearer(
    exemptions: &[OAuth2CallbackExemption],
    method: &str,
    path: &str,
) -> bool {
    exemptions.iter().any(|e| e.admits(method, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "0123456789abcdef0123456789abcdef";

    fn dereg_like() -> OAuth2CallbackExemption {
        OAuth2CallbackExemption::new("POST", "/nx-callback/v1/{var}/dereg-notify/{token}", |cb| {
            cb.vars == ["imsi-001010000000001"] && cb.token == GOOD
        })
    }

    #[test]
    fn the_exact_route_with_a_held_token_is_admitted() {
        let e = dereg_like();
        let path = format!("/nx-callback/v1/imsi-001010000000001/dereg-notify/{GOOD}");
        assert_eq!(
            e.match_path("POST", &path),
            Some(CallbackPath {
                vars: vec!["imsi-001010000000001"],
                token: GOOD
            })
        );
        assert!(e.admits("POST", &path));
    }

    /// Every spelling that is not the route byte for byte, and every token the
    /// NF does not hold, is left to the bearer check.
    #[test]
    fn no_variant_spelling_or_foreign_token_is_admitted() {
        let e = dereg_like();
        let ue = "imsi-001010000000001";
        let refused = [
            // Wrong or missing token.
            format!("/nx-callback/v1/{ue}/dereg-notify/{}", "f".repeat(32)),
            format!("/nx-callback/v1/{ue}/dereg-notify/"),
            format!("/nx-callback/v1/{ue}/dereg-notify"),
            // Another UE's path with this UE's token.
            format!("/nx-callback/v1/imsi-001010000000002/dereg-notify/{GOOD}"),
            // Trailing slash, doubled slashes, no leading slash.
            format!("/nx-callback/v1/{ue}/dereg-notify/{GOOD}/"),
            format!("//nx-callback/v1/{ue}/dereg-notify/{GOOD}"),
            format!("/nx-callback//v1/{ue}/dereg-notify/{GOOD}"),
            format!("nx-callback/v1/{ue}/dereg-notify/{GOOD}"),
            // Extra segments, including a service path appended after the token.
            format!("/nx-callback/v1/{ue}/dereg-notify/{GOOD}/x"),
            format!("/nx-callback/v1/{ue}/dereg-notify/{GOOD}/../../../../nx-svc/v1/ue"),
            // Dot segments in place of a variable.
            format!("/nx-callback/v1/../dereg-notify/{GOOD}"),
            format!("/nx-callback/v1/./dereg-notify/{GOOD}"),
            // Percent-encoding anywhere.
            format!("/nx%2Dcallback/v1/{ue}/dereg-notify/{GOOD}"),
            format!("/nx-callback/v1/{ue}/dereg%2Dnotify/{GOOD}"),
            format!("/nx-callback/v1/imsi%2D001010000000001/dereg-notify/{GOOD}"),
            format!("/nx-callback/v1/{ue}/dereg-notify/{GOOD}%2F"),
            format!("/nx-callback/v1/{ue}%2Fdereg-notify/{GOOD}"),
            // Case.
            format!("/NX-callback/v1/{ue}/dereg-notify/{GOOD}"),
            format!("/nx-callback/V1/{ue}/dereg-notify/{GOOD}"),
            // A query glued to the path (the server hands the matcher the path only).
            format!("/nx-callback/v1/{ue}/dereg-notify/{GOOD}?x=1"),
            // Over-long token.
            format!("/nx-callback/v1/{ue}/dereg-notify/{}", "a".repeat(300)),
        ];
        for path in &refused {
            assert!(!e.admits("POST", path), "admitted {path}");
        }
        let path = format!("/nx-callback/v1/{ue}/dereg-notify/{GOOD}");
        for method in ["GET", "PUT", "DELETE", "PATCH", "post", ""] {
            assert!(!e.admits(method, &path), "admitted {method} {path}");
        }
    }

    /// Variable and token segments match only a small unreserved charset, so a
    /// check that accepts any id still never sees a dot segment or an encoded
    /// byte.
    #[test]
    fn variable_and_token_segments_are_drawn_from_a_safe_charset() {
        let any = OAuth2CallbackExemption::new("POST", "/nx-callback/v1/{var}/n/{token}", |_| true);
        for ok in ["imsi-001010000000001", "nai-user@realm.example", "ee_1.2"] {
            assert!(
                any.admits("POST", &format!("/nx-callback/v1/{ok}/n/{GOOD}")),
                "{ok}"
            );
        }
        for bad in [".", "..", "a%2Fb", "%2e%2e", "a b", "a+b", "a;b", "a\\b"] {
            let path = format!("/nx-callback/v1/{bad}/n/{GOOD}");
            assert!(any.match_path("POST", &path).is_none(), "{path}");
        }
        for bad in ["a.b", "a@b", "a%41", "..", "a~b"] {
            let path = format!("/nx-callback/v1/ue/n/{bad}");
            assert!(any.match_path("POST", &path).is_none(), "{path}");
        }
    }

    #[test]
    fn the_check_decides_even_for_a_well_formed_path() {
        let deny =
            OAuth2CallbackExemption::new("POST", "/nx-callback/v1/notify/{token}", |_| false);
        assert!(deny
            .match_path("POST", &format!("/nx-callback/v1/notify/{GOOD}"))
            .is_some());
        assert!(!deny.admits("POST", &format!("/nx-callback/v1/notify/{GOOD}")));
    }

    #[test]
    fn token_eq_compares_whole_tokens() {
        assert!(token_eq(GOOD, GOOD));
        assert!(!token_eq(GOOD, &GOOD[..31]));
        assert!(!token_eq(GOOD, "0123456789abcdef0123456789abcdee"));
        assert!(!token_eq("", GOOD));
    }

    #[test]
    fn an_empty_list_admits_nothing() {
        assert!(!admits_without_bearer(
            &[],
            "POST",
            "/nx-callback/v1/notify/abc"
        ));
    }

    #[test]
    fn the_route_reads_back_as_registered() {
        assert_eq!(
            dereg_like().route(),
            "POST /nx-callback/v1/{var}/dereg-notify/{token}"
        );
        assert_eq!(
            format!("{:?}", dereg_like()),
            "POST /nx-callback/v1/{var}/dereg-notify/{token}"
        );
    }

    #[test]
    #[should_panic(expected = "exactly one {token}")]
    fn a_pattern_without_a_token_is_refused() {
        OAuth2CallbackExemption::new("POST", "/nx-callback/v1/notify", |_| true);
    }

    #[test]
    #[should_panic(expected = "exactly one {token}")]
    fn a_token_that_is_not_last_is_refused() {
        OAuth2CallbackExemption::new("POST", "/nx-callback/v1/{token}/notify", |_| true);
    }

    #[test]
    #[should_panic(expected = "start with a literal")]
    fn a_pattern_starting_with_a_variable_is_refused() {
        OAuth2CallbackExemption::new("POST", "/{var}/v1/{token}", |_| true);
    }

    #[test]
    #[should_panic(expected = "bad segment")]
    fn a_pattern_with_an_empty_segment_is_refused() {
        OAuth2CallbackExemption::new("POST", "/nx-callback//{token}", |_| true);
    }

    #[test]
    #[should_panic(expected = "bad segment")]
    fn a_wildcard_prefix_pattern_is_refused() {
        OAuth2CallbackExemption::new("POST", "/nx-callback/*/{token}", |_| true);
    }

    #[test]
    #[should_panic(expected = "not an HTTP method")]
    fn a_lowercase_method_is_refused() {
        OAuth2CallbackExemption::new("post", "/nx-callback/v1/{token}", |_| true);
    }
}
