//! Minimal DNS wire codec for the EASDF's UDP/53 plane (issue #276).
//!
//! RFC 1035 message format, RFC 6891 EDNS(0). Hand-rolled rather than vendored,
//! matching how this tree already carries NAS, NGAP, PFCP and Diameter codecs —
//! and because the subset an EASDF needs is genuinely small: it answers `A` and
//! `AAAA` queries for edge FQDNs and forwards everything else verbatim.
//!
//! # Why this module is NOT behind the `dns-udp` feature
//!
//! The socket is; this is not. Two reasons, and the second is the one that
//! matters. First, a pure codec changes no network posture, which is the reason
//! #276 gives for gating at all. Second, the recorded house rule in this project
//! is to prefer a runtime switch over a cargo feature precisely because CI builds
//! default features and a gated path therefore rots uncompiled. #276 asks for a
//! cargo feature with a specific justification (binding a privileged port), so
//! the feature stands — but keeping the codec out of it means the part with all
//! the parsing logic is compiled and tested on every CI run regardless.
//!
//! # What is deliberately not implemented
//!
//! Compression is *read* (a query may arrive with a compressed QNAME) but only
//! ever *written* as the one pointer to the question name at offset 12, which is
//! the only compression opportunity a single-question answer has. No AXFR, no
//! DNSSEC validation, no TCP fallback: a `TC`-flagged truncated answer is the
//! documented behaviour, and a resolver that wants the rest retries over TCP
//! against an upstream, not against the EASDF.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Fixed DNS header size (RFC 1035 §4.1.1).
pub const HEADER_LEN: usize = 12;

/// Bare-UDP payload ceiling before EDNS(0) (RFC 1035 §4.2.1).
pub const MAX_UDP_PAYLOAD: usize = 512;

/// Largest EDNS(0) payload we will honour, so a peer advertising 65535 cannot
/// make us allocate a datagram no path will carry.
pub const MAX_EDNS_PAYLOAD: u16 = 4096;

/// A name longer than this is malformed (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;

/// One label may not exceed this (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Pointer-chase ceiling. A compressed name cannot legitimately need more hops
/// than the message has bytes, so this bounds the "compression loop" case
/// without needing to track visited offsets.
const MAX_POINTER_HOPS: usize = 64;

/// RCODEs used by this codec (RFC 1035 §4.1.1, RFC 6895).
pub mod rcode {
    pub const NO_ERROR: u8 = 0;
    pub const FORM_ERR: u8 = 1;
    pub const SERV_FAIL: u8 = 2;
    pub const NX_DOMAIN: u8 = 3;
    pub const NOT_IMP: u8 = 4;
}

/// RR/query types this codec names.
pub mod qtype {
    pub const A: u16 = 1;
    pub const AAAA: u16 = 28;
    /// EDNS(0) pseudo-RR (RFC 6891 §6.1).
    pub const OPT: u16 = 41;
}

/// The only class an EASDF answers in.
pub const CLASS_IN: u16 = 1;

/// Why a datagram could not be read as a DNS message.
///
/// Distinguished rather than collapsed into one error because the *answer* to a
/// client differs: a message we cannot parse far enough to find an ID gets no
/// answer at all (there is no ID to put in one), while a message we can identify
/// but not serve gets a `FORMERR` or `NOTIMP` with its ID echoed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the fixed header, so there is no ID to answer with.
    ShorterThanHeader,
    /// Ran off the end of the buffer mid-record.
    Truncated,
    /// A label length byte was neither a length ≤63 nor a compression pointer.
    BadLabelLength,
    /// Compression pointer chain exceeded [`MAX_POINTER_HOPS`].
    CompressionLoop,
    /// Assembled name exceeded 255 octets.
    NameTooLong,
    /// A name label was not valid UTF-8. Legal DNS, unusable as an FQDN string.
    NonUtf8Label,
}

impl ParseError {
    /// Whether the ID was readable, i.e. whether an error response can be sent.
    pub fn is_answerable(&self) -> bool {
        !matches!(self, Self::ShorterThanHeader)
    }
}

/// Parsed DNS header flags, in the shape this codec cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// `QR`: false = query, true = response.
    pub response: bool,
    /// `OPCODE`. Only 0 (QUERY) is served.
    pub opcode: u8,
    /// `AA`: authoritative answer.
    pub authoritative: bool,
    /// `TC`: truncated.
    pub truncated: bool,
    /// `RD`: recursion desired (echoed back per RFC 1035 §4.1.1).
    pub recursion_desired: bool,
    /// `RA`: recursion available.
    pub recursion_available: bool,
    /// `RCODE`.
    pub rcode: u8,
}

/// One question (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The QNAME as a dotted string, lowercased, no trailing dot. Matches what
    /// the EASDF's resolution engine compares against.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// The EDNS(0) OPT pseudo-RR a modern resolver sets (RFC 6891).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns {
    /// The requestor's advertised UDP payload size, clamped to
    /// [`MAX_EDNS_PAYLOAD`] and floored at [`MAX_UDP_PAYLOAD`].
    pub udp_payload_size: u16,
    /// `DO` bit. Echoed, never acted on: this codec does not sign anything.
    pub dnssec_ok: bool,
}

/// One answer record this codec can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
}

impl Record {
    fn rr_type(&self) -> u16 {
        match self {
            Self::A(_) => qtype::A,
            Self::Aaaa(_) => qtype::AAAA,
        }
    }

    fn rdata_len(&self) -> usize {
        match self {
            Self::A(_) => 4,
            Self::Aaaa(_) => 16,
        }
    }

    /// Encoded size when written with a 2-byte compression pointer as its NAME.
    fn encoded_len(&self) -> usize {
        // NAME(2, pointer) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
        12 + self.rdata_len()
    }

    /// Does this record answer a query of `qt`? Used so an `A` query is not
    /// answered with the `AAAA` an operator also configured, which a stub
    /// resolver would treat as a bogus response.
    pub fn answers(&self, qt: u16) -> bool {
        self.rr_type() == qt
    }
}

/// A decoded DNS message: enough of one for the EASDF's purposes.
///
/// Both directions use this type. The alternative — a `Query` and a `Response` —
/// would need the same header, name and RR parsing twice, and the test that
/// decodes what [`build_response`] produced would then be exercising a *second*
/// parser rather than the one production uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: Flags,
    /// The first question, when the message carries exactly one. `None` when
    /// QDCOUNT is 0; a QDCOUNT above 1 is reported in `question_count` and the
    /// caller decides (this codec's server refuses it with `FORMERR`).
    pub question: Option<Question>,
    pub question_count: u16,
    pub answers: Vec<Record>,
    /// Answer records whose type this codec does not model, counted so a test
    /// can tell "no answers" from "answers we did not decode".
    pub unmodelled_answers: u16,
    pub edns: Option<Edns>,
}

/// Read `n` bytes at `pos`, or fail.
fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], ParseError> {
    let end = pos.checked_add(n).ok_or(ParseError::Truncated)?;
    let slice = buf.get(*pos..end).ok_or(ParseError::Truncated)?;
    *pos = end;
    Ok(slice)
}

fn take_u16(buf: &[u8], pos: &mut usize) -> Result<u16, ParseError> {
    let b = take(buf, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_u32(buf: &[u8], pos: &mut usize) -> Result<u32, ParseError> {
    let b = take(buf, pos, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode a possibly-compressed domain name starting at `*pos`.
///
/// `*pos` is advanced past the name **as it appears at that position**, which for
/// a compressed name is past the pointer rather than past the pointed-to labels —
/// the distinction that makes a compressed QNAME parse correctly instead of
/// resuming inside the target.
///
/// The returned name is lowercased with no trailing dot, so it can be compared
/// against the EAS map without a second normalisation step. The root name
/// decodes to the empty string.
fn read_name(buf: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    let mut name = String::new();
    let mut cursor = *pos;
    let mut hops = 0usize;
    // Where to leave `*pos`: set on the first pointer we follow, because
    // everything after it belongs to the pointed-to name, not to this one.
    let mut resume: Option<usize> = None;

    loop {
        let len = *buf.get(cursor).ok_or(ParseError::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                cursor += 1;
                if len == 0 {
                    break;
                }
                let len = len as usize;
                if len > MAX_LABEL_LEN {
                    return Err(ParseError::BadLabelLength);
                }
                let label = buf.get(cursor..cursor + len).ok_or(ParseError::Truncated)?;
                cursor += len;
                if !name.is_empty() {
                    name.push('.');
                }
                let label = std::str::from_utf8(label).map_err(|_| ParseError::NonUtf8Label)?;
                name.push_str(&label.to_ascii_lowercase());
                if name.len() > MAX_NAME_LEN {
                    return Err(ParseError::NameTooLong);
                }
            }
            0xc0 => {
                let hi = (len & 0x3f) as usize;
                let lo = *buf.get(cursor + 1).ok_or(ParseError::Truncated)? as usize;
                let target = (hi << 8) | lo;
                if resume.is_none() {
                    resume = Some(cursor + 2);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(ParseError::CompressionLoop);
                }
                // A pointer must point backwards; forwards or self-referential is
                // the loop case the hop counter would otherwise take 64 tries to
                // notice.
                if target >= cursor {
                    return Err(ParseError::CompressionLoop);
                }
                cursor = target;
            }
            // 0x40 and 0x80 are reserved label types (RFC 6891 §6.1 retired the
            // one experimental use); neither is a length nor a pointer.
            _ => return Err(ParseError::BadLabelLength),
        }
    }

    *pos = resume.unwrap_or(cursor);
    Ok(name)
}

/// Skip an RR's RDATA and return `(rr_type, class, ttl, rdata)`.
fn read_rr<'a>(
    buf: &'a [u8],
    pos: &mut usize,
) -> Result<(String, u16, u16, u32, &'a [u8]), ParseError> {
    let name = read_name(buf, pos)?;
    let rr_type = take_u16(buf, pos)?;
    let class = take_u16(buf, pos)?;
    let ttl = take_u32(buf, pos)?;
    let rdlen = take_u16(buf, pos)? as usize;
    let rdata = take(buf, pos, rdlen)?;
    Ok((name, rr_type, class, ttl, rdata))
}

/// Decode a DNS message.
///
/// Records whose type this codec does not model are skipped (their RDLENGTH is
/// honoured), not rejected: a resolver is entitled to send additional records we
/// have no opinion about, and refusing the whole datagram over one of them would
/// make the EASDF unusable behind a forwarder.
pub fn parse_message(buf: &[u8]) -> Result<Message, ParseError> {
    if buf.len() < HEADER_LEN {
        return Err(ParseError::ShorterThanHeader);
    }
    let mut pos = 0usize;
    let id = take_u16(buf, &mut pos)?;
    let raw_flags = take_u16(buf, &mut pos)?;
    let qdcount = take_u16(buf, &mut pos)?;
    let ancount = take_u16(buf, &mut pos)?;
    let nscount = take_u16(buf, &mut pos)?;
    let arcount = take_u16(buf, &mut pos)?;

    let flags = Flags {
        response: raw_flags & 0x8000 != 0,
        opcode: ((raw_flags >> 11) & 0x0f) as u8,
        authoritative: raw_flags & 0x0400 != 0,
        truncated: raw_flags & 0x0200 != 0,
        recursion_desired: raw_flags & 0x0100 != 0,
        recursion_available: raw_flags & 0x0080 != 0,
        rcode: (raw_flags & 0x000f) as u8,
    };

    let mut question = None;
    for i in 0..qdcount {
        let name = read_name(buf, &mut pos)?;
        let qt = take_u16(buf, &mut pos)?;
        let qc = take_u16(buf, &mut pos)?;
        if i == 0 {
            question = Some(Question {
                name,
                qtype: qt,
                qclass: qc,
            });
        }
    }

    let mut answers = Vec::new();
    let mut unmodelled_answers = 0u16;
    for _ in 0..ancount {
        let (_, rr_type, _, _, rdata) = read_rr(buf, &mut pos)?;
        match (rr_type, rdata.len()) {
            (qtype::A, 4) => answers.push(Record::A(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (qtype::AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                answers.push(Record::Aaaa(Ipv6Addr::from(octets)));
            }
            _ => unmodelled_answers += 1,
        }
    }

    // Authority section is walked only to reach the additional section, where the
    // OPT record lives.
    for _ in 0..nscount {
        read_rr(buf, &mut pos)?;
    }

    let mut edns = None;
    for _ in 0..arcount {
        let (_, rr_type, class, ttl, _) = read_rr(buf, &mut pos)?;
        if rr_type == qtype::OPT && edns.is_none() {
            // RFC 6891 §6.1.2: CLASS carries the requestor's payload size and the
            // top of TTL carries the extended flags, of which `DO` is bit 15.
            edns = Some(Edns {
                udp_payload_size: class.clamp(MAX_UDP_PAYLOAD as u16, MAX_EDNS_PAYLOAD),
                dnssec_ok: ttl & 0x0000_8000 != 0,
            });
        }
    }

    Ok(Message {
        id,
        flags,
        question,
        question_count: qdcount,
        answers,
        unmodelled_answers,
        edns,
    })
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Encode a name as uncompressed labels. An empty name is the root (a single 0).
fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(MAX_LABEL_LEN);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

/// What [`build_response`] should say.
#[derive(Debug, Clone)]
pub struct Response<'a> {
    /// Echoed from the query.
    pub id: u16,
    /// Echoed from the query, so the client can match it.
    pub question: Option<&'a Question>,
    /// Echoed, per RFC 1035 §4.1.1.
    pub recursion_desired: bool,
    /// Set when the EASDF is the configured authority for the name — true for an
    /// EAS-map or handling-rule answer, false for anything derived elsewhere.
    pub authoritative: bool,
    /// The EASDF can forward, so `RA` is set whenever an upstream is configured.
    pub recursion_available: bool,
    pub rcode: u8,
    pub records: &'a [Record],
    pub ttl: u32,
    /// The query's EDNS(0), when it had one. Its presence changes both the
    /// payload ceiling and whether the response carries an OPT of its own.
    pub edns: Option<Edns>,
}

/// Encode a response, truncating with `TC` when it will not fit.
///
/// The payload ceiling is the requestor's EDNS(0) size when it sent one, else
/// 512. Records are dropped from the end until the message fits; `TC` is set if
/// any were dropped, which is what tells a resolver to retry over TCP rather
/// than treat a short answer set as the whole truth.
///
/// The OPT record is emitted **only** when the query carried one (RFC 6891
/// §6.1.1: a response must not contain an OPT unless the request did). This is
/// the case the issue calls out — a resolver that sets EDNS and gets a response
/// without it may retry or fail.
pub fn build_response(resp: &Response<'_>) -> Vec<u8> {
    let ceiling = resp
        .edns
        .map(|e| e.udp_payload_size as usize)
        .unwrap_or(MAX_UDP_PAYLOAD);

    // Fixed cost: header + question + (OPT, when echoing one).
    let mut fixed = HEADER_LEN;
    if let Some(q) = resp.question {
        // labels + terminator + QTYPE + QCLASS
        fixed += q
            .name
            .split('.')
            .filter(|l| !l.is_empty())
            .map(|l| l.len() + 1)
            .sum::<usize>()
            + 1
            + 4;
    }
    let opt_len = if resp.edns.is_some() { 11 } else { 0 };
    fixed += opt_len;

    let mut budget = ceiling.saturating_sub(fixed);
    let mut included = 0usize;
    for record in resp.records {
        let len = record.encoded_len();
        if len > budget {
            break;
        }
        budget -= len;
        included += 1;
    }
    let truncated = included < resp.records.len();

    let mut flags: u16 = 0x8000; // QR
    if resp.authoritative {
        flags |= 0x0400;
    }
    if truncated {
        flags |= 0x0200;
    }
    if resp.recursion_desired {
        flags |= 0x0100;
    }
    if resp.recursion_available {
        flags |= 0x0080;
    }
    flags |= (resp.rcode & 0x0f) as u16;

    let mut out = Vec::with_capacity(fixed + 64);
    push_u16(&mut out, resp.id);
    push_u16(&mut out, flags);
    push_u16(&mut out, if resp.question.is_some() { 1 } else { 0 });
    push_u16(&mut out, included as u16);
    push_u16(&mut out, 0); // NSCOUNT
    push_u16(&mut out, if resp.edns.is_some() { 1 } else { 0 });

    if let Some(q) = resp.question {
        write_name(&mut out, &q.name);
        push_u16(&mut out, q.qtype);
        push_u16(&mut out, q.qclass);
    }

    for record in resp.records.iter().take(included) {
        // NAME as a pointer to the question name, which always begins at offset
        // 12. Only valid because the question is written first and there is at
        // most one; asserted by the round-trip tests rather than assumed.
        if resp.question.is_some() {
            push_u16(&mut out, 0xc000 | HEADER_LEN as u16);
        } else {
            out.push(0);
        }
        push_u16(&mut out, record.rr_type());
        push_u16(&mut out, CLASS_IN);
        out.extend_from_slice(&resp.ttl.to_be_bytes());
        push_u16(&mut out, record.rdata_len() as u16);
        match record {
            Record::A(ip) => out.extend_from_slice(&ip.octets()),
            Record::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
        }
    }

    if let Some(edns) = resp.edns {
        out.push(0); // NAME: root
        push_u16(&mut out, qtype::OPT);
        push_u16(&mut out, edns.udp_payload_size); // CLASS: our payload size
        let ttl: u32 = if edns.dnssec_ok { 0x0000_8000 } else { 0 };
        out.extend_from_slice(&ttl.to_be_bytes());
        push_u16(&mut out, 0); // RDLENGTH
    }

    out
}

/// A response carrying only an RCODE — used for `FORMERR`, `NOTIMP`, `SERVFAIL`
/// and `NXDOMAIN`, all of which echo the question when one was readable.
pub fn build_error(
    id: u16,
    question: Option<&Question>,
    rcode: u8,
    recursion_desired: bool,
    recursion_available: bool,
    edns: Option<Edns>,
) -> Vec<u8> {
    build_response(&Response {
        id,
        question,
        recursion_desired,
        authoritative: false,
        recursion_available,
        rcode,
        records: &[],
        ttl: 0,
        edns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a query the way a stub resolver would, for the parse tests.
    fn query_bytes(id: u16, name: &str, qt: u16, edns: Option<u16>) -> Vec<u8> {
        let mut out = Vec::new();
        push_u16(&mut out, id);
        push_u16(&mut out, 0x0100); // RD
        push_u16(&mut out, 1); // QDCOUNT
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, if edns.is_some() { 1 } else { 0 });
        write_name(&mut out, name);
        push_u16(&mut out, qt);
        push_u16(&mut out, CLASS_IN);
        if let Some(size) = edns {
            out.push(0);
            push_u16(&mut out, qtype::OPT);
            push_u16(&mut out, size);
            out.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // DO set
            push_u16(&mut out, 0);
        }
        out
    }

    #[test]
    fn a_plain_query_round_trips_through_an_answer() {
        let wire = query_bytes(0xbeef, "app.edge.example.com", qtype::A, None);
        let query = parse_message(&wire).expect("query parses");

        assert_eq!(query.id, 0xbeef);
        assert!(!query.flags.response);
        assert!(query.flags.recursion_desired);
        assert_eq!(query.question_count, 1);
        let question = query.question.clone().expect("one question");
        assert_eq!(question.name, "app.edge.example.com");
        assert_eq!(question.qtype, qtype::A);
        assert_eq!(question.qclass, CLASS_IN);
        assert!(query.edns.is_none());

        let records = [Record::A(Ipv4Addr::new(10, 45, 0, 7))];
        let answer = build_response(&Response {
            id: query.id,
            question: Some(&question),
            recursion_desired: true,
            authoritative: true,
            recursion_available: false,
            rcode: rcode::NO_ERROR,
            records: &records,
            ttl: 30,
            edns: None,
        });

        let decoded = parse_message(&answer).expect("answer parses");
        assert_eq!(decoded.id, 0xbeef);
        assert!(decoded.flags.response);
        assert!(decoded.flags.authoritative);
        assert!(!decoded.flags.truncated);
        assert!(decoded.flags.recursion_desired, "RD must be echoed");
        assert_eq!(decoded.flags.rcode, rcode::NO_ERROR);
        assert_eq!(
            decoded.question.as_ref().map(|q| q.name.as_str()),
            Some("app.edge.example.com"),
            "the question must be echoed so a stub resolver can match it"
        );
        assert_eq!(
            decoded.answers,
            vec![Record::A(Ipv4Addr::new(10, 45, 0, 7))]
        );
        assert_eq!(decoded.unmodelled_answers, 0);
        assert!(
            decoded.edns.is_none(),
            "RFC 6891 §6.1.1: no OPT in the response when the query had none"
        );
    }

    /// The compressed-name case #276 names, asserted at `read_name` directly.
    ///
    /// Note where compression can and cannot appear, because the obvious version
    /// of this test is impossible: a *question's* QNAME is the first name in the
    /// message, so there is nothing before it to point at. Compression is
    /// therefore something we meet in the ANSWER section (or from a forwarder's
    /// response), and the property that matters is that the cursor resumes after
    /// the two-byte POINTER rather than after the pointed-to labels — get that
    /// wrong and every field following a compressed name is read from the wrong
    /// offset. The sentinel byte is what makes that observable.
    #[test]
    fn a_compressed_name_is_followed_and_resumes_after_the_pointer() {
        let mut buf = vec![0u8; HEADER_LEN];
        let suffix_at = buf.len();
        write_name(&mut buf, "edge.example.com");
        let name_at = buf.len();
        buf.push(3);
        buf.extend_from_slice(b"app");
        push_u16(&mut buf, 0xc000 | suffix_at as u16);
        buf.push(0xff); // must survive: not part of the name

        let mut pos = name_at;
        assert_eq!(
            read_name(&buf, &mut pos).expect("compressed name reads"),
            "app.edge.example.com"
        );
        assert_eq!(
            pos,
            buf.len() - 1,
            "the cursor must resume after the pointer, not after the target labels"
        );
        assert_eq!(buf[pos], 0xff);
    }

    /// The production compression path: `build_response` writes every answer RR's
    /// NAME as a pointer to the question, so a second record only decodes if the
    /// first record's compressed name advanced the cursor by exactly two bytes.
    #[test]
    fn multiple_answer_records_decode_after_their_compressed_names() {
        let wire = query_bytes(0x7777, "app.edge.example.com", qtype::A, None);
        let question = parse_message(&wire)
            .expect("parses")
            .question
            .expect("question");
        let records = [
            Record::A(Ipv4Addr::new(10, 45, 0, 1)),
            Record::A(Ipv4Addr::new(10, 45, 0, 2)),
            Record::A(Ipv4Addr::new(10, 45, 0, 3)),
        ];
        let answer = build_response(&Response {
            id: 0x7777,
            question: Some(&question),
            recursion_desired: true,
            authoritative: true,
            recursion_available: false,
            rcode: rcode::NO_ERROR,
            records: &records,
            ttl: 30,
            edns: None,
        });
        // The pointer is what keeps three answers this small.
        assert_eq!(answer.len(), HEADER_LEN + 26 + 3 * 16);
        assert_eq!(
            parse_message(&answer).expect("parses").answers,
            records.to_vec(),
            "all three records must decode, in order"
        );
    }

    #[test]
    fn a_compression_pointer_that_does_not_point_backwards_is_refused() {
        // Self-referential pointer in the question name.
        let mut wire = Vec::new();
        push_u16(&mut wire, 0x0002);
        push_u16(&mut wire, 0x0000);
        push_u16(&mut wire, 1);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0xc000 | 12u16); // points at itself
        push_u16(&mut wire, qtype::A);
        push_u16(&mut wire, CLASS_IN);

        assert_eq!(parse_message(&wire), Err(ParseError::CompressionLoop));
    }

    #[test]
    fn an_unknown_qtype_parses_and_is_answered_by_no_record() {
        // MX is well-formed and something the EASDF has no answer for. It must
        // parse (so the server can reply NOTIMP with the question echoed) rather
        // than fail to decode.
        const MX: u16 = 15;
        let wire = query_bytes(0x1234, "mail.example.com", MX, None);
        let msg = parse_message(&wire).expect("an MX query is still a valid query");
        let question = msg.question.expect("one question");
        assert_eq!(question.qtype, MX);

        let a = Record::A(Ipv4Addr::LOCALHOST);
        assert!(!a.answers(MX), "an A record must not answer an MX query");
        assert!(a.answers(qtype::A));

        let err = build_error(0x1234, Some(&question), rcode::NOT_IMP, true, false, None);
        let decoded = parse_message(&err).expect("the error parses");
        assert_eq!(decoded.flags.rcode, rcode::NOT_IMP);
        assert!(decoded.answers.is_empty());
        assert_eq!(decoded.question, Some(question));
    }

    #[test]
    fn malformed_and_truncated_messages_are_rejected_distinguishably() {
        // Shorter than the header: no ID, so no answer is possible.
        let e = parse_message(&[0u8; 5]).expect_err("5 bytes is not a message");
        assert_eq!(e, ParseError::ShorterThanHeader);
        assert!(
            !e.is_answerable(),
            "with no readable ID there is nothing to answer with"
        );

        // Header claims a question that is not there.
        let mut wire = Vec::new();
        push_u16(&mut wire, 0x0003);
        push_u16(&mut wire, 0x0000);
        push_u16(&mut wire, 1);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0);
        let e = parse_message(&wire).expect_err("QDCOUNT=1 with no question");
        assert_eq!(e, ParseError::Truncated);
        assert!(
            e.is_answerable(),
            "the ID was readable, so FORMERR is sendable"
        );

        // A query cut off mid-QNAME.
        let full = query_bytes(0x0004, "app.edge.example.com", qtype::A, None);
        assert_eq!(
            parse_message(&full[..full.len() - 6]),
            Err(ParseError::Truncated)
        );

        // A reserved label type (0x80) is neither a length nor a pointer.
        let mut wire = Vec::new();
        push_u16(&mut wire, 0x0005);
        push_u16(&mut wire, 0x0000);
        push_u16(&mut wire, 1);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0);
        push_u16(&mut wire, 0);
        wire.push(0x80);
        wire.extend_from_slice(&[0u8; 8]);
        assert_eq!(parse_message(&wire), Err(ParseError::BadLabelLength));
    }

    #[test]
    fn an_edns0_query_gets_an_opt_in_its_response_and_a_larger_ceiling() {
        let wire = query_bytes(0x4321, "app.edge.example.com", qtype::A, Some(1232));
        let msg = parse_message(&wire).expect("EDNS query parses");
        let edns = msg
            .edns
            .expect("OPT record found in the additional section");
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(edns.dnssec_ok, "the DO bit must be read");

        let question = msg.question.clone().expect("one question");
        let records = [Record::A(Ipv4Addr::new(10, 45, 0, 8))];
        let answer = build_response(&Response {
            id: msg.id,
            question: Some(&question),
            recursion_desired: true,
            authoritative: true,
            recursion_available: true,
            rcode: rcode::NO_ERROR,
            records: &records,
            ttl: 30,
            edns: msg.edns,
        });
        let decoded = parse_message(&answer).expect("answer parses");
        let echoed = decoded
            .edns
            .expect("a response to an EDNS query must carry an OPT");
        assert_eq!(echoed.udp_payload_size, 1232);
        assert!(echoed.dnssec_ok);
        assert_eq!(decoded.answers.len(), 1);
    }

    /// A payload size below the bare-UDP floor is raised to it, and one above
    /// our ceiling is lowered: a peer advertising 65535 must not make us build a
    /// datagram no path will carry, and one advertising 12 must not make us
    /// truncate an answer that fits in a plain 512-byte reply.
    #[test]
    fn an_absurd_edns_payload_size_is_clamped_both_ways() {
        for (advertised, expected) in [(1u16, MAX_UDP_PAYLOAD as u16), (65535, MAX_EDNS_PAYLOAD)] {
            let wire = query_bytes(1, "app.edge.example.com", qtype::A, Some(advertised));
            let msg = parse_message(&wire).expect("parses");
            assert_eq!(msg.edns.expect("OPT").udp_payload_size, expected);
        }
    }

    /// An EAS list can exceed the UDP limit, which is the case #276 names. The
    /// answer must be a `TC`-flagged prefix, not a silently short one: a resolver
    /// reading a short answer set with `TC` clear treats it as complete.
    #[test]
    fn an_oversized_answer_set_is_truncated_with_the_tc_bit_set() {
        let wire = query_bytes(0x5555, "app.edge.example.com", qtype::AAAA, None);
        let msg = parse_message(&wire).expect("parses");
        let question = msg.question.clone().expect("one question");

        // 16-byte RDATA + 12 bytes of RR overhead = 28 each; 40 of them is
        // 1120 bytes, comfortably past the 512 floor.
        let records: Vec<Record> = (0..40)
            .map(|i| Record::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
            .collect();

        let answer = build_response(&Response {
            id: msg.id,
            question: Some(&question),
            recursion_desired: true,
            authoritative: true,
            recursion_available: false,
            rcode: rcode::NO_ERROR,
            records: &records,
            ttl: 30,
            edns: None,
        });

        assert!(
            answer.len() <= MAX_UDP_PAYLOAD,
            "a bare-UDP answer must fit in 512 bytes, got {}",
            answer.len()
        );
        let decoded = parse_message(&answer).expect("truncated answer still parses");
        assert!(
            decoded.flags.truncated,
            "TC must be set when records were dropped"
        );
        assert!(
            decoded.answers.len() < records.len(),
            "the point of the test is that some were dropped"
        );
        assert!(
            !decoded.answers.is_empty(),
            "truncation must keep what fits, not drop everything"
        );

        // With EDNS advertising 4096 the same set fits, so TC must be clear --
        // otherwise the ceiling is being ignored.
        let big = build_response(&Response {
            id: msg.id,
            question: Some(&question),
            recursion_desired: true,
            authoritative: true,
            recursion_available: false,
            rcode: rcode::NO_ERROR,
            records: &records,
            ttl: 30,
            edns: Some(Edns {
                udp_payload_size: MAX_EDNS_PAYLOAD,
                dnssec_ok: false,
            }),
        });
        let decoded = parse_message(&big).expect("parses");
        assert!(!decoded.flags.truncated);
        assert_eq!(decoded.answers.len(), records.len());
    }

    #[test]
    fn a_name_longer_than_255_octets_is_refused() {
        let long = (0..40)
            .map(|_| "abcdefghij".to_string())
            .collect::<Vec<_>>()
            .join(".");
        assert!(long.len() > MAX_NAME_LEN);
        let wire = query_bytes(9, &long, qtype::A, None);
        assert_eq!(parse_message(&wire), Err(ParseError::NameTooLong));
    }

    #[test]
    fn names_are_lowercased_and_the_trailing_root_is_not_part_of_the_name() {
        let wire = query_bytes(10, "APP.Edge.Example.COM", qtype::A, None);
        let msg = parse_message(&wire).expect("parses");
        assert_eq!(
            msg.question.expect("question").name,
            "app.edge.example.com",
            "0x20-randomised or mixed-case queries must compare equal to the EAS map"
        );
    }
}
