//! #417 stage B: a schema-blind X.691 ALIGNED bit sink for the hand-derived
//! NGAP goldens in amfd's tests.
//!
//! The goldens that replace the hand-written `nextgcore-ngap` codec are derived
//! by hand from the TS 38.413 V17.9 ASN.1 (`libs/nextgcore-ngap-gen/asn`) and
//! X.691. Where a PDU's width depends on its values (lists, long integers), the
//! derivation drives this sink. The sink knows bits, bit-fields, alignment and
//! the open-type length determinant, and nothing about the schema. Each test
//! that uses it says, beside the calls, which schema member each call encodes
//! and which X.691 clause fixes its width. It is the same sink smfd's
//! `n2_transfer/golden.rs` uses, so a derivation slip shows the same way in
//! both crates.
//!
//! Shared layout facts used by the derivations (X.691 ALIGNED):
//! - NGAP-PDU is an extensible CHOICE of three, so an extension bit and a
//!   two-bit index; procedureCode `INTEGER (0..255)` is one aligned octet;
//!   criticality `ENUMERATED {reject, ignore, notify}` is two bits; the value
//!   is an open type (§23, §13.2, §11.2);
//! - a SEQUENCE with `...` opens with its extension bit, then one presence bit
//!   per OPTIONAL member (§19);
//! - ProtocolIE-Container `SEQUENCE (SIZE(0..65535)) OF` is its count in two
//!   aligned octets; each field is its id in two aligned octets, its
//!   criticality in two bits, then the value as an open type (§11.9.3.6);
//! - `INTEGER` with a range past 64K is its octet count n as n-1 in the
//!   fewest bits that hold the count range, then n aligned octets, n minimal
//!   (§11.5.7.4).

/// An X.691 ALIGNED bit sink.
#[derive(Default)]
pub(crate) struct Bits(Vec<bool>);

impl Bits {
    /// One bit: an extension bit, a presence bit, a one-bit index.
    pub(crate) fn bit(&mut self, b: bool) -> &mut Self {
        self.0.push(b);
        self
    }

    /// `value` as an `n`-bit field, most significant bit first.
    pub(crate) fn field(&mut self, value: u64, n: u32) -> &mut Self {
        for i in (0..n).rev() {
            self.0.push(value >> i & 1 == 1);
        }
        self
    }

    /// Zero bits up to the next octet boundary.
    pub(crate) fn align(&mut self) -> &mut Self {
        while !self.0.len().is_multiple_of(8) {
            self.0.push(false);
        }
        self
    }

    /// Octet-aligned octets.
    pub(crate) fn octets(&mut self, o: &[u8]) -> &mut Self {
        self.align();
        for b in o {
            self.field(u64::from(*b), 8);
        }
        self
    }

    /// An open type (or an unconstrained OCTET STRING) holding `inner`: the
    /// aligned length determinant, short form below 128, two-octet `10` form
    /// below 16384 (§11.9.3.6-§11.9.3.7), then the octets.
    pub(crate) fn open(&mut self, inner: &[u8]) -> &mut Self {
        assert!(
            inner.len() < 16384,
            "fragmented lengths are not derived here"
        );
        if inner.len() < 128 {
            self.octets(&[inner.len() as u8]);
        } else {
            self.octets(&(0x8000 | inner.len() as u16).to_be_bytes());
        }
        self.octets(inner)
    }

    /// One ProtocolIE-Field: id, criticality (0 reject, 1 ignore, 2 notify),
    /// the open type.
    pub(crate) fn ie(&mut self, id: u16, criticality: u8, value: &[u8]) -> &mut Self {
        self.octets(&id.to_be_bytes())
            .field(u64::from(criticality), 2)
            .open(value)
    }

    /// The complete encoding, padded to an octet (§11.1).
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.align();
        self.0
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |o, b| o << 1 | u8::from(*b)))
            .collect()
    }
}

/// An NGAP-PDU: `choice` 0 initiatingMessage, 1 successfulOutcome, 2
/// unsuccessfulOutcome; the procedure code; the criticality; then the message
/// value, a SEQUENCE {protocolIEs, ...}: extension bit, the IE count, the IEs
/// (id, criticality, value octets) in order.
pub(crate) fn pdu(
    choice: u64,
    procedure: u8,
    criticality: u8,
    ies: &[(u16, u8, Vec<u8>)],
) -> Vec<u8> {
    let mut value = Bits::default();
    value.bit(false).octets(&(ies.len() as u16).to_be_bytes());
    for (id, c, v) in ies {
        value.ie(*id, *c, v);
    }
    let mut b = Bits::default();
    b.bit(false)
        .field(choice, 2)
        .octets(&[procedure])
        .field(u64::from(criticality), 2)
        .open(&value.finish());
    b.finish()
}

/// `INTEGER (0..ub)` with ub past 64K: n-1 in `width` bits, then the value in
/// its minimal n octets, aligned (X.691 §11.5.7.4). AMF-UE-NGAP-ID
/// `(0..2^40-1)` has n in 1..5, so `width` 3; RAN-UE-NGAP-ID `(0..2^32-1)`
/// has n in 1..4, so `width` 2.
pub(crate) fn long_integer(value: u64, width: u32) -> Vec<u8> {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|o| **o == 0).count().min(7);
    let mut b = Bits::default();
    b.field((8 - skip) as u64 - 1, width).octets(&be[skip..]);
    b.finish()
}

/// The AMF-UE-NGAP-ID IE value.
pub(crate) fn amf_ue_ngap_id(v: u64) -> Vec<u8> {
    long_integer(v, 3)
}

/// The RAN-UE-NGAP-ID IE value.
pub(crate) fn ran_ue_ngap_id(v: u32) -> Vec<u8> {
    long_integer(u64::from(v), 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sink against octets worked out by hand without it.
    #[test]
    fn the_sink_writes_the_hand_worked_octets() {
        // AMF-UE-NGAP-ID 1: `000` + pad, `01`; 2^32: `100` + pad, five octets.
        assert_eq!(amf_ue_ngap_id(1), [0x00, 0x01]);
        assert_eq!(amf_ue_ngap_id(1 << 32), [0x80, 0x01, 0, 0, 0, 0]);
        // RAN-UE-NGAP-ID 0x0102: `01` + pad, two octets.
        assert_eq!(ran_ue_ngap_id(0x0102), [0x40, 0x01, 0x02]);
        // An empty-IE initiating message, procedure 21 (NG Reset), reject:
        // `0 00` + pad, `15`, `00`, length 3, value `00 00 00`.
        assert_eq!(
            pdu(0, 21, 0, &[]),
            [0x00, 0x15, 0x00, 0x03, 0x00, 0x00, 0x00]
        );
    }
}
