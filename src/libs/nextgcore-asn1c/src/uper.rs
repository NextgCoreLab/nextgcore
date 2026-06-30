//! Unaligned Packed Encoding Rules (UPER) encoder/decoder — ITU-T X.691.
//!
//! Standalone codepath for protocols that use the UNALIGNED PER variant —
//! notably LPP (3GPP TS 37.355) and RRC. Kept deliberately SEPARATE from
//! `per.rs` (which implements Aligned PER / APER for NGAP/S1AP/E1AP/F1AP/XnAP)
//! so the aligned path used by every NF's live wire is never touched.
//!
//! Wave-3 lmfd-LIB-02a.
//!
//! # How UPER differs from APER (the only differences that matter here)
//!
//! The two variants share the *same* logical fields and the *same* bit
//! patterns for each field; they differ ONLY in octet alignment:
//!
//! * UPER **never** inserts alignment padding. A constrained whole number is
//!   packed into the exact minimum number of bits for its range — even when
//!   that range exceeds 64K (e.g. RRC `ARFCN-ValueNR ::= INTEGER (0..3279165)`
//!   is 22 bits, never an aligned length-of-length octet form). There is no
//!   special 256 / 65536 / >64K octet-aligned case at all (X.691 11.5.3): a
//!   "huge" constrained range is simply *more bits*, not a length-of-length
//!   octet string. (APER, by contrast, switches to 1-octet / 2-octet / aligned
//!   length-of-length forms above the 255 boundary — see `per.rs`.)
//! * Length determinants, strings, the unconstrained-integer octets and the
//!   normally-small octets are all written bit-unaligned (no `align()`).
//! * Only the **final, top-level** message is zero-padded up to a multiple of
//!   8 bits — done here by [`UperEncoder::into_bytes`].
//!
//! Everything that is encoding-rule-agnostic — the [`Constraint`] range /
//! `bits_needed` math and the [`PerError`] / [`PerResult`] types — is reused
//! verbatim from [`crate::per`]; it is NOT duplicated.

use crate::per::{Constraint, PerError, PerResult};
use bitvec::prelude::*;
use bytes::Bytes;

/// UPER (Unaligned PER) encoder over an MSB-first bit cursor.
pub struct UperEncoder {
    buffer: BitVec<u8, Msb0>,
}

impl UperEncoder {
    pub fn new() -> Self {
        Self {
            buffer: BitVec::new(),
        }
    }

    pub fn with_capacity(bits: usize) -> Self {
        Self {
            buffer: BitVec::with_capacity(bits),
        }
    }

    /// Number of bits written so far (before final octet padding).
    pub fn bit_length(&self) -> usize {
        self.buffer.len()
    }

    /// Finalize the message: zero-pad the bit stream up to a multiple of 8 bits
    /// (X.691 10.1 / 11.1 trailing alignment of the complete encoding) and
    /// return the octets. This top-level pad is the ONLY alignment UPER ever
    /// performs.
    pub fn into_bytes(mut self) -> Bytes {
        while !self.buffer.len().is_multiple_of(8) {
            self.buffer.push(false);
        }
        Bytes::from(self.buffer.into_vec())
    }

    /// Write a single bit.
    pub fn write_bit(&mut self, bit: bool) {
        self.buffer.push(bit);
    }

    /// Write the low `num_bits` of `value`, MSB first.
    pub fn write_bits(&mut self, value: u64, num_bits: usize) {
        for i in (0..num_bits).rev() {
            self.buffer.push((value >> i) & 1 == 1);
        }
    }

    /// Write raw bytes (each as 8 bits, MSB first) — bit-unaligned.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_bits(*byte as u64, 8);
        }
    }

    /// Encode a constrained whole number (X.691 11.5, UNALIGNED variant).
    ///
    /// `(value - lb)` is written as a non-negative-binary-integer in the
    /// minimum number of bits needed for the range, with NO alignment and NO
    /// length-of-length octet form — regardless of how large the range is.
    pub fn encode_constrained_whole_number(
        &mut self,
        value: i64,
        constraint: &Constraint,
    ) -> PerResult<()> {
        if value < constraint.min || value > constraint.max {
            return Err(PerError::ConstraintViolation {
                value,
                min: constraint.min,
                max: constraint.max,
            });
        }

        let range = constraint.range();
        if range == 1 {
            // Single legal value: nothing to send.
            return Ok(());
        }

        let offset = (value - constraint.min) as u64;
        let bits = constraint.bits_needed();
        self.write_bits(offset, bits);
        Ok(())
    }

    /// Encode an unconstrained whole number (X.691 11.8 / 13.2.6).
    ///
    /// Minimum-length two's-complement octets, preceded by an (unaligned)
    /// length determinant. Unlike APER, the octets are NOT octet-aligned.
    pub fn encode_unconstrained_whole_number(&mut self, value: i64) -> PerResult<()> {
        let bytes = twos_complement_min_octets(value);
        self.encode_length_determinant(bytes.len())?;
        self.write_bytes(&bytes);
        Ok(())
    }

    /// Encode a length determinant (X.691 11.9), UNALIGNED.
    ///
    /// Same 0xxxxxxx / 10xxxxxx-xxxxxxxx bit patterns as APER but with no
    /// leading octet alignment. Lengths > 16383 require fragmentation and must
    /// go through [`Self::encode_fragmented_octets`] / [`Self::encode_fragmented_bits`].
    pub fn encode_length_determinant(&mut self, length: usize) -> PerResult<()> {
        if length <= 127 {
            // Short form: 0xxxxxxx (8 bits, unaligned)
            self.write_bits(length as u64, 8);
        } else if length <= 16383 {
            // Long form: 10xxxxxx xxxxxxxx (16 bits, unaligned)
            self.write_bits(0x8000 | length as u64, 16);
        } else {
            return Err(PerError::InvalidLength { length });
        }
        Ok(())
    }

    /// Write octets preceded by their (unaligned) length, fragmenting per
    /// X.691 11.9.3.8 (16K-multiple blocks) when the count exceeds 16383.
    pub fn encode_fragmented_octets(&mut self, data: &[u8]) -> PerResult<()> {
        let mut rest = data;
        while rest.len() > 16383 {
            let multiplier = std::cmp::min(rest.len() / 16384, 4);
            let chunk = multiplier * 16384;
            self.write_bits(0xC0 | multiplier as u64, 8);
            self.write_bytes(&rest[..chunk]);
            rest = &rest[chunk..];
        }
        self.encode_length_determinant(rest.len())?;
        self.write_bytes(rest);
        Ok(())
    }

    /// Write bits preceded by their (unaligned) length, fragmenting per
    /// X.691 11.9.3.8 (16K-multiple bit blocks) when the count exceeds 16383.
    pub fn encode_fragmented_bits(&mut self, bits: &BitSlice<u8, Msb0>) -> PerResult<()> {
        let mut rest = bits;
        while rest.len() > 16383 {
            let multiplier = std::cmp::min(rest.len() / 16384, 4);
            let chunk = multiplier * 16384;
            self.write_bits(0xC0 | multiplier as u64, 8);
            for bit in &rest[..chunk] {
                self.write_bit(*bit);
            }
            rest = &rest[chunk..];
        }
        self.encode_length_determinant(rest.len())?;
        for bit in rest {
            self.write_bit(*bit);
        }
        Ok(())
    }

    /// Encode a length constrained to `min..=max` as a constrained whole number.
    pub fn encode_constrained_length(
        &mut self,
        length: usize,
        min: usize,
        max: usize,
    ) -> PerResult<()> {
        let constraint = Constraint::new(min as i64, max as i64);
        self.encode_constrained_whole_number(length as i64, &constraint)
    }

    /// Encode a normally-small non-negative whole number (X.691 11.6).
    pub fn encode_normally_small_non_negative(&mut self, value: u64) -> PerResult<()> {
        if value <= 63 {
            // Small: 0 + 6-bit value.
            self.write_bit(false);
            self.write_bits(value, 6);
        } else {
            // Large: 1 + semi-constrained whole number (length + min octets),
            // all bit-unaligned.
            self.write_bit(true);
            let mut buf = Vec::new();
            let mut v = value;
            while v > 0 {
                buf.push((v & 0xFF) as u8);
                v >>= 8;
            }
            buf.reverse();
            self.encode_length_determinant(buf.len())?;
            self.write_bytes(&buf);
        }
        Ok(())
    }

    /// Encode a normally-small LENGTH (X.691 11.9.4.2), lower bound 1.
    ///
    /// Used for the size of a SEQUENCE extension-addition presence bit-map.
    /// `n` is the count (>= 1): `0 + (n-1):6` when `n <= 64`, otherwise
    /// `1` followed by a general length determinant.
    pub fn encode_normally_small_length(&mut self, n: usize) -> PerResult<()> {
        if n == 0 {
            return Err(PerError::InvalidLength { length: 0 });
        }
        if n <= 64 {
            self.write_bit(false);
            self.write_bits((n - 1) as u64, 6);
        } else {
            self.write_bit(true);
            self.encode_length_determinant(n)?;
        }
        Ok(())
    }

    /// Encode an ENUMERATED (X.691 14), UNALIGNED.
    ///
    /// Root values use a constrained whole number; for an extensible type an
    /// extension marker bit precedes it, and extension additions are encoded
    /// as their normally-small index past the end of the root.
    pub fn encode_enumerated(&mut self, value: i64, constraint: &Constraint) -> PerResult<()> {
        if constraint.extensible {
            let in_root = value >= constraint.min && value <= constraint.max;
            self.write_bit(!in_root);
            if in_root {
                self.encode_constrained_whole_number(value, constraint)?;
            } else {
                if value <= constraint.max {
                    return Err(PerError::ConstraintViolation {
                        value,
                        min: constraint.min,
                        max: constraint.max,
                    });
                }
                self.encode_normally_small_non_negative((value - constraint.max - 1) as u64)?;
            }
        } else {
            self.encode_constrained_whole_number(value, constraint)?;
        }
        Ok(())
    }

    /// Encode a CHOICE index (X.691 23), UNALIGNED.
    pub fn encode_choice_index(
        &mut self,
        index: usize,
        num_alternatives: usize,
        extensible: bool,
    ) -> PerResult<()> {
        if extensible {
            let in_root = index < num_alternatives;
            self.write_bit(!in_root);
            if in_root {
                let constraint = Constraint::new(0, (num_alternatives - 1) as i64);
                self.encode_constrained_whole_number(index as i64, &constraint)?;
            } else {
                self.encode_normally_small_non_negative((index - num_alternatives) as u64)?;
            }
        } else {
            if index >= num_alternatives {
                return Err(PerError::InvalidChoiceIndex {
                    index,
                    max: num_alternatives - 1,
                });
            }
            let constraint = Constraint::new(0, (num_alternatives - 1) as i64);
            self.encode_constrained_whole_number(index as i64, &constraint)?;
        }
        Ok(())
    }

    /// Encode an OCTET STRING (X.691 17), UNALIGNED — never octet-aligned.
    pub fn encode_octet_string(
        &mut self,
        data: &[u8],
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<()> {
        let len = data.len();
        match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => {
                if len != min {
                    return Err(PerError::InvalidLength { length: len });
                }
                self.write_bytes(data);
            }
            (Some(min), Some(max)) => {
                self.encode_constrained_length(len, min, max)?;
                self.write_bytes(data);
            }
            _ => {
                // Unconstrained: length-prefixed, fragmenting beyond 16383.
                self.encode_fragmented_octets(data)?;
            }
        }
        Ok(())
    }

    /// Encode a BIT STRING (X.691 16), UNALIGNED — never octet-aligned.
    pub fn encode_bit_string(
        &mut self,
        bits: &BitSlice<u8, Msb0>,
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<()> {
        let len = bits.len();
        match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => {
                if len != min {
                    return Err(PerError::InvalidLength { length: len });
                }
                for bit in bits {
                    self.write_bit(*bit);
                }
            }
            (Some(min), Some(max)) => {
                self.encode_constrained_length(len, min, max)?;
                for bit in bits {
                    self.write_bit(*bit);
                }
            }
            _ => {
                self.encode_fragmented_bits(bits)?;
            }
        }
        Ok(())
    }

    /// Encode a SEQUENCE preamble (X.691 18): the extension marker bit (only
    /// when the type is extensible) followed by one presence bit per
    /// OPTIONAL / DEFAULT root field, in declaration order.
    ///
    /// Pass `extension_present = Some(b)` for an extensible SEQUENCE (with `b`
    /// indicating whether any extension additions follow), or `None` for a
    /// non-extensible SEQUENCE (no marker bit emitted).
    pub fn encode_sequence_preamble(
        &mut self,
        extension_present: Option<bool>,
        optionals: &[bool],
    ) {
        if let Some(ext) = extension_present {
            self.write_bit(ext);
        }
        for &present in optionals {
            self.write_bit(present);
        }
    }

    /// Encode a SEQUENCE extension-addition block (X.691 18.7-18.9).
    ///
    /// Layout: normally-small LENGTH giving the bit-map size, then one presence
    /// bit per addition, then — for each present addition — its value wrapped
    /// as an OPEN TYPE (length determinant + that many octets). Each `Some`
    /// member must already be the byte-padded UPER encoding of that addition
    /// (i.e. the bytes from a nested [`UperEncoder::into_bytes`]).
    pub fn encode_extension_additions(&mut self, members: &[Option<Vec<u8>>]) -> PerResult<()> {
        if members.is_empty() {
            return Ok(());
        }
        self.encode_normally_small_length(members.len())?;
        for m in members {
            self.write_bit(m.is_some());
        }
        for m in members.iter().flatten() {
            // OPEN TYPE wrapping == unconstrained octet string (len + octets),
            // which fragments automatically for very large additions.
            self.encode_octet_string(m, None, None)?;
        }
        Ok(())
    }
}

impl Default for UperEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimum-length two's-complement octets for an unconstrained integer
/// (X.691 11.4 / 8.3). Shared by the unconstrained-whole-number path.
fn twos_complement_min_octets(value: i64) -> Vec<u8> {
    if value >= 0 {
        let mut v = value as u64;
        let mut buf = Vec::new();
        if v == 0 {
            buf.push(0);
        } else {
            while v > 0 {
                buf.push((v & 0xFF) as u8);
                v >>= 8;
            }
            buf.reverse();
            // Leading zero so the sign bit reads as positive.
            if buf[0] & 0x80 != 0 {
                buf.insert(0, 0);
            }
        }
        buf
    } else {
        let mut v = value;
        let mut buf = Vec::new();
        loop {
            let byte = (v & 0xFF) as u8;
            buf.push(byte);
            v >>= 8;
            if v == -1 && (byte & 0x80 != 0) {
                break;
            }
            if v == 0 && (byte & 0x80 == 0) {
                break;
            }
        }
        buf.reverse();
        buf
    }
}

/// UPER (Unaligned PER) decoder over an MSB-first bit cursor.
pub struct UperDecoder<'a> {
    data: &'a BitSlice<u8, Msb0>,
    position: usize,
}

impl<'a> UperDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data: BitSlice::from_slice(data),
            position: 0,
        }
    }

    /// Current bit cursor position.
    pub fn bit_position(&self) -> usize {
        self.position
    }

    /// Bits remaining to be read.
    pub fn remaining_bits(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Read a single bit.
    pub fn read_bit(&mut self) -> PerResult<bool> {
        if self.position >= self.data.len() {
            return Err(PerError::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }
        let bit = self.data[self.position];
        self.position += 1;
        Ok(bit)
    }

    /// Read `num_bits` bits as a value, MSB first.
    pub fn read_bits(&mut self, num_bits: usize) -> PerResult<u64> {
        if self.position + num_bits > self.data.len() {
            return Err(PerError::BufferUnderflow {
                needed: num_bits,
                available: self.data.len() - self.position,
            });
        }
        let mut value: u64 = 0;
        for _ in 0..num_bits {
            value = (value << 1) | (self.data[self.position] as u64);
            self.position += 1;
        }
        Ok(value)
    }

    /// Read `num_bytes` octets (bit-unaligned).
    pub fn read_bytes(&mut self, num_bytes: usize) -> PerResult<Vec<u8>> {
        let needed = num_bytes
            .checked_mul(8)
            .ok_or(PerError::InvalidLength { length: num_bytes })?;
        if needed > self.remaining_bits() {
            return Err(PerError::BufferUnderflow {
                needed,
                available: self.remaining_bits(),
            });
        }
        let mut bytes = Vec::with_capacity(num_bytes);
        for _ in 0..num_bytes {
            bytes.push(self.read_bits(8)? as u8);
        }
        Ok(bytes)
    }

    /// Decode a constrained whole number (X.691 11.5, UNALIGNED).
    pub fn decode_constrained_whole_number(&mut self, constraint: &Constraint) -> PerResult<i64> {
        let range = constraint.range();
        if range == 1 {
            return Ok(constraint.min);
        }
        let bits = constraint.bits_needed();
        let offset = self.read_bits(bits)?;
        if range != 0 && offset >= range {
            return Err(PerError::DecodeError(format!(
                "Decoded offset {offset} outside constraint range {range}"
            )));
        }
        Ok(constraint.min + offset as i64)
    }

    /// Decode an unconstrained whole number (X.691 11.8 / 13.2.6).
    pub fn decode_unconstrained_whole_number(&mut self) -> PerResult<i64> {
        let len = self.decode_length_determinant()?;
        if len == 0 || len > 8 {
            return Err(PerError::DecodeError(format!(
                "Invalid unconstrained integer length: {len}"
            )));
        }
        let bytes = self.read_bytes(len)?;
        let negative = bytes[0] & 0x80 != 0;
        let mut value: i64 = if negative { -1 } else { 0 };
        for byte in bytes {
            value = (value << 8) | (byte as i64);
        }
        Ok(value)
    }

    /// Decode a length determinant (X.691 11.9), UNALIGNED. Rejects fragment
    /// headers — callers that fragment must drive [`Self::decode_length_fragment`].
    pub fn decode_length_determinant(&mut self) -> PerResult<usize> {
        let (length, fragmented) = self.decode_length_fragment()?;
        if fragmented {
            return Err(PerError::DecodeError(
                "Fragmented length determinant not permitted in this context".to_string(),
            ));
        }
        Ok(length)
    }

    /// Decode one length block (X.691 11.9.3), UNALIGNED.
    ///
    /// Returns `(length, fragmented)`; when `fragmented` is true, `length`
    /// items follow and another block must then be decoded.
    pub fn decode_length_fragment(&mut self) -> PerResult<(usize, bool)> {
        let first_byte = self.read_bits(8)? as u8;
        if first_byte & 0x80 == 0 {
            // Short form: 0xxxxxxx
            Ok((first_byte as usize, false))
        } else if first_byte & 0x40 == 0 {
            // Long form: 10xxxxxx xxxxxxxx
            let second_byte = self.read_bits(8)? as u8;
            Ok((
                (((first_byte & 0x3F) as usize) << 8) | (second_byte as usize),
                false,
            ))
        } else {
            // Fragment header: 11xxxxxx, multiplier of 16K in 1..=4
            let multiplier = (first_byte & 0x3F) as usize;
            if !(1..=4).contains(&multiplier) {
                return Err(PerError::InvalidLength {
                    length: multiplier * 16384,
                });
            }
            Ok((multiplier * 16384, true))
        }
    }

    /// Decode a constrained length determinant.
    pub fn decode_constrained_length(&mut self, min: usize, max: usize) -> PerResult<usize> {
        let constraint = Constraint::new(min as i64, max as i64);
        self.decode_constrained_whole_number(&constraint)
            .map(|v| v as usize)
    }

    /// Decode a normally-small non-negative whole number (X.691 11.6).
    pub fn decode_normally_small_non_negative(&mut self) -> PerResult<u64> {
        let large = self.read_bit()?;
        if !large {
            self.read_bits(6)
        } else {
            let len = self.decode_length_determinant()?;
            if len == 0 || len > 8 {
                return Err(PerError::DecodeError(format!(
                    "Invalid normally-small number length: {len}"
                )));
            }
            let mut value: u64 = 0;
            for _ in 0..len {
                value = (value << 8) | self.read_bits(8)?;
            }
            Ok(value)
        }
    }

    /// Decode a normally-small LENGTH (X.691 11.9.4.2), lower bound 1.
    pub fn decode_normally_small_length(&mut self) -> PerResult<usize> {
        let large = self.read_bit()?;
        if !large {
            Ok(self.read_bits(6)? as usize + 1)
        } else {
            self.decode_length_determinant()
        }
    }

    /// Decode an ENUMERATED (X.691 14), UNALIGNED.
    pub fn decode_enumerated(&mut self, constraint: &Constraint) -> PerResult<i64> {
        if constraint.extensible {
            let extended = self.read_bit()?;
            if !extended {
                self.decode_constrained_whole_number(constraint)
            } else {
                let index = self.decode_normally_small_non_negative()?;
                i64::try_from(index)
                    .ok()
                    .and_then(|i| constraint.max.checked_add(1)?.checked_add(i))
                    .ok_or_else(|| {
                        PerError::DecodeError(format!(
                            "Enumerated extension index {index} too large"
                        ))
                    })
            }
        } else {
            self.decode_constrained_whole_number(constraint)
        }
    }

    /// Decode a CHOICE index (X.691 23), UNALIGNED.
    pub fn decode_choice_index(
        &mut self,
        num_alternatives: usize,
        extensible: bool,
    ) -> PerResult<usize> {
        if extensible {
            let extended = self.read_bit()?;
            if !extended {
                let constraint = Constraint::new(0, (num_alternatives - 1) as i64);
                self.decode_constrained_whole_number(&constraint)
                    .map(|v| v as usize)
            } else {
                let ext_index = self.decode_normally_small_non_negative()?;
                usize::try_from(ext_index)
                    .ok()
                    .and_then(|i| num_alternatives.checked_add(i))
                    .ok_or_else(|| {
                        PerError::DecodeError(format!(
                            "Choice extension index {ext_index} too large"
                        ))
                    })
            }
        } else {
            let constraint = Constraint::new(0, (num_alternatives - 1) as i64);
            self.decode_constrained_whole_number(&constraint)
                .map(|v| v as usize)
        }
    }

    /// Decode an OCTET STRING (X.691 17), UNALIGNED.
    pub fn decode_octet_string(
        &mut self,
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<Vec<u8>> {
        let len = match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => min,
            (Some(min), Some(max)) => self.decode_constrained_length(min, max)?,
            _ => {
                let mut data = Vec::new();
                loop {
                    let (len, fragmented) = self.decode_length_fragment()?;
                    data.extend_from_slice(&self.read_bytes(len)?);
                    if !fragmented {
                        return Ok(data);
                    }
                }
            }
        };
        self.read_bytes(len)
    }

    /// Decode a BIT STRING (X.691 16), UNALIGNED.
    pub fn decode_bit_string(
        &mut self,
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<BitVec<u8, Msb0>> {
        let len = match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => min,
            (Some(min), Some(max)) => self.decode_constrained_length(min, max)?,
            _ => {
                let mut bits = BitVec::new();
                loop {
                    let (len, fragmented) = self.decode_length_fragment()?;
                    if len > self.remaining_bits() {
                        return Err(PerError::BufferUnderflow {
                            needed: len,
                            available: self.remaining_bits(),
                        });
                    }
                    for _ in 0..len {
                        bits.push(self.read_bit()?);
                    }
                    if !fragmented {
                        return Ok(bits);
                    }
                }
            }
        };
        if len > self.remaining_bits() {
            return Err(PerError::BufferUnderflow {
                needed: len,
                available: self.remaining_bits(),
            });
        }
        let mut bits = BitVec::with_capacity(len);
        for _ in 0..len {
            bits.push(self.read_bit()?);
        }
        Ok(bits)
    }

    /// Decode a SEQUENCE preamble (X.691 18): optional extension marker bit
    /// (only when `extensible`) plus `num_optionals` presence bits. Returns
    /// `(extension_present, optional_presence_bits)`.
    pub fn decode_sequence_preamble(
        &mut self,
        extensible: bool,
        num_optionals: usize,
    ) -> PerResult<(bool, Vec<bool>)> {
        let extension_present = if extensible { self.read_bit()? } else { false };
        let mut optionals = Vec::with_capacity(num_optionals);
        for _ in 0..num_optionals {
            optionals.push(self.read_bit()?);
        }
        Ok((extension_present, optionals))
    }

    /// Decode a SEQUENCE extension-addition block (X.691 18.7-18.9), the
    /// counterpart of [`UperEncoder::encode_extension_additions`]. Returns one
    /// entry per addition: `Some(open_type_octets)` when present, else `None`.
    pub fn decode_extension_additions(&mut self) -> PerResult<Vec<Option<Vec<u8>>>> {
        let n = self.decode_normally_small_length()?;
        let mut present = Vec::with_capacity(n);
        for _ in 0..n {
            present.push(self.read_bit()?);
        }
        let mut out = Vec::with_capacity(n);
        for p in present {
            if p {
                out.push(Some(self.decode_octet_string(None, None)?));
            } else {
                out.push(None);
            }
        }
        Ok(out)
    }
}

/// Trait for types that can be encoded with UPER.
pub trait UperEncode {
    fn encode_uper(&self, encoder: &mut UperEncoder) -> PerResult<()>;
}

/// Trait for types that can be decoded with UPER.
pub trait UperDecode: Sized {
    fn decode_uper(decoder: &mut UperDecoder) -> PerResult<Self>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Hand-derived X.691 UNALIGNED reference vectors ----------------------

    /// X.691 11.5.3: constrained INTEGER (0..7) = 5.
    /// range = 8 → bits_needed = 3. offset = 5-0 = 5 = binary 101.
    /// The bit stream is exactly `101` (3 bits, NO alignment, NO length).
    /// `into_bytes` zero-pads to one octet: 101_00000 = 0xA0.
    #[test]
    fn vec_constrained_int_0_7_eq_5() {
        let c = Constraint::new(0, 7);
        let mut enc = UperEncoder::new();
        enc.encode_constrained_whole_number(5, &c).unwrap();
        assert_eq!(enc.bit_length(), 3, "must be exactly 3 bits, no padding");
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0xA0]); // 1010_0000

        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), 5);
        assert_eq!(dec.bit_position(), 3);
    }

    /// Demonstrates the headline UPER difference vs APER for a >64K range.
    /// INTEGER (0..3279165) (RRC `ARFCN-ValueNR`): range = 3279166 →
    /// bits_needed = 22. The value is packed in 22 bits with NO length-of-length
    /// octet form and NO alignment.
    ///   3279165 = 0x32093D, low 22 bits = 11_0010_0000_1001_0011_1101.
    ///   Pad with 2 trailing zero bits to 24: 1100_1000 0010_0100 1111_0100
    ///   = 0xC8 0x24 0xF4.
    #[test]
    fn vec_constrained_over_64k_is_min_bits_not_length_of_length() {
        let c = Constraint::new(0, 3279165);
        assert_eq!(c.bits_needed(), 22);
        let mut enc = UperEncoder::new();
        enc.encode_constrained_whole_number(3279165, &c).unwrap();
        assert_eq!(enc.bit_length(), 22, "22 bits, no length-of-length octets");
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0xC8, 0x24, 0xF4]);

        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), 3279165);
    }

    /// SEQUENCE { a INTEGER (0..7) OPTIONAL } — NON-extensible.
    /// Preamble = 1 presence bit.
    /// Present, a=5:  preamble `1` + value `101` = `1101` → pad → 1101_0000 = 0xD0.
    /// Absent:        preamble `0`               = `0`    → pad → 0000_0000 = 0x00.
    #[test]
    fn vec_sequence_one_optional_present_vs_absent() {
        let c = Constraint::new(0, 7);

        // Present.
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(None, &[true]);
        enc.encode_constrained_whole_number(5, &c).unwrap();
        assert_eq!(enc.bit_length(), 4);
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0xD0]); // 1101_0000

        let mut dec = UperDecoder::new(&bytes);
        let (ext, opts) = dec.decode_sequence_preamble(false, 1).unwrap();
        assert!(!ext);
        assert_eq!(opts, vec![true]);
        assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), 5);

        // Absent.
        let mut enc = UperEncoder::new();
        enc.encode_sequence_preamble(None, &[false]);
        assert_eq!(enc.bit_length(), 1);
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0x00]);

        let mut dec = UperDecoder::new(&bytes);
        let (ext, opts) = dec.decode_sequence_preamble(false, 1).unwrap();
        assert!(!ext);
        assert_eq!(opts, vec![false]);
    }

    /// Extensible ENUMERATED { a, b, c, ...(ext), d, e }.
    /// Root b (value 1): ext-bit `0` + constrained(0..2)=range 3 → 2 bits,
    ///   offset 1 = `01`. Stream `001` → pad → 0010_0000 = 0x20.
    /// Addition d (value 3): ext-bit `1` + normally-small index (3-2-1)=0 →
    ///   small form `0` + 6-bit `000000`. Stream `1`+`0000000` = 1000_0000 = 0x80.
    #[test]
    fn vec_enumerated_extensible_root_vs_addition() {
        let c = Constraint::extensible(0, 2);

        // Root value b = 1.
        let mut enc = UperEncoder::new();
        enc.encode_enumerated(1, &c).unwrap();
        assert_eq!(enc.bit_length(), 3);
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0x20]); // 0010_0000
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_enumerated(&c).unwrap(), 1);

        // Extension addition d = 3.
        let mut enc = UperEncoder::new();
        enc.encode_enumerated(3, &c).unwrap();
        assert_eq!(enc.bit_length(), 8);
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0x80]); // 1000_0000
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_enumerated(&c).unwrap(), 3);
    }

    /// Extension-addition group with exactly ONE present member whose OPEN TYPE
    /// content is the single octet 0x2A.
    ///   normally-small-length(1) = `0` + (1-1)=0 in 6 bits   → `0000000`  (7 bits)
    ///   presence bit-map (1 addition, present)               → `1`        (1 bit)
    ///   open type: length-determinant(1) = `00000001`        → 0x01       (8 bits)
    ///              content octet                              → 0x2A       (8 bits)
    /// Concatenated: 0000000 1 | 00000001 | 00101010 = 0x01, 0x01, 0x2A.
    #[test]
    fn vec_extension_addition_group_one_present() {
        let members = vec![Some(vec![0x2Au8])];
        let mut enc = UperEncoder::new();
        enc.encode_extension_additions(&members).unwrap();
        assert_eq!(enc.bit_length(), 24);
        let bytes = enc.into_bytes();
        assert_eq!(bytes.as_ref(), &[0x01, 0x01, 0x2A]);

        let mut dec = UperDecoder::new(&bytes);
        let got = dec.decode_extension_additions().unwrap();
        assert_eq!(got, vec![Some(vec![0x2Au8])]);
    }

    /// Extension-addition group with one ABSENT and one PRESENT member.
    ///   normally-small-length(2) = `0` + (2-1)=1 in 6 bits   → `0000001`  (7 bits)
    ///   presence bit-map: absent, present                    → `01`       (2 bits)
    ///   open type for #1: length-determinant(2) `00000010`   → 0x02       (8 bits)
    ///                     content 0xBE, 0xEF                  → 0xBE 0xEF  (16 bits)
    /// 7+2+8+16 = 33 bits → pad to 40 (5 octets).
    #[test]
    fn vec_extension_addition_group_absent_then_present() {
        let members = vec![None, Some(vec![0xBE, 0xEF])];
        let mut enc = UperEncoder::new();
        enc.encode_extension_additions(&members).unwrap();
        assert_eq!(enc.bit_length(), 33);
        let bytes = enc.into_bytes();
        // Continuous bit string, then regroup by 8 and zero-pad the tail:
        //   0000001 | 01 | 00000010 | 10111110 | 11101111
        // = 00000010 10000001 01011111 01110111 1_0000000
        // =   0x02     0x81     0x5F     0x77     0x80
        assert_eq!(bytes.as_ref(), &[0x02, 0x81, 0x5F, 0x77, 0x80]);

        let mut dec = UperDecoder::new(&bytes);
        let got = dec.decode_extension_additions().unwrap();
        assert_eq!(got, vec![None, Some(vec![0xBE, 0xEF])]);
    }

    /// Length determinant short vs long form, UNALIGNED (no leading octet pad).
    /// 5    → `0` + 0000101 = 00000101 = 0x05  (8 bits)
    /// 200  → `10` + 14-bit 200 = 1000_0000_1100_1000 = 0x80 0xC8 (16 bits)
    #[test]
    fn vec_length_determinant_forms() {
        let mut enc = UperEncoder::new();
        enc.encode_length_determinant(5).unwrap();
        assert_eq!(enc.bit_length(), 8);
        assert_eq!(enc.into_bytes().as_ref(), &[0x05]);

        let mut enc = UperEncoder::new();
        enc.encode_length_determinant(200).unwrap();
        assert_eq!(enc.bit_length(), 16);
        assert_eq!(enc.into_bytes().as_ref(), &[0x80, 0xC8]);
    }

    /// normally-small-non-negative: small 5 = `0`+000101 (7 bits); pad → 0x0A.
    #[test]
    fn vec_normally_small_non_negative_small() {
        let mut enc = UperEncoder::new();
        enc.encode_normally_small_non_negative(5).unwrap();
        assert_eq!(enc.bit_length(), 7);
        // 0 000101 0(pad) = 0000_1010 = 0x0A
        assert_eq!(enc.into_bytes().as_ref(), &[0x0A]);
    }

    // ---- Round-trip property tests ------------------------------------------

    #[test]
    fn rt_constrained_whole_number() {
        let c = Constraint::new(-5, 250); // range 256 -> 8 bits unaligned
        for v in [-5i64, -1, 0, 1, 100, 249, 250] {
            let mut enc = UperEncoder::new();
            enc.encode_constrained_whole_number(v, &c).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), v);
        }
    }

    #[test]
    fn rt_constrained_packs_back_to_back_no_alignment() {
        // Two 3-bit fields + one 2-bit field = 8 bits, ZERO padding between.
        let c3 = Constraint::new(0, 7);
        let c2 = Constraint::new(0, 2);
        let mut enc = UperEncoder::new();
        enc.encode_constrained_whole_number(5, &c3).unwrap(); // 101
        enc.encode_constrained_whole_number(2, &c3).unwrap(); // 010
        enc.encode_constrained_whole_number(1, &c2).unwrap(); // 01
        assert_eq!(enc.bit_length(), 8);
        let bytes = enc.into_bytes();
        // 101 010 01 = 1010_1001 = 0xA9
        assert_eq!(bytes.as_ref(), &[0xA9]);

        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_constrained_whole_number(&c3).unwrap(), 5);
        assert_eq!(dec.decode_constrained_whole_number(&c3).unwrap(), 2);
        assert_eq!(dec.decode_constrained_whole_number(&c2).unwrap(), 1);
    }

    #[test]
    fn rt_unconstrained_whole_number() {
        for v in [0i64, 1, -1, 127, 128, -128, 255, -255, 65535, -65536, i64::MIN, i64::MAX] {
            let mut enc = UperEncoder::new();
            enc.encode_unconstrained_whole_number(v).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_unconstrained_whole_number().unwrap(), v);
        }
    }

    #[test]
    fn rt_normally_small_non_negative() {
        for v in [0u64, 1, 63, 64, 255, 256, 1_000_000, u32::MAX as u64] {
            let mut enc = UperEncoder::new();
            enc.encode_normally_small_non_negative(v).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_normally_small_non_negative().unwrap(), v);
        }
    }

    #[test]
    fn rt_normally_small_length() {
        for n in [1usize, 2, 63, 64, 65, 200, 16383] {
            let mut enc = UperEncoder::new();
            enc.encode_normally_small_length(n).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_normally_small_length().unwrap(), n);
        }
    }

    #[test]
    fn rt_length_determinant() {
        for len in [0usize, 1, 127, 128, 255, 1000, 16383] {
            let mut enc = UperEncoder::new();
            enc.encode_length_determinant(len).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_length_determinant().unwrap(), len);
        }
    }

    #[test]
    fn rt_enumerated_extensible() {
        let c = Constraint::extensible(0, 4);
        for v in [0i64, 2, 4, 5, 6, 70] {
            let mut enc = UperEncoder::new();
            enc.encode_enumerated(v, &c).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_enumerated(&c).unwrap(), v);
        }
    }

    #[test]
    fn rt_choice_index_extensible() {
        for idx in [0usize, 1, 3, 4, 5, 100] {
            let mut enc = UperEncoder::new();
            enc.encode_choice_index(idx, 4, true).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_choice_index(4, true).unwrap(), idx);
        }
    }

    #[test]
    fn rt_choice_index_non_extensible() {
        for idx in 0..8usize {
            let mut enc = UperEncoder::new();
            enc.encode_choice_index(idx, 8, false).unwrap();
            assert_eq!(enc.bit_length(), 3); // range 8 -> 3 bits, unaligned
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_choice_index(8, false).unwrap(), idx);
        }
    }

    #[test]
    fn rt_octet_string_variants() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        // Fixed.
        let mut enc = UperEncoder::new();
        enc.encode_octet_string(&data, Some(4), Some(4)).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_octet_string(Some(4), Some(4)).unwrap(), data);

        // Constrained.
        let mut enc = UperEncoder::new();
        enc.encode_octet_string(&data, Some(1), Some(10)).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_octet_string(Some(1), Some(10)).unwrap(), data);

        // Unconstrained.
        let mut enc = UperEncoder::new();
        enc.encode_octet_string(&data, None, None).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_octet_string(None, None).unwrap(), data);
    }

    #[test]
    fn rt_octet_string_unaligned_after_odd_offset() {
        // A 3-bit field first forces the octet string to start mid-octet; UPER
        // must NOT realign it (a key APER/UPER divergence).
        let c = Constraint::new(0, 7);
        let data = vec![0xFF, 0x00];
        let mut enc = UperEncoder::new();
        enc.encode_constrained_whole_number(5, &c).unwrap(); // 3 bits
        enc.encode_octet_string(&data, Some(2), Some(2)).unwrap(); // fixed 2 octets, no align
        assert_eq!(enc.bit_length(), 3 + 16); // no realignment padding
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), 5);
        assert_eq!(dec.decode_octet_string(Some(2), Some(2)).unwrap(), data);
    }

    #[test]
    fn rt_bit_string_variants() {
        let mut src: BitVec<u8, Msb0> = BitVec::new();
        for b in [true, false, true, true, false, false, false, true, true] {
            src.push(b);
        }
        // Fixed (9 bits -> would be aligned-padded in APER, never in UPER).
        let mut enc = UperEncoder::new();
        enc.encode_bit_string(&src, Some(9), Some(9)).unwrap();
        assert_eq!(enc.bit_length(), 9);
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_bit_string(Some(9), Some(9)).unwrap(), src);

        // Constrained.
        let mut enc = UperEncoder::new();
        enc.encode_bit_string(&src, Some(1), Some(32)).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_bit_string(Some(1), Some(32)).unwrap(), src);

        // Unconstrained.
        let mut enc = UperEncoder::new();
        enc.encode_bit_string(&src, None, None).unwrap();
        let bytes = enc.into_bytes();
        let mut dec = UperDecoder::new(&bytes);
        assert_eq!(dec.decode_bit_string(None, None).unwrap(), src);
    }

    #[test]
    fn rt_fragmented_octet_string() {
        // Spans the long-form boundary and the 16K fragmentation boundary.
        for len in [16383usize, 16384, 20000, 70000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut enc = UperEncoder::new();
            enc.encode_octet_string(&data, None, None).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            assert_eq!(dec.decode_octet_string(None, None).unwrap(), data);
        }
    }

    #[test]
    fn rt_full_extensible_sequence() {
        // Build an extensible SEQUENCE with one optional root field and one
        // present extension addition, end to end.
        let c = Constraint::new(0, 255);

        let mut enc = UperEncoder::new();
        // ext additions follow + optional root field present.
        enc.encode_sequence_preamble(Some(true), &[true]);
        enc.encode_constrained_whole_number(0xAB, &c).unwrap();
        // One extension addition (an INTEGER(0..255)=0xCD), open-type wrapped.
        let mut sub = UperEncoder::new();
        sub.encode_constrained_whole_number(0xCD, &c).unwrap();
        let member = sub.into_bytes().to_vec();
        enc.encode_extension_additions(&[Some(member.clone())]).unwrap();
        let bytes = enc.into_bytes();

        let mut dec = UperDecoder::new(&bytes);
        let (ext, opts) = dec.decode_sequence_preamble(true, 1).unwrap();
        assert!(ext);
        assert_eq!(opts, vec![true]);
        assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), 0xAB);
        let adds = dec.decode_extension_additions().unwrap();
        assert_eq!(adds, vec![Some(member)]);
        // And the wrapped addition decodes back to its value.
        let mut sub_dec = UperDecoder::new(adds[0].as_ref().unwrap());
        assert_eq!(sub_dec.decode_constrained_whole_number(&c).unwrap(), 0xCD);
    }

    // ---- Negative / malformed-input tests -----------------------------------

    #[test]
    fn err_constrained_out_of_range_encode() {
        let c = Constraint::new(0, 7);
        let mut enc = UperEncoder::new();
        assert!(enc.encode_constrained_whole_number(8, &c).is_err());
    }

    #[test]
    fn err_constrained_offset_out_of_range_decode() {
        // range 0..300 -> 9 bits; feed 0x1FF (offset 511) which exceeds 300.
        let c = Constraint::new(0, 300);
        let mut dec = UperDecoder::new(&[0xFF, 0x80]); // 1_1111_1111...
        assert!(dec.decode_constrained_whole_number(&c).is_err());
    }

    #[test]
    fn err_unconstrained_length_too_large_decode() {
        // length determinant 9 (> 8 octets for an i64).
        let mut dec = UperDecoder::new(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(dec.decode_unconstrained_whole_number().is_err());
    }

    #[test]
    fn err_buffer_underflow() {
        let mut dec = UperDecoder::new(&[]);
        assert!(dec.read_bit().is_err());
        let mut dec = UperDecoder::new(&[0x00]);
        assert!(dec.read_bits(9).is_err());
    }

    #[test]
    fn err_length_fragment_invalid_multiplier() {
        // 0xC0 = fragment header with multiplier 0 (illegal).
        let mut dec = UperDecoder::new(&[0xC0]);
        assert!(dec.decode_length_determinant().is_err());
    }

    // proptest-style coverage using the proptest dev-dependency.
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_constrained_roundtrip(min in -1000i64..1000, span in 0u64..5000, v_off in 0u64..5000) {
            let max = min + span as i64;
            let c = Constraint::new(min, max);
            let range = c.range();
            prop_assume!(range > 0);
            let v = min + (v_off % range) as i64;
            let mut enc = UperEncoder::new();
            enc.encode_constrained_whole_number(v, &c).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            prop_assert_eq!(dec.decode_constrained_whole_number(&c).unwrap(), v);
        }

        #[test]
        fn prop_unconstrained_roundtrip(v in any::<i64>()) {
            let mut enc = UperEncoder::new();
            enc.encode_unconstrained_whole_number(v).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            prop_assert_eq!(dec.decode_unconstrained_whole_number().unwrap(), v);
        }

        #[test]
        fn prop_octet_string_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let mut enc = UperEncoder::new();
            enc.encode_octet_string(&data, None, None).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            prop_assert_eq!(dec.decode_octet_string(None, None).unwrap(), data);
        }

        #[test]
        fn prop_normally_small_roundtrip(v in any::<u64>()) {
            let mut enc = UperEncoder::new();
            enc.encode_normally_small_non_negative(v).unwrap();
            let bytes = enc.into_bytes();
            let mut dec = UperDecoder::new(&bytes);
            prop_assert_eq!(dec.decode_normally_small_non_negative().unwrap(), v);
        }
    }
}
