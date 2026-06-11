//! PER (Packed Encoding Rules) encoding/decoding
//!
//! Implementation of Aligned PER (APER) as used by NGAP and S1AP protocols.
//! Based on ITU-T X.691 and matching the behavior of lib/asn1c/common/

use bitvec::prelude::*;
use bytes::Bytes;
use thiserror::Error;

/// PER codec errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum PerError {
    #[error("Buffer underflow: need {needed} bits, have {available}")]
    BufferUnderflow { needed: usize, available: usize },
    #[error("Buffer overflow: cannot write {needed} bits")]
    BufferOverflow { needed: usize },
    #[error("Invalid constraint: value {value} not in range {min}..={max}")]
    ConstraintViolation { value: i64, min: i64, max: i64 },
    #[error("Invalid choice index: {index} (max {max})")]
    InvalidChoiceIndex { index: usize, max: usize },
    #[error("Invalid length: {length}")]
    InvalidLength { length: usize },
    #[error("Unsupported extension")]
    UnsupportedExtension,
    #[error("Decode error: {0}")]
    DecodeError(String),
}

pub type PerResult<T> = Result<T, PerError>;

/// Constraint definition for constrained integers
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Constraint {
    pub min: i64,
    pub max: i64,
    pub extensible: bool,
}

impl Constraint {
    pub const fn new(min: i64, max: i64) -> Self {
        Self {
            min,
            max,
            extensible: false,
        }
    }

    pub const fn extensible(min: i64, max: i64) -> Self {
        Self {
            min,
            max,
            extensible: true,
        }
    }

    /// Calculate the range of the constraint
    pub fn range(&self) -> u64 {
        if self.max >= self.min {
            (self.max - self.min) as u64 + 1
        } else {
            0
        }
    }

    /// Calculate bits needed to encode values in this range
    pub fn bits_needed(&self) -> usize {
        let range = self.range();
        if range <= 1 {
            0
        } else {
            64 - (range - 1).leading_zeros() as usize
        }
    }
}

/// APER (Aligned PER) Encoder
pub struct AperEncoder {
    buffer: BitVec<u8, Msb0>,
}

impl AperEncoder {
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

    /// Get the encoded bytes
    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.buffer.into_vec())
    }

    /// Get current bit position
    pub fn bit_position(&self) -> usize {
        self.buffer.len()
    }

    /// Align to octet boundary
    pub fn align(&mut self) {
        let remainder = self.buffer.len() % 8;
        if remainder != 0 {
            let padding = 8 - remainder;
            for _ in 0..padding {
                self.buffer.push(false);
            }
        }
    }

    /// Write a single bit
    pub fn write_bit(&mut self, bit: bool) {
        self.buffer.push(bit);
    }

    /// Write multiple bits from a value (MSB first)
    pub fn write_bits(&mut self, value: u64, num_bits: usize) {
        for i in (0..num_bits).rev() {
            self.buffer.push((value >> i) & 1 == 1);
        }
    }

    /// Write raw bytes
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_bits(*byte as u64, 8);
        }
    }

    /// Encode constrained whole number (X.691 Section 12.2)
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
        let offset = (value - constraint.min) as u64;

        if range == 1 {
            // No encoding needed
            return Ok(());
        }

        if range <= 255 {
            // Non-negative-binary-integer in minimum bits
            let bits = constraint.bits_needed();
            self.write_bits(offset, bits);
        } else if range == 256 {
            // One octet, aligned
            self.align();
            self.write_bits(offset, 8);
        } else if range <= 65536 {
            // Two octets, aligned
            self.align();
            self.write_bits(offset, 16);
        } else {
            // Range > 64K: length-of-length form (X.691 Section 13.2.6).
            // The offset is encoded in the minimum number of octets, preceded by
            // that octet count as a constrained length (1..=b, where b is the
            // octet width of the whole range).
            let max_octets = constraint.bits_needed().div_ceil(8);
            let num_octets = if offset == 0 {
                1
            } else {
                (64 - offset.leading_zeros() as usize).div_ceil(8)
            };
            let len_constraint = Constraint::new(1, max_octets as i64);
            self.encode_constrained_whole_number(num_octets as i64, &len_constraint)?;
            self.align();
            for i in (0..num_octets).rev() {
                self.write_bits((offset >> (i * 8)) & 0xFF, 8);
            }
        }

        Ok(())
    }

    /// Encode unconstrained whole number (X.691 Section 12.2.6)
    pub fn encode_unconstrained_whole_number(&mut self, value: i64) -> PerResult<()> {
        let bytes = if value >= 0 {
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
                // Add leading zero if high bit set (to indicate positive)
                if buf[0] & 0x80 != 0 {
                    buf.insert(0, 0);
                }
            }
            buf
        } else {
            // Two's complement for negative
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
        };

        self.encode_length_determinant(bytes.len())?;
        self.align();
        self.write_bytes(&bytes);
        Ok(())
    }

    /// Encode length determinant (X.691 Section 11.9)
    ///
    /// A single length determinant can only express up to 16383. Larger values
    /// require fragmentation, where 16K-multiple length blocks interleave with
    /// the data they describe (Section 11.9.3) — use `encode_fragmented_octets`
    /// or `encode_fragmented_bits` for those.
    pub fn encode_length_determinant(&mut self, length: usize) -> PerResult<()> {
        self.align();
        if length <= 127 {
            // Short form: 0xxxxxxx
            self.write_bits(length as u64, 8);
        } else if length <= 16383 {
            // Long form: 10xxxxxx xxxxxxxx
            self.write_bits(0x8000 | length as u64, 16);
        } else {
            // Lengths > 16383 cannot be expressed by a standalone determinant
            return Err(PerError::InvalidLength { length });
        }
        Ok(())
    }

    /// Write octets preceded by their length, fragmenting per X.691 Section 11.9.3.
    ///
    /// Lengths > 16383 are split into 16K-multiple fragments, each fragment
    /// header (11xxxxxx, multiplier 1..=4) immediately followed by its data,
    /// terminated by a final short/long-form block (possibly of length zero).
    pub fn encode_fragmented_octets(&mut self, data: &[u8]) -> PerResult<()> {
        let mut rest = data;
        while rest.len() > 16383 {
            let multiplier = std::cmp::min(rest.len() / 16384, 4);
            let chunk = multiplier * 16384;
            self.align();
            self.write_bits(0xC0 | multiplier as u64, 8);
            self.write_bytes(&rest[..chunk]);
            rest = &rest[chunk..];
        }
        self.encode_length_determinant(rest.len())?;
        self.write_bytes(rest);
        Ok(())
    }

    /// Write bits preceded by their length, fragmenting per X.691 Section 11.9.3.
    /// Fragments are counted in bits (16K-multiple blocks of bits).
    pub fn encode_fragmented_bits(&mut self, bits: &BitSlice<u8, Msb0>) -> PerResult<()> {
        let mut rest = bits;
        while rest.len() > 16383 {
            let multiplier = std::cmp::min(rest.len() / 16384, 4);
            let chunk = multiplier * 16384;
            self.align();
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

    /// Encode constrained length determinant
    pub fn encode_constrained_length(
        &mut self,
        length: usize,
        min: usize,
        max: usize,
    ) -> PerResult<()> {
        let constraint = Constraint::new(min as i64, max as i64);
        self.encode_constrained_whole_number(length as i64, &constraint)
    }

    /// Encode ENUMERATED (X.691 Section 14)
    pub fn encode_enumerated(&mut self, value: i64, constraint: &Constraint) -> PerResult<()> {
        if constraint.extensible {
            let in_root = value >= constraint.min && value <= constraint.max;
            self.write_bit(!in_root);
            if in_root {
                self.encode_constrained_whole_number(value, constraint)?;
            } else {
                // Extension additions are encoded as their index within the
                // extension list, not their absolute value (X.691 Section 14.6)
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

    /// Encode normally small non-negative whole number (X.691 Section 11.6)
    pub fn encode_normally_small_non_negative(&mut self, value: u64) -> PerResult<()> {
        if value <= 63 {
            self.write_bit(false);
            self.write_bits(value, 6);
        } else {
            // Semi-constrained whole number with lower bound 0 (Section 11.6.2):
            // length determinant followed by the minimum unsigned octets
            self.write_bit(true);
            let mut buf = Vec::new();
            let mut v = value;
            while v > 0 {
                buf.push((v & 0xFF) as u8);
                v >>= 8;
            }
            buf.reverse();
            self.encode_length_determinant(buf.len())?;
            self.align();
            self.write_bytes(&buf);
        }
        Ok(())
    }

    /// Encode CHOICE index (X.691 Section 23)
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

    /// Encode OCTET STRING (X.691 Section 17)
    pub fn encode_octet_string(
        &mut self,
        data: &[u8],
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<()> {
        let len = data.len();

        match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => {
                // Fixed size - no length encoding
                if len != min {
                    return Err(PerError::InvalidLength { length: len });
                }
                if min > 2 {
                    self.align();
                }
                self.write_bytes(data);
            }
            (Some(min), Some(max)) => {
                // Constrained
                self.encode_constrained_length(len, min, max)?;
                if max > 2 {
                    self.align();
                }
                self.write_bytes(data);
            }
            _ => {
                // Unconstrained - fragments interleave with data when > 16383
                self.encode_fragmented_octets(data)?;
            }
        }
        Ok(())
    }

    /// Encode BIT STRING (X.691 Section 16)
    pub fn encode_bit_string(
        &mut self,
        bits: &BitSlice<u8, Msb0>,
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<()> {
        let len = bits.len();

        match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => {
                // Fixed size
                if len != min {
                    return Err(PerError::InvalidLength { length: len });
                }
                if min > 16 {
                    self.align();
                }
                for bit in bits {
                    self.write_bit(*bit);
                }
            }
            (Some(min), Some(max)) => {
                self.encode_constrained_length(len, min, max)?;
                if max > 16 {
                    self.align();
                }
                for bit in bits {
                    self.write_bit(*bit);
                }
            }
            _ => {
                // Unconstrained - fragments interleave with data when > 16383
                self.encode_fragmented_bits(bits)?;
            }
        }
        Ok(())
    }
}

impl Default for AperEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// APER (Aligned PER) Decoder
pub struct AperDecoder<'a> {
    data: &'a BitSlice<u8, Msb0>,
    position: usize,
}

impl<'a> AperDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data: BitSlice::from_slice(data),
            position: 0,
        }
    }

    /// Get current bit position
    pub fn bit_position(&self) -> usize {
        self.position
    }

    /// Get remaining bits
    pub fn remaining_bits(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Align to octet boundary
    pub fn align(&mut self) {
        let remainder = self.position % 8;
        if remainder != 0 {
            self.position += 8 - remainder;
        }
    }

    /// Read a single bit
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

    /// Read multiple bits as a value (MSB first)
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

    /// Read raw bytes
    pub fn read_bytes(&mut self, num_bytes: usize) -> PerResult<Vec<u8>> {
        // Validate availability before allocating so malformed lengths cannot
        // trigger huge allocations or arithmetic overflow
        let needed = num_bytes.checked_mul(8).ok_or(PerError::InvalidLength {
            length: num_bytes,
        })?;
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

    /// Decode constrained whole number (X.691 Section 12.2)
    pub fn decode_constrained_whole_number(&mut self, constraint: &Constraint) -> PerResult<i64> {
        let range = constraint.range();

        if range == 1 {
            return Ok(constraint.min);
        }

        let offset = if range <= 255 {
            let bits = constraint.bits_needed();
            self.read_bits(bits)?
        } else if range == 256 {
            self.align();
            self.read_bits(8)?
        } else if range <= 65536 {
            self.align();
            self.read_bits(16)?
        } else {
            // Range > 64K: length-of-length form (X.691 Section 13.2.6)
            let max_octets = constraint.bits_needed().div_ceil(8);
            let len_constraint = Constraint::new(1, max_octets as i64);
            let num_octets = self.decode_constrained_whole_number(&len_constraint)? as usize;
            self.align();
            let mut value: u64 = 0;
            for _ in 0..num_octets {
                value = (value << 8) | self.read_bits(8)?;
            }
            value
        };

        // Reject offsets outside the constraint so malformed input cannot
        // produce out-of-range (or overflowing) values
        if range != 0 && offset >= range {
            return Err(PerError::DecodeError(format!(
                "Decoded offset {offset} outside constraint range {range}"
            )));
        }

        Ok(constraint.min + offset as i64)
    }

    /// Decode unconstrained whole number (X.691 Section 12.2.6)
    pub fn decode_unconstrained_whole_number(&mut self) -> PerResult<i64> {
        let len = self.decode_length_determinant()?;
        // A conformant encoder emits 1..=8 octets for an i64; anything else is
        // malformed and would silently truncate
        if len == 0 || len > 8 {
            return Err(PerError::DecodeError(format!(
                "Invalid unconstrained integer length: {len}"
            )));
        }
        self.align();
        let bytes = self.read_bytes(len)?;

        // Check sign bit
        let negative = bytes[0] & 0x80 != 0;

        let mut value: i64 = if negative { -1 } else { 0 };
        for byte in bytes {
            value = (value << 8) | (byte as i64);
        }

        Ok(value)
    }

    /// Decode length determinant (X.691 Section 11.9)
    ///
    /// Fragment headers (11xxxxxx) are rejected here because fragmented lengths
    /// interleave with the data they describe (Section 11.9.3) — callers that
    /// support fragmentation must drive `decode_length_fragment` directly.
    pub fn decode_length_determinant(&mut self) -> PerResult<usize> {
        let (length, fragmented) = self.decode_length_fragment()?;
        if fragmented {
            return Err(PerError::DecodeError(
                "Fragmented length determinant not permitted in this context".to_string(),
            ));
        }
        Ok(length)
    }

    /// Decode one length block (X.691 Section 11.9.3)
    ///
    /// Returns `(length, fragmented)`. When `fragmented` is true, `length`
    /// items of data follow immediately, after which the caller must decode
    /// the next length block; a non-fragmented block terminates the sequence.
    pub fn decode_length_fragment(&mut self) -> PerResult<(usize, bool)> {
        self.align();
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

    /// Decode constrained length determinant
    pub fn decode_constrained_length(&mut self, min: usize, max: usize) -> PerResult<usize> {
        let constraint = Constraint::new(min as i64, max as i64);
        self.decode_constrained_whole_number(&constraint)
            .map(|v| v as usize)
    }

    /// Decode ENUMERATED (X.691 Section 14)
    pub fn decode_enumerated(&mut self, constraint: &Constraint) -> PerResult<i64> {
        if constraint.extensible {
            let extended = self.read_bit()?;
            if !extended {
                self.decode_constrained_whole_number(constraint)
            } else {
                // Extension additions carry their index within the extension
                // list, offset from the end of the root (X.691 Section 14.6)
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

    /// Decode normally small non-negative whole number (X.691 Section 11.6)
    pub fn decode_normally_small_non_negative(&mut self) -> PerResult<u64> {
        let large = self.read_bit()?;
        if !large {
            self.read_bits(6)
        } else {
            // Semi-constrained whole number with lower bound 0 (Section 11.6.2)
            let len = self.decode_length_determinant()?;
            if len == 0 || len > 8 {
                return Err(PerError::DecodeError(format!(
                    "Invalid normally-small number length: {len}"
                )));
            }
            self.align();
            let mut value: u64 = 0;
            for _ in 0..len {
                value = (value << 8) | self.read_bits(8)?;
            }
            Ok(value)
        }
    }

    /// Decode CHOICE index (X.691 Section 23)
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

    /// Decode OCTET STRING (X.691 Section 17)
    pub fn decode_octet_string(
        &mut self,
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<Vec<u8>> {
        let len = match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => {
                if min > 2 {
                    self.align();
                }
                min
            }
            (Some(min), Some(max)) => {
                let len = self.decode_constrained_length(min, max)?;
                if max > 2 {
                    self.align();
                }
                len
            }
            _ => {
                // Unconstrained - data may be fragmented (X.691 Section 11.9.3)
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

    /// Decode BIT STRING (X.691 Section 16)
    pub fn decode_bit_string(
        &mut self,
        min_len: Option<usize>,
        max_len: Option<usize>,
    ) -> PerResult<BitVec<u8, Msb0>> {
        let len = match (min_len, max_len) {
            (Some(min), Some(max)) if min == max => {
                if min > 16 {
                    self.align();
                }
                min
            }
            (Some(min), Some(max)) => {
                let len = self.decode_constrained_length(min, max)?;
                if max > 16 {
                    self.align();
                }
                len
            }
            _ => {
                // Unconstrained - data may be fragmented (X.691 Section 11.9.3)
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
}

/// Trait for types that can be encoded with APER
pub trait AperEncode {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()>;
}

/// Trait for types that can be decoded with APER
pub trait AperDecode: Sized {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_bits_needed() {
        assert_eq!(Constraint::new(0, 0).bits_needed(), 0);
        assert_eq!(Constraint::new(0, 1).bits_needed(), 1);
        assert_eq!(Constraint::new(0, 2).bits_needed(), 2);
        assert_eq!(Constraint::new(0, 3).bits_needed(), 2);
        assert_eq!(Constraint::new(0, 7).bits_needed(), 3);
        assert_eq!(Constraint::new(0, 255).bits_needed(), 8);
    }

    #[test]
    fn test_encode_decode_constrained() {
        let constraint = Constraint::new(0, 2);

        for value in 0..=2 {
            let mut encoder = AperEncoder::new();
            encoder
                .encode_constrained_whole_number(value, &constraint)
                .unwrap();
            encoder.align();

            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = decoder
                .decode_constrained_whole_number(&constraint)
                .unwrap();

            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_encode_decode_length() {
        for len in [0, 1, 127, 128, 255, 1000, 16383] {
            let mut encoder = AperEncoder::new();
            encoder.encode_length_determinant(len).unwrap();

            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = decoder.decode_length_determinant().unwrap();

            assert_eq!(len, decoded);
        }
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let data = vec![0x01, 0x02, 0x03, 0x04];

        let mut encoder = AperEncoder::new();
        encoder.encode_octet_string(&data, None, None).unwrap();

        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = decoder.decode_octet_string(None, None).unwrap();

        assert_eq!(data, decoded);
    }

    #[test]
    fn test_constrained_over_64k_byte_layout() {
        // AMF-UE-NGAP-ID constraint: INTEGER (0..2^40-1), X.691 Section 13.2.6
        let constraint = Constraint::new(0, 1099511627775);

        // Small value: 1 octet, length-of-length offset 0 (3 bits) + align
        let mut encoder = AperEncoder::new();
        encoder
            .encode_constrained_whole_number(1, &constraint)
            .unwrap();
        assert_eq!(encoder.into_bytes().as_ref(), &[0x00, 0x01]);

        // 40-bit value with top bit set: 5 octets, offset 4 (0b100) + align
        let mut encoder = AperEncoder::new();
        encoder
            .encode_constrained_whole_number(0x80_0000_0000, &constraint)
            .unwrap();
        assert_eq!(
            encoder.into_bytes().as_ref(),
            &[0x80, 0x80, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_constrained_over_64k_roundtrip() {
        let constraint = Constraint::new(0, 1099511627775);
        for value in [0, 1, 255, 65536, 0x80_0000_0000, 1099511627775] {
            let mut encoder = AperEncoder::new();
            encoder
                .encode_constrained_whole_number(value, &constraint)
                .unwrap();
            encoder.align();

            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = decoder
                .decode_constrained_whole_number(&constraint)
                .unwrap();

            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_length_determinant_over_16383_rejected() {
        let mut encoder = AperEncoder::new();
        let result = encoder.encode_length_determinant(16384);
        assert_eq!(result, Err(PerError::InvalidLength { length: 16384 }));
    }

    #[test]
    fn test_fragmented_octet_string_roundtrip() {
        // Spans: long-form boundary, single 16K fragment with zero terminator,
        // fragment + remainder, and a 4x16K fragment + remainder
        for len in [16383usize, 16384, 20000, 70000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();

            let mut encoder = AperEncoder::new();
            encoder.encode_octet_string(&data, None, None).unwrap();

            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            let decoded = decoder.decode_octet_string(None, None).unwrap();

            assert_eq!(data, decoded);
        }
    }

    #[test]
    fn test_fragmented_octet_string_wire_layout() {
        // 20000 octets: fragment header 0xC1 + 16384 octets of data,
        // then long-form length 3616 (0x8E 0x20) + the remaining octets
        let data = vec![0xAB; 20000];
        let mut encoder = AperEncoder::new();
        encoder.encode_octet_string(&data, None, None).unwrap();
        let bytes = encoder.into_bytes();

        assert_eq!(bytes.len(), 1 + 16384 + 2 + 3616);
        assert_eq!(bytes[0], 0xC1);
        assert_eq!(bytes[1], 0xAB);
        assert_eq!(bytes[1 + 16384], 0x8E);
        assert_eq!(bytes[1 + 16384 + 1], 0x20);
        assert_eq!(bytes[1 + 16384 + 2], 0xAB);

        // Exact 16K multiple terminates with a zero-length block
        let data = vec![0xCD; 16384];
        let mut encoder = AperEncoder::new();
        encoder.encode_octet_string(&data, None, None).unwrap();
        let bytes = encoder.into_bytes();
        assert_eq!(bytes.len(), 1 + 16384 + 1);
        assert_eq!(bytes[0], 0xC1);
        assert_eq!(bytes[bytes.len() - 1], 0x00);
    }

    #[test]
    fn test_malformed_decode_returns_err() {
        // Length fragment header with invalid multiplier 0
        let mut decoder = AperDecoder::new(&[0xC0]);
        assert!(decoder.decode_length_determinant().is_err());

        // Valid fragment header where a standalone determinant is required
        let mut decoder = AperDecoder::new(&[0xC1]);
        assert!(decoder.decode_length_determinant().is_err());

        // Unconstrained integer claiming more octets than an i64 can hold
        let mut decoder = AperDecoder::new(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(decoder.decode_unconstrained_whole_number().is_err());

        // Constrained offset outside the declared range
        let constraint = Constraint::new(0, 300);
        let mut decoder = AperDecoder::new(&[0xFF, 0xFF]);
        assert!(decoder.decode_constrained_whole_number(&constraint).is_err());
    }
}
