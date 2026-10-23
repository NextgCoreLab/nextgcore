//! Bounds-checked reads for the NAS decoders (#595).
//!
//! NAS arrives from the UE, so every decoder must treat its input as hostile.
//! The `bytes::Buf` getters (`get_u8`, `advance`, `copy_to_slice`, ...) panic on
//! a short buffer, and a panic in the decoding task lets a single UE take the
//! AMF/MME down. Decoders use these methods instead: each checks `remaining()`
//! first and returns [`NasError::BufferTooShort`].

use crate::error::{NasError, NasResult};
use bytes::{Buf, Bytes};

/// The declared-length rule of a fixed-layout IE (#613).
///
/// A length below the IE's minimum makes it syntactically incorrect, and the
/// decoder must not borrow octets of the next IE to fill its fields (TS 24.501
/// §7.5 / §7.7.1, TS 24.301 §7.5 / §7.7.1). Whether octets beyond the known
/// fields are an error depends on the IE's own definition, so each call site
/// cites the clause that picks the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IeLen {
    /// The definition fixes the length ("a length of N octets"). Any other
    /// declared length is an erroneous IE.
    Exact(usize),
    /// The definition gives a minimum and marks the octets after it optional or
    /// spare, so later releases may add fields. Octets beyond the known ones are
    /// skipped inside the IE, never read as the next IE.
    AtLeast(usize),
    /// The definition bounds the value part on both sides (e.g. RES is 4 to 16
    /// octets) and nothing may follow it.
    Between(usize, usize),
}

impl IeLen {
    /// Check a declared value-part length against the rule.
    pub(crate) fn check(self, len: usize) -> NasResult<()> {
        let bad = |expected| {
            Err(NasError::InvalidIeLength {
                expected,
                actual: len,
            })
        };
        match self {
            Self::Exact(n) if len != n => bad(n),
            Self::AtLeast(n) if len < n => bad(n),
            Self::Between(min, _) if len < min => bad(min),
            Self::Between(_, max) if len > max => bad(max),
            _ => Ok(()),
        }
    }
}

/// Bounds-checked counterparts of the `bytes::Buf` getters.
pub(crate) trait NasBuf: Buf {
    /// Fail unless at least `n` bytes remain.
    #[inline]
    fn need(&self, n: usize) -> NasResult<()> {
        if self.remaining() < n {
            return Err(NasError::BufferTooShort {
                expected: n,
                actual: self.remaining(),
            });
        }
        Ok(())
    }

    /// Next byte, without consuming it.
    #[inline]
    fn peek_u8(&self) -> NasResult<u8> {
        self.need(1)?;
        Ok(self.chunk()[0])
    }

    #[inline]
    fn read_u8(&mut self) -> NasResult<u8> {
        self.need(1)?;
        Ok(self.get_u8())
    }

    #[inline]
    fn read_u16(&mut self) -> NasResult<u16> {
        self.need(2)?;
        Ok(self.get_u16())
    }

    #[inline]
    fn read_u16_le(&mut self) -> NasResult<u16> {
        self.need(2)?;
        Ok(self.get_u16_le())
    }

    #[inline]
    fn read_u32(&mut self) -> NasResult<u32> {
        self.need(4)?;
        Ok(self.get_u32())
    }

    #[inline]
    fn read_u64(&mut self) -> NasResult<u64> {
        self.need(8)?;
        Ok(self.get_u64())
    }

    /// Fill `dst` completely.
    #[inline]
    fn read_into(&mut self, dst: &mut [u8]) -> NasResult<()> {
        self.need(dst.len())?;
        self.copy_to_slice(dst);
        Ok(())
    }

    /// Read exactly `n` bytes.
    #[inline]
    fn read_bytes(&mut self, n: usize) -> NasResult<Bytes> {
        self.need(n)?;
        Ok(self.copy_to_bytes(n))
    }

    /// Read an LV value part (1-octet length): check the declared length
    /// against `rule`, then return exactly that many octets. The caller decodes
    /// its fields inside the returned buffer, so the IE consumes its own length
    /// and no more, whatever the fields need.
    #[inline]
    fn read_lv(&mut self, rule: IeLen) -> NasResult<Bytes> {
        let len = self.read_u8()? as usize;
        rule.check(len)?;
        self.read_bytes(len)
    }

    /// [`read_lv`](Self::read_lv) for an LV-E value part (2-octet length).
    #[inline]
    fn read_lv_e(&mut self, rule: IeLen) -> NasResult<Bytes> {
        let len = self.read_u16()? as usize;
        rule.check(len)?;
        self.read_bytes(len)
    }

    /// Discard exactly `n` bytes.
    #[inline]
    fn skip(&mut self, n: usize) -> NasResult<()> {
        self.need(n)?;
        self.advance(n);
        Ok(())
    }
}

impl<B: Buf + ?Sized> NasBuf for B {}

/// Decode an optional type 4 IE (TLV, 1-octet length) per TS 24.501 §7.7.1 /
/// TS 24.301 §7.7.1: "The UE shall treat all optional IEs that are
/// syntactically incorrect in a message as not present in the message. The
/// network shall take the same approach." (#630)
///
/// `buf` is positioned after the IEI, at the length octet. The IE is framed by
/// its own length and `decode` runs on exactly that frame (length octet
/// included, as the IE decoders expect). Any error inside the frame makes the
/// IE absent (`None`), and the walk continues after it. A frame that runs past
/// the message is still an error: the message is truncated, not the IE.
pub(crate) fn optional_tlv<T>(
    buf: &mut Bytes,
    decode: impl FnOnce(&mut Bytes) -> NasResult<T>,
) -> NasResult<Option<T>> {
    let len = buf.peek_u8()? as usize;
    optional_framed(buf, 1 + len, decode)
}

/// [`optional_tlv`] for a type 6 IE (TLV-E, 2-octet length).
pub(crate) fn optional_tlv_e<T>(
    buf: &mut Bytes,
    decode: impl FnOnce(&mut Bytes) -> NasResult<T>,
) -> NasResult<Option<T>> {
    buf.need(2)?;
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    optional_framed(buf, 2 + len, decode)
}

fn optional_framed<T>(
    buf: &mut Bytes,
    frame_len: usize,
    decode: impl FnOnce(&mut Bytes) -> NasResult<T>,
) -> NasResult<Option<T>> {
    let mut frame = buf.read_bytes(frame_len)?;
    match decode(&mut frame) {
        Ok(ie) => Ok(Some(ie)),
        Err(e) => {
            log::debug!(
                "NAS: optional IE of {frame_len} octets is syntactically incorrect ({e}); \
                 treated as not present (TS 24.501/24.301 §7.7.1)"
            );
            Ok(None)
        }
    }
}

/// Store a decoded optional IE only if the message has not already got one:
/// "the UE shall handle only the contents of the information element
/// appearing first and shall ignore all subsequent repetitions" (TS 24.501 /
/// TS 24.301 §7.6.3; "the network should follow the same procedures").
///
/// A first instance that was syntactically incorrect is not present
/// (§7.7.1), so a later well-formed repetition is then the first one present.
pub(crate) fn set_first<T>(slot: &mut Option<T>, ie: Option<T>) {
    if slot.is_none() {
        *slot = ie;
    }
}

/// Returns true if `iei` denotes a type-6 (TLV-E) IE in the 5GS/EPS NAS
/// protocols, i.e. one whose length field is 2 octets rather than 1
/// (TS 24.007 §11.2.5).
///
/// The whole 0x70..=0x7F band. Every optional IE with an IEI there in the
/// TS 24.501 and TS 24.301 clause 8 tables is TLV-E, and none is TLV: EPS NAS
/// message container / Requested MBS container (0x70), NAS message container
/// (0x71), Service-level-AA container (0x72), SOR transparent container
/// (0x73), ciphering key data (0x74), CAG information list (0x75),
/// operator-defined access category definitions (0x76), Additional GUTI
/// (0x77), EAP message / ESM message container (0x78), LADN information
/// (0x79), extended emergency number list (0x7A), Payload container /
/// Extended PCO (0x7B), mapped EPS bearer contexts / ciphering key data
/// (0x7C) and 0x7D. Consuming the right number of length octets keeps the
/// walk in sync when such an IE is not modelled. Before #784 review the list
/// missed 0x70 and 0x72, which UEs send in REGISTRATION REQUEST.
pub(crate) fn is_tlv_e_iei(iei: u8) -> bool {
    (0x70..=0x7F).contains(&iei)
}

/// Skip an unknown / unhandled optional IE in a default IE-loop arm, per
/// TS 24.501 / TS 24.301 §7.6.1 (unknown IEs are ignored, not errored) and the
/// TS 24.007 IE-format rules. `buf` must be positioned at the IEI octet; `iei`
/// is the peeked IEI (`buf.peek_u8()?`).
///
/// - `iei >= 0x80`: type-1 (TV, half-octet IEI in the high nibble) or type-2
///   (T): the whole IE is the single IEI octet.
/// - TLV-E ([`is_tlv_e_iei`]): the IEI octet, a 2-octet length, the value.
/// - other `iei < 0x80`: type-4 (TLV): the IEI octet, a 1-octet length, the
///   value. Unknown type-3 (fixed-length TV) IEs cannot be told apart, but all
///   *known* ones are matched explicitly, so this only affects unknown ones.
///
/// An unknown IE whose length (or its length octets) runs past the message
/// ends the walk: the rest of the message is consumed and the IE is treated as
/// not present (§7.6.1 ignores unknown IEs; §7.7.1 treats a syntactically
/// incorrect optional one as absent). It does not fail the message, because an
/// unknown IE's format is a guess: an unmodelled type 3 (TV) IE read as TLV
/// overruns on perfectly valid input (#784 review). Known IEs that overrun
/// (`optional_tlv`, `opaque_tlv`) remain an error.
pub(crate) fn skip_unknown_ie(buf: &mut Bytes, iei: u8) -> NasResult<()> {
    buf.skip(1)?; // consume the IEI octet (peeked, not yet advanced by caller)
    if iei >= 0x80 {
        return Ok(());
    }
    let len = if is_tlv_e_iei(iei) {
        if buf.remaining() < 2 {
            buf.advance(buf.remaining());
            return Ok(());
        }
        buf.read_u16()? as usize
    } else {
        if buf.remaining() < 1 {
            return Ok(());
        }
        buf.read_u8()? as usize
    };
    if len > buf.remaining() {
        log::debug!(
            "NAS: unknown IE {iei:#04x} declares {len} octets with {} left; \
             treated as not present and the walk ends",
            buf.remaining()
        );
        buf.advance(buf.remaining());
        return Ok(());
    }
    buf.skip(len)
}

/// Read the length and value of an opaque type 4 IE (TLV; the IEI already
/// consumed). The value is kept as octets, so the only syntax error is a
/// length past the message, which is `BufferTooShort` (#784). Before #784 the
/// inline arms skipped such an IE without advancing, so the walk re-read its
/// value octets as IEIs.
pub(crate) fn opaque_tlv(buf: &mut Bytes) -> NasResult<Vec<u8>> {
    let len = buf.read_u8()? as usize;
    Ok(buf.read_bytes(len)?.to_vec())
}

/// [`opaque_tlv`] for a type 6 IE (TLV-E, 2-octet length).
pub(crate) fn opaque_tlv_e(buf: &mut Bytes) -> NasResult<Vec<u8>> {
    let len = buf.read_u16()? as usize;
    Ok(buf.read_bytes(len)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_reads_are_errors_not_panics() {
        let mut b = Bytes::from_static(&[1]);
        assert!(b.read_u16().is_err());
        assert_eq!(b.peek_u8().unwrap(), 1);
        assert_eq!(b.read_u8().unwrap(), 1);
        assert!(b.read_u8().is_err());
        assert!(b.peek_u8().is_err());
        assert!(b.skip(1).is_err());
        assert!(b.read_bytes(1).is_err());
        assert!(b.read_into(&mut [0u8; 1]).is_err());
        assert!(b.read_u32().is_err());
        assert!(b.read_u64().is_err());
        assert!(b.skip(0).is_ok());
    }
}
