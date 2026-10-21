//! Bounds-checked reads for the NAS decoders (#595).
//!
//! NAS arrives from the UE, so every decoder must treat its input as hostile.
//! The `bytes::Buf` getters (`get_u8`, `advance`, `copy_to_slice`, ...) panic on
//! a short buffer, and a panic in the decoding task lets a single UE take the
//! AMF/MME down. Decoders use these methods instead: each checks `remaining()`
//! first and returns [`NasError::BufferTooShort`].

use crate::error::{NasError, NasResult};
use bytes::{Buf, Bytes};

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

    /// Discard exactly `n` bytes.
    #[inline]
    fn skip(&mut self, n: usize) -> NasResult<()> {
        self.need(n)?;
        self.advance(n);
        Ok(())
    }
}

impl<B: Buf + ?Sized> NasBuf for B {}

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
