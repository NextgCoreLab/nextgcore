//! TLV (Type-Length-Value) encoding/decoding
//!
//! Exact port of lib/core/ogs-tlv.h and ogs-tlv.c
//!
//! This implementation supports multiple TLV modes:
//! - T1_L1: 1-byte type, 1-byte length
//! - T1_L2: 1-byte type, 2-byte length
//! - T1_L2_I1: 1-byte type, 2-byte length, 1-byte instance
//! - T2_L2: 2-byte type, 2-byte length
//! - T1: 1-byte type only (fixed length)

use thiserror::Error;

/// TLV encoding modes (identical to C defines)
pub const OGS_TLV_MODE_T1_L1: u8 = 1;
pub const OGS_TLV_MODE_T1_L2: u8 = 2;
pub const OGS_TLV_MODE_T1_L2_I1: u8 = 3;
pub const OGS_TLV_MODE_T2_L2: u8 = 4;
pub const OGS_TLV_MODE_T1: u8 = 5;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum TlvError {
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Invalid TLV format")]
    InvalidFormat,
    #[error("Unexpected end of data")]
    UnexpectedEnd,
    #[error("Invalid mode: {0}")]
    InvalidMode(u8),
}

/// TLV element (identical to ogs_tlv_t)
#[derive(Debug, Clone)]
pub struct OgsTlv {
    /// TLV mode
    pub mode: u8,
    /// Type field
    pub tlv_type: u32,
    /// Length field
    pub length: u32,
    /// Instance field (for T1_L2_I1 mode)
    pub instance: u8,
    /// Value data
    pub value: Vec<u8>,
    /// Embedded TLVs (for nested structures)
    pub embedded: Vec<OgsTlv>,
}

impl OgsTlv {
    /// Create a new TLV element
    pub fn new(mode: u8, tlv_type: u32, value: Vec<u8>) -> Self {
        OgsTlv {
            mode,
            tlv_type,
            length: value.len() as u32,
            instance: 0,
            value,
            embedded: Vec::new(),
        }
    }

    /// Create a new TLV element with instance
    pub fn with_instance(mode: u8, tlv_type: u32, instance: u8, value: Vec<u8>) -> Self {
        OgsTlv {
            mode,
            tlv_type,
            length: value.len() as u32,
            instance,
            value,
            embedded: Vec::new(),
        }
    }

    /// Get header size based on mode
    pub fn header_size(mode: u8) -> usize {
        match mode {
            OGS_TLV_MODE_T1_L1 => 2,      // 1 + 1
            OGS_TLV_MODE_T1_L2 => 3,      // 1 + 2
            OGS_TLV_MODE_T1_L2_I1 => 4,   // 1 + 2 + 1
            OGS_TLV_MODE_T2_L2 => 4,      // 2 + 2
            OGS_TLV_MODE_T1 => 1,         // 1 (no length)
            _ => 0,
        }
    }

    /// Encode TLV to bytes (identical to ogs_tlv_render)
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, TlvError> {
        let header_size = Self::header_size(self.mode);
        let total_len = header_size + self.value.len();
        
        if buf.len() < total_len {
            return Err(TlvError::BufferTooSmall);
        }

        let mut offset = 0;

        match self.mode {
            OGS_TLV_MODE_T1_L1 => {
                buf[offset] = self.tlv_type as u8;
                offset += 1;
                buf[offset] = self.length as u8;
                offset += 1;
            }
            OGS_TLV_MODE_T1_L2 => {
                buf[offset] = self.tlv_type as u8;
                offset += 1;
                buf[offset] = (self.length >> 8) as u8;
                buf[offset + 1] = self.length as u8;
                offset += 2;
            }
            OGS_TLV_MODE_T1_L2_I1 => {
                buf[offset] = self.tlv_type as u8;
                offset += 1;
                buf[offset] = (self.length >> 8) as u8;
                buf[offset + 1] = self.length as u8;
                offset += 2;
                buf[offset] = self.instance;
                offset += 1;
            }
            OGS_TLV_MODE_T2_L2 => {
                buf[offset] = (self.tlv_type >> 8) as u8;
                buf[offset + 1] = self.tlv_type as u8;
                offset += 2;
                buf[offset] = (self.length >> 8) as u8;
                buf[offset + 1] = self.length as u8;
                offset += 2;
            }
            OGS_TLV_MODE_T1 => {
                buf[offset] = self.tlv_type as u8;
                offset += 1;
            }
            _ => return Err(TlvError::InvalidMode(self.mode)),
        }

        buf[offset..offset + self.value.len()].copy_from_slice(&self.value);
        offset += self.value.len();

        Ok(offset)
    }

    /// Decode TLV from bytes (identical to ogs_tlv_parse_block)
    pub fn decode(buf: &[u8], mode: u8) -> Result<(Self, usize), TlvError> {
        let header_size = Self::header_size(mode);
        
        if buf.len() < header_size {
            return Err(TlvError::UnexpectedEnd);
        }

        let mut offset = 0;
        let tlv_type: u32;
        let length: u32;
        let instance: u8;

        match mode {
            OGS_TLV_MODE_T1_L1 => {
                tlv_type = buf[offset] as u32;
                offset += 1;
                length = buf[offset] as u32;
                offset += 1;
                instance = 0;
            }
            OGS_TLV_MODE_T1_L2 => {
                tlv_type = buf[offset] as u32;
                offset += 1;
                length = ((buf[offset] as u32) << 8) | (buf[offset + 1] as u32);
                offset += 2;
                instance = 0;
            }
            OGS_TLV_MODE_T1_L2_I1 => {
                tlv_type = buf[offset] as u32;
                offset += 1;
                length = ((buf[offset] as u32) << 8) | (buf[offset + 1] as u32);
                offset += 2;
                instance = buf[offset];
                offset += 1;
            }
            OGS_TLV_MODE_T2_L2 => {
                tlv_type = ((buf[offset] as u32) << 8) | (buf[offset + 1] as u32);
                offset += 2;
                length = ((buf[offset] as u32) << 8) | (buf[offset + 1] as u32);
                offset += 2;
                instance = 0;
            }
            OGS_TLV_MODE_T1 => {
                tlv_type = buf[offset] as u32;
                offset += 1;
                length = 0; // No length field
                instance = 0;
            }
            _ => return Err(TlvError::InvalidMode(mode)),
        }

        if buf.len() < offset + length as usize {
            return Err(TlvError::UnexpectedEnd);
        }

        let value = buf[offset..offset + length as usize].to_vec();
        let total_len = offset + length as usize;

        let tlv = OgsTlv {
            mode,
            tlv_type,
            length,
            instance,
            value,
            embedded: Vec::new(),
        };

        Ok((tlv, total_len))
    }

    /// Decode TLV with fixed length (for T1 mode)
    pub fn decode_fixed(buf: &[u8], mode: u8, fixed_length: u32) -> Result<(Self, usize), TlvError> {
        let header_size = Self::header_size(mode);
        
        if buf.len() < header_size + fixed_length as usize {
            return Err(TlvError::UnexpectedEnd);
        }

        let tlv_type = buf[0] as u32;
        let value = buf[1..1 + fixed_length as usize].to_vec();

        let tlv = OgsTlv {
            mode,
            tlv_type,
            length: fixed_length,
            instance: 0,
            value,
            embedded: Vec::new(),
        };

        Ok((tlv, 1 + fixed_length as usize))
    }

    /// Get encoded size
    pub fn encoded_size(&self) -> usize {
        Self::header_size(self.mode) + self.value.len()
    }

    /// Add embedded TLV
    pub fn add_embedded(&mut self, tlv: OgsTlv) {
        self.embedded.push(tlv);
    }

    /// Get value as u8
    pub fn value_u8(&self) -> u8 {
        if self.value.is_empty() {
            0
        } else {
            self.value[0]
        }
    }

    /// Get value as u16 (big-endian)
    pub fn value_u16(&self) -> u16 {
        if self.value.len() < 2 {
            0
        } else {
            ((self.value[0] as u16) << 8) | (self.value[1] as u16)
        }
    }

    /// Get value as u32 (big-endian)
    pub fn value_u32(&self) -> u32 {
        if self.value.len() < 4 {
            0
        } else {
            ((self.value[0] as u32) << 24)
                | ((self.value[1] as u32) << 16)
                | ((self.value[2] as u32) << 8)
                | (self.value[3] as u32)
        }
    }
}

impl Default for OgsTlv {
    fn default() -> Self {
        OgsTlv {
            mode: OGS_TLV_MODE_T2_L2,
            tlv_type: 0,
            length: 0,
            instance: 0,
            value: Vec::new(),
            embedded: Vec::new(),
        }
    }
}

/// TLV message containing multiple TLV elements
#[derive(Debug, Clone, Default)]
pub struct OgsTlvMsg {
    /// TLV mode for this message
    pub mode: u8,
    /// TLV elements
    pub elements: Vec<OgsTlv>,
}

impl OgsTlvMsg {
    /// Create a new TLV message with specified mode
    pub fn new(mode: u8) -> Self {
        OgsTlvMsg {
            mode,
            elements: Vec::new(),
        }
    }

    /// Add a TLV element
    pub fn add(&mut self, tlv_type: u32, value: Vec<u8>) {
        self.elements.push(OgsTlv::new(self.mode, tlv_type, value));
    }

    /// Add a TLV element with instance
    pub fn add_with_instance(&mut self, tlv_type: u32, instance: u8, value: Vec<u8>) {
        self.elements.push(OgsTlv::with_instance(self.mode, tlv_type, instance, value));
    }

    /// Encode all TLV elements (identical to ogs_tlv_render)
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, TlvError> {
        let mut offset = 0;
        for tlv in &self.elements {
            let len = tlv.encode(&mut buf[offset..])?;
            offset += len;
        }
        Ok(offset)
    }

    /// Decode TLV elements from buffer (identical to ogs_tlv_parse_block)
    pub fn decode(buf: &[u8], mode: u8) -> Result<Self, TlvError> {
        let mut msg = OgsTlvMsg::new(mode);
        let mut offset = 0;

        while offset < buf.len() {
            let (tlv, len) = OgsTlv::decode(&buf[offset..], mode)?;
            msg.elements.push(tlv);
            offset += len;
        }

        Ok(msg)
    }

    /// Find element by type (identical to ogs_tlv_find)
    pub fn find(&self, tlv_type: u32) -> Option<&OgsTlv> {
        self.elements.iter().find(|e| e.tlv_type == tlv_type)
    }

    /// Find element by type and instance
    pub fn find_with_instance(&self, tlv_type: u32, instance: u8) -> Option<&OgsTlv> {
        self.elements.iter().find(|e| e.tlv_type == tlv_type && e.instance == instance)
    }

    /// Get total encoded size (identical to ogs_tlv_calc_length)
    pub fn encoded_size(&self) -> usize {
        self.elements.iter().map(|e| e.encoded_size()).sum()
    }

    /// Get element count (identical to ogs_tlv_calc_count)
    pub fn count(&self) -> usize {
        self.elements.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_t1_l1() {
        let tlv = OgsTlv::new(OGS_TLV_MODE_T1_L1, 0x42, vec![1, 2, 3, 4]);
        
        let mut buf = [0u8; 100];
        let len = tlv.encode(&mut buf).unwrap();
        
        assert_eq!(len, 6); // 1 + 1 + 4
        assert_eq!(buf[0], 0x42); // type
        assert_eq!(buf[1], 4);    // length
        assert_eq!(&buf[2..6], &[1, 2, 3, 4]); // value
        
        let (decoded, decoded_len) = OgsTlv::decode(&buf[..len], OGS_TLV_MODE_T1_L1).unwrap();
        assert_eq!(decoded_len, len);
        assert_eq!(decoded.tlv_type, 0x42);
        assert_eq!(decoded.length, 4);
        assert_eq!(decoded.value, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_tlv_t1_l2() {
        let tlv = OgsTlv::new(OGS_TLV_MODE_T1_L2, 0x42, vec![1, 2, 3, 4]);
        
        let mut buf = [0u8; 100];
        let len = tlv.encode(&mut buf).unwrap();
        
        assert_eq!(len, 7); // 1 + 2 + 4
        assert_eq!(buf[0], 0x42); // type
        assert_eq!(buf[1], 0);    // length high
        assert_eq!(buf[2], 4);    // length low
        
        let (decoded, _) = OgsTlv::decode(&buf[..len], OGS_TLV_MODE_T1_L2).unwrap();
        assert_eq!(decoded.tlv_type, 0x42);
        assert_eq!(decoded.length, 4);
    }

    #[test]
    fn test_tlv_t1_l2_i1() {
        let tlv = OgsTlv::with_instance(OGS_TLV_MODE_T1_L2_I1, 0x42, 0x03, vec![1, 2, 3, 4]);
        
        let mut buf = [0u8; 100];
        let len = tlv.encode(&mut buf).unwrap();
        
        assert_eq!(len, 8); // 1 + 2 + 1 + 4
        assert_eq!(buf[0], 0x42); // type
        assert_eq!(buf[3], 0x03); // instance
        
        let (decoded, _) = OgsTlv::decode(&buf[..len], OGS_TLV_MODE_T1_L2_I1).unwrap();
        assert_eq!(decoded.tlv_type, 0x42);
        assert_eq!(decoded.instance, 0x03);
    }

    #[test]
    fn test_tlv_t2_l2() {
        let tlv = OgsTlv::new(OGS_TLV_MODE_T2_L2, 0x1234, vec![1, 2, 3, 4]);
        
        let mut buf = [0u8; 100];
        let len = tlv.encode(&mut buf).unwrap();
        
        assert_eq!(len, 8); // 2 + 2 + 4
        assert_eq!(buf[0], 0x12); // type high
        assert_eq!(buf[1], 0x34); // type low
        
        let (decoded, _) = OgsTlv::decode(&buf[..len], OGS_TLV_MODE_T2_L2).unwrap();
        assert_eq!(decoded.tlv_type, 0x1234);
    }

    #[test]
    fn test_tlv_msg() {
        let mut msg = OgsTlvMsg::new(OGS_TLV_MODE_T1_L1);
        msg.add(0x01, vec![1, 2]);
        msg.add(0x02, vec![3, 4, 5]);
        msg.add(0x03, vec![6]);
        
        assert_eq!(msg.count(), 3);
        
        let mut buf = [0u8; 100];
        let len = msg.encode(&mut buf).unwrap();
        
        let decoded = OgsTlvMsg::decode(&buf[..len], OGS_TLV_MODE_T1_L1).unwrap();
        assert_eq!(decoded.count(), 3);
        
        let elem = decoded.find(0x02).unwrap();
        assert_eq!(elem.value, vec![3, 4, 5]);
    }

    #[test]
    fn test_tlv_value_helpers() {
        let tlv = OgsTlv::new(OGS_TLV_MODE_T1_L1, 0x01, vec![0x12, 0x34, 0x56, 0x78]);
        
        assert_eq!(tlv.value_u8(), 0x12);
        assert_eq!(tlv.value_u16(), 0x1234);
        assert_eq!(tlv.value_u32(), 0x12345678);
    }

    #[test]
    fn test_tlv_round_trip() {
        let modes = [
            OGS_TLV_MODE_T1_L1,
            OGS_TLV_MODE_T1_L2,
            OGS_TLV_MODE_T1_L2_I1,
            OGS_TLV_MODE_T2_L2,
        ];
        
        for mode in modes {
            let original = OgsTlv::with_instance(mode, 0x42, 0x05, vec![1, 2, 3, 4, 5]);
            
            let mut buf = [0u8; 100];
            let len = original.encode(&mut buf).unwrap();
            
            let (decoded, decoded_len) = OgsTlv::decode(&buf[..len], mode).unwrap();
            
            assert_eq!(decoded_len, len);
            assert_eq!(decoded.tlv_type, original.tlv_type);
            assert_eq!(decoded.length, original.length);
            assert_eq!(decoded.value, original.value);
            
            if mode == OGS_TLV_MODE_T1_L2_I1 {
                assert_eq!(decoded.instance, original.instance);
            }
        }
    }

    #[test]
    fn test_tlv_buffer_too_small() {
        let tlv = OgsTlv::new(OGS_TLV_MODE_T1_L1, 0x42, vec![1, 2, 3, 4]);
        
        let mut buf = [0u8; 3]; // Too small
        let result = tlv.encode(&mut buf);
        
        assert!(matches!(result, Err(TlvError::BufferTooSmall)));
    }

    #[test]
    fn test_tlv_unexpected_end() {
        let buf = [0x42, 0x10]; // Type and length, but no value
        let result = OgsTlv::decode(&buf, OGS_TLV_MODE_T1_L1);
        
        assert!(matches!(result, Err(TlvError::UnexpectedEnd)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating valid TLV modes
    fn tlv_mode_strategy() -> impl Strategy<Value = u8> {
        prop_oneof![
            Just(OGS_TLV_MODE_T1_L1),
            Just(OGS_TLV_MODE_T1_L2),
            Just(OGS_TLV_MODE_T1_L2_I1),
            Just(OGS_TLV_MODE_T2_L2),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property 1: TLV round-trip encoding/decoding preserves data
        #[test]
        fn prop_tlv_round_trip(
            mode in tlv_mode_strategy(),
            tlv_type in 0u32..=65535u32,
            instance in 0u8..=15u8,
            value_len in 0usize..=255usize,
            seed in any::<u64>()
        ) {
            // Constrain type based on mode
            let actual_type = match mode {
                OGS_TLV_MODE_T1_L1 | OGS_TLV_MODE_T1_L2 | OGS_TLV_MODE_T1_L2_I1 => tlv_type & 0xFF,
                OGS_TLV_MODE_T2_L2 => tlv_type & 0xFFFF,
                _ => tlv_type,
            };

            // Constrain length based on mode
            let actual_len = match mode {
                OGS_TLV_MODE_T1_L1 => value_len.min(255),
                _ => value_len,
            };

            // Generate deterministic value data
            let value: Vec<u8> = (0..actual_len)
                .map(|i| ((seed.wrapping_add(i as u64)) & 0xFF) as u8)
                .collect();

            let original = OgsTlv::with_instance(mode, actual_type, instance, value.clone());

            let mut buf = vec![0u8; original.encoded_size() + 10];
            let encoded_len = original.encode(&mut buf).unwrap();

            let (decoded, decoded_len) = OgsTlv::decode(&buf[..encoded_len], mode).unwrap();

            prop_assert_eq!(decoded_len, encoded_len);
            prop_assert_eq!(decoded.tlv_type, actual_type);
            prop_assert_eq!(decoded.length, actual_len as u32);
            prop_assert_eq!(decoded.value, value);

            if mode == OGS_TLV_MODE_T1_L2_I1 {
                prop_assert_eq!(decoded.instance, instance);
            }
        }

        /// Property 2: Encoded size matches actual encoding
        #[test]
        fn prop_encoded_size_accurate(
            mode in tlv_mode_strategy(),
            value_len in 0usize..=100usize,
            seed in any::<u64>()
        ) {
            let value: Vec<u8> = (0..value_len)
                .map(|i| ((seed.wrapping_add(i as u64)) & 0xFF) as u8)
                .collect();

            let tlv = OgsTlv::new(mode, 0x42, value);
            let predicted_size = tlv.encoded_size();

            let mut buf = vec![0u8; predicted_size + 10];
            let actual_size = tlv.encode(&mut buf).unwrap();

            prop_assert_eq!(predicted_size, actual_size);
        }

        /// Property 3: Header size is correct for each mode
        #[test]
        fn prop_header_size_correct(mode in tlv_mode_strategy()) {
            let expected = match mode {
                OGS_TLV_MODE_T1_L1 => 2,
                OGS_TLV_MODE_T1_L2 => 3,
                OGS_TLV_MODE_T1_L2_I1 => 4,
                OGS_TLV_MODE_T2_L2 => 4,
                OGS_TLV_MODE_T1 => 1,
                _ => 0,
            };
            prop_assert_eq!(OgsTlv::header_size(mode), expected);
        }

        /// Property 4: TLV message round-trip preserves all elements
        #[test]
        fn prop_tlv_msg_round_trip(
            mode in tlv_mode_strategy(),
            num_elements in 1usize..=10usize,
            seed in any::<u64>()
        ) {
            let mut msg = OgsTlvMsg::new(mode);

            for i in 0..num_elements {
                let tlv_type = match mode {
                    OGS_TLV_MODE_T2_L2 => (i as u32 + 1) * 0x100,
                    _ => (i as u32 + 1) & 0xFF,
                };
                let value: Vec<u8> = (0..((i + 1) * 3))
                    .map(|j| ((seed.wrapping_add(j as u64).wrapping_add(i as u64)) & 0xFF) as u8)
                    .collect();
                msg.add(tlv_type, value);
            }

            let mut buf = vec![0u8; msg.encoded_size() + 10];
            let encoded_len = msg.encode(&mut buf).unwrap();

            let decoded = OgsTlvMsg::decode(&buf[..encoded_len], mode).unwrap();

            prop_assert_eq!(decoded.count(), num_elements);

            for (orig, dec) in msg.elements.iter().zip(decoded.elements.iter()) {
                prop_assert_eq!(orig.tlv_type, dec.tlv_type);
                prop_assert_eq!(orig.length, dec.length);
                prop_assert_eq!(&orig.value, &dec.value);
            }
        }

        /// Property 5: Find operation returns correct element
        #[test]
        fn prop_find_returns_correct_element(
            mode in tlv_mode_strategy(),
            num_elements in 1usize..=10usize,
            target_idx in 0usize..10usize,
            seed in any::<u64>()
        ) {
            let mut msg = OgsTlvMsg::new(mode);

            for i in 0..num_elements {
                let tlv_type = match mode {
                    OGS_TLV_MODE_T2_L2 => (i as u32 + 1) * 0x100,
                    _ => (i as u32 + 1) & 0xFF,
                };
                let value: Vec<u8> = (0..((i + 1) * 2))
                    .map(|j| ((seed.wrapping_add(j as u64).wrapping_add(i as u64)) & 0xFF) as u8)
                    .collect();
                msg.add(tlv_type, value);
            }

            let actual_idx = target_idx % num_elements;
            let target_type = match mode {
                OGS_TLV_MODE_T2_L2 => (actual_idx as u32 + 1) * 0x100,
                _ => (actual_idx as u32 + 1) & 0xFF,
            };

            let found = msg.find(target_type);
            prop_assert!(found.is_some());
            prop_assert_eq!(found.unwrap().tlv_type, target_type);
        }

        /// Property 6: Buffer too small error is returned correctly
        #[test]
        fn prop_buffer_too_small_error(
            mode in tlv_mode_strategy(),
            value_len in 1usize..=50usize,
            seed in any::<u64>()
        ) {
            let value: Vec<u8> = (0..value_len)
                .map(|i| ((seed.wrapping_add(i as u64)) & 0xFF) as u8)
                .collect();

            let tlv = OgsTlv::new(mode, 0x42, value);
            let required_size = tlv.encoded_size();

            // Try with buffer that's too small
            let mut small_buf = vec![0u8; required_size - 1];
            let result = tlv.encode(&mut small_buf);

            prop_assert!(matches!(result, Err(TlvError::BufferTooSmall)));
        }

        /// Property 7: Value helper functions return correct values
        #[test]
        fn prop_value_helpers_correct(
            b0 in any::<u8>(),
            b1 in any::<u8>(),
            b2 in any::<u8>(),
            b3 in any::<u8>()
        ) {
            let tlv = OgsTlv::new(OGS_TLV_MODE_T1_L1, 0x01, vec![b0, b1, b2, b3]);

            prop_assert_eq!(tlv.value_u8(), b0);
            prop_assert_eq!(tlv.value_u16(), ((b0 as u16) << 8) | (b1 as u16));
            prop_assert_eq!(
                tlv.value_u32(),
                ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
            );
        }

        /// Property 8: Empty value TLV round-trips correctly
        #[test]
        fn prop_empty_value_round_trip(mode in tlv_mode_strategy()) {
            let tlv = OgsTlv::new(mode, 0x42, vec![]);

            let mut buf = vec![0u8; tlv.encoded_size() + 10];
            let encoded_len = tlv.encode(&mut buf).unwrap();

            let (decoded, decoded_len) = OgsTlv::decode(&buf[..encoded_len], mode).unwrap();

            prop_assert_eq!(decoded_len, encoded_len);
            prop_assert_eq!(decoded.tlv_type, 0x42);
            prop_assert_eq!(decoded.length, 0);
            prop_assert!(decoded.value.is_empty());
        }

        /// Property 9: Message encoded size equals sum of element sizes
        #[test]
        fn prop_msg_encoded_size_is_sum(
            mode in tlv_mode_strategy(),
            num_elements in 1usize..=5usize,
            seed in any::<u64>()
        ) {
            let mut msg = OgsTlvMsg::new(mode);

            for i in 0..num_elements {
                let tlv_type = match mode {
                    OGS_TLV_MODE_T2_L2 => (i as u32 + 1) * 0x100,
                    _ => (i as u32 + 1) & 0xFF,
                };
                let value: Vec<u8> = (0..((i + 1) * 2))
                    .map(|j| ((seed.wrapping_add(j as u64)) & 0xFF) as u8)
                    .collect();
                msg.add(tlv_type, value);
            }

            let sum_of_sizes: usize = msg.elements.iter().map(|e| e.encoded_size()).sum();
            prop_assert_eq!(msg.encoded_size(), sum_of_sizes);
        }
    }
}
