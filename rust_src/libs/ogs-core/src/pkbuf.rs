//! Packet buffer implementation
//!
//! Exact port of lib/core/ogs-pkbuf.h and ogs-pkbuf.c
//!
//! This implementation provides a packet buffer with:
//! - Headroom for prepending headers
//! - Tailroom for appending data
//! - Reserve, put, push, pull, trim operations

use std::sync::Arc;

/// Cluster sizes matching C implementation
pub const CLUSTER_128: usize = 128;
pub const CLUSTER_256: usize = 256;
pub const CLUSTER_512: usize = 512;
pub const CLUSTER_1024: usize = 1024;
pub const CLUSTER_2048: usize = 2048;
pub const CLUSTER_8192: usize = 8192;
pub const CLUSTER_32768: usize = 32768;

/// Cluster - shared buffer storage (identical to ogs_cluster_t)
#[derive(Debug)]
struct OgsCluster {
    buffer: Vec<u8>,
    size: usize,
}

impl OgsCluster {
    fn new(size: usize) -> Self {
        OgsCluster {
            buffer: vec![0u8; size],
            size,
        }
    }
}

/// Packet buffer for network data (identical to ogs_pkbuf_t)
/// 
/// Memory layout:
/// ```text
/// |<-- headroom -->|<-- data (len) -->|<-- tailroom -->|
/// head             data               tail             end
/// ```
pub struct OgsPkbuf {
    /// Shared cluster storage
    cluster: Arc<OgsCluster>,
    /// Length of valid data
    len: usize,
    /// Start of buffer (head pointer)
    head: usize,
    /// End of buffer (end pointer)
    end: usize,
    /// Start of data (data pointer)
    data: usize,
    /// End of data (tail pointer)
    tail: usize,
    /// Optional parameters (used for SCTP stream number and PPID)
    pub param: [u64; 2],
}

impl OgsPkbuf {
    /// Create a new packet buffer with given capacity (identical to ogs_pkbuf_alloc)
    pub fn new(size: usize) -> Self {
        let cluster_size = Self::select_cluster_size(size);
        let cluster = Arc::new(OgsCluster::new(cluster_size));
        
        OgsPkbuf {
            cluster,
            len: 0,
            head: 0,
            end: cluster_size,
            data: 0,
            tail: 0,
            param: [0, 0],
        }
    }

    /// Select appropriate cluster size for requested size
    fn select_cluster_size(size: usize) -> usize {
        if size <= CLUSTER_128 {
            CLUSTER_128
        } else if size <= CLUSTER_256 {
            CLUSTER_256
        } else if size <= CLUSTER_512 {
            CLUSTER_512
        } else if size <= CLUSTER_1024 {
            CLUSTER_1024
        } else if size <= CLUSTER_2048 {
            CLUSTER_2048
        } else if size <= CLUSTER_8192 {
            CLUSTER_8192
        } else if size <= CLUSTER_32768 {
            CLUSTER_32768
        } else {
            // Round up to next power of 2 for big clusters
            size.next_power_of_two()
        }
    }

    /// Get tailroom (identical to ogs_pkbuf_tailroom)
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.end - self.tail
    }

    /// Get headroom (identical to ogs_pkbuf_headroom)
    #[inline]
    pub fn headroom(&self) -> usize {
        self.data - self.head
    }

    /// Reserve headroom (identical to ogs_pkbuf_reserve)
    /// Must be called before any data is added
    #[inline]
    pub fn reserve(&mut self, len: usize) {
        debug_assert!(self.data == self.head && self.tail == self.head,
            "reserve must be called before adding data");
        debug_assert!(self.head + len <= self.end,
            "reserve exceeds buffer capacity");
        self.data += len;
        self.tail += len;
    }

    /// Add space at tail and return mutable slice (identical to ogs_pkbuf_put)
    /// Panics if not enough tailroom
    #[inline]
    pub fn put(&mut self, len: usize) -> &mut [u8] {
        assert!(self.tailroom() >= len, "not enough tailroom");
        let old_tail = self.tail;
        self.tail += len;
        self.len += len;
        self.data_mut_range(old_tail, self.tail)
    }

    /// Put a u8 value at tail (identical to ogs_pkbuf_put_u8)
    #[inline]
    pub fn put_u8(&mut self, val: u8) {
        self.put(1)[0] = val;
    }

    /// Put a u16 value at tail in big-endian (identical to ogs_pkbuf_put_u16)
    #[inline]
    pub fn put_u16(&mut self, val: u16) {
        let bytes = val.to_be_bytes();
        self.put(2).copy_from_slice(&bytes);
    }

    /// Put a u32 value at tail in big-endian (identical to ogs_pkbuf_put_u32)
    #[inline]
    pub fn put_u32(&mut self, val: u32) {
        let bytes = val.to_be_bytes();
        self.put(4).copy_from_slice(&bytes);
    }

    /// Copy data to tail (identical to ogs_pkbuf_put_data)
    pub fn put_data(&mut self, data: &[u8]) {
        let dest = self.put(data.len());
        dest.copy_from_slice(data);
    }

    /// Add space at head and return mutable slice (identical to ogs_pkbuf_push)
    /// Panics if not enough headroom
    #[inline]
    pub fn push(&mut self, len: usize) -> &mut [u8] {
        assert!(self.headroom() >= len, "not enough headroom");
        self.data -= len;
        self.len += len;
        self.data_mut_range(self.data, self.data + len)
    }

    /// Remove data from head (identical to ogs_pkbuf_pull)
    /// Returns None if len > current data length
    #[inline]
    pub fn pull(&mut self, len: usize) -> Option<&[u8]> {
        if len > self.len {
            return None;
        }
        let old_data = self.data;
        self.data += len;
        self.len -= len;
        Some(self.data_range(old_data, old_data + len))
    }

    /// Pull data from head, panics if not enough data
    #[inline]
    pub fn pull_unchecked(&mut self, len: usize) -> &[u8] {
        self.pull(len).expect("not enough data to pull")
    }

    /// Trim buffer to specified length (identical to ogs_pkbuf_trim)
    /// Returns error if len > current length
    pub fn trim(&mut self, len: usize) -> Result<(), &'static str> {
        if len > self.len {
            return Err("trim length exceeds buffer length");
        }
        self.tail = self.data + len;
        self.len = len;
        Ok(())
    }

    /// Get data slice
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.data_range(self.data, self.tail)
    }

    /// Get mutable data slice
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data_mut_range(self.data, self.tail)
    }

    /// Get data length
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get total capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cluster.size
    }

    /// Copy the packet buffer (identical to ogs_pkbuf_copy)
    pub fn copy(&self) -> Self {
        let mut new_pkbuf = OgsPkbuf::new(self.len);
        new_pkbuf.put_data(self.data());
        new_pkbuf
    }

    /// Reset buffer to initial state
    pub fn reset(&mut self) {
        self.data = self.head;
        self.tail = self.head;
        self.len = 0;
    }

    /// Helper to get immutable slice from cluster
    #[inline]
    fn data_range(&self, start: usize, end: usize) -> &[u8] {
        &self.cluster.buffer[start..end]
    }

    /// Helper to get mutable slice from cluster
    /// This is safe because we have exclusive access through &mut self
    #[inline]
    fn data_mut_range(&mut self, start: usize, end: usize) -> &mut [u8] {
        // Safety: We have exclusive access to the pkbuf, and Arc::get_mut
        // would fail if there are other references. For simplicity, we use
        // unsafe here since the pkbuf owns exclusive write access.
        let cluster = Arc::get_mut(&mut self.cluster)
            .expect("cannot mutate shared cluster");
        &mut cluster.buffer[start..end]
    }
}

impl Clone for OgsPkbuf {
    fn clone(&self) -> Self {
        self.copy()
    }
}

impl Default for OgsPkbuf {
    fn default() -> Self {
        Self::new(CLUSTER_2048) // Default MTU-sized buffer
    }
}

impl std::fmt::Debug for OgsPkbuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OgsPkbuf")
            .field("len", &self.len)
            .field("headroom", &self.headroom())
            .field("tailroom", &self.tailroom())
            .field("capacity", &self.capacity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkbuf_new() {
        let pkbuf = OgsPkbuf::new(100);
        assert_eq!(pkbuf.len(), 0);
        assert!(pkbuf.is_empty());
        assert!(pkbuf.capacity() >= 100);
    }

    #[test]
    fn test_pkbuf_reserve() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.reserve(20);
        assert_eq!(pkbuf.headroom(), 20);
        assert_eq!(pkbuf.len(), 0);
    }

    #[test]
    fn test_pkbuf_put() {
        let mut pkbuf = OgsPkbuf::new(100);
        let data = pkbuf.put(10);
        data.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(pkbuf.len(), 10);
        assert_eq!(pkbuf.data(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_pkbuf_put_data() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4, 5]);
        assert_eq!(pkbuf.len(), 5);
        assert_eq!(pkbuf.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_pkbuf_push() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.reserve(20);
        pkbuf.put_data(&[5, 6, 7, 8]);
        
        let header = pkbuf.push(4);
        header.copy_from_slice(&[1, 2, 3, 4]);
        
        assert_eq!(pkbuf.len(), 8);
        assert_eq!(pkbuf.data(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_pkbuf_pull() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4, 5, 6, 7, 8]);
        
        let pulled = pkbuf.pull(4).unwrap();
        assert_eq!(pulled, &[1, 2, 3, 4]);
        assert_eq!(pkbuf.len(), 4);
        assert_eq!(pkbuf.data(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_pkbuf_pull_too_much() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4]);
        
        assert!(pkbuf.pull(10).is_none());
        assert_eq!(pkbuf.len(), 4); // Unchanged
    }

    #[test]
    fn test_pkbuf_trim() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4, 5, 6, 7, 8]);
        
        pkbuf.trim(4).unwrap();
        assert_eq!(pkbuf.len(), 4);
        assert_eq!(pkbuf.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_pkbuf_trim_error() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4]);
        
        assert!(pkbuf.trim(10).is_err());
    }

    #[test]
    fn test_pkbuf_put_u8() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_u8(0x42);
        assert_eq!(pkbuf.data(), &[0x42]);
    }

    #[test]
    fn test_pkbuf_put_u16() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_u16(0x1234);
        assert_eq!(pkbuf.data(), &[0x12, 0x34]); // Big-endian
    }

    #[test]
    fn test_pkbuf_put_u32() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_u32(0x12345678);
        assert_eq!(pkbuf.data(), &[0x12, 0x34, 0x56, 0x78]); // Big-endian
    }

    #[test]
    fn test_pkbuf_copy() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4, 5]);
        
        let copy = pkbuf.copy();
        assert_eq!(copy.len(), pkbuf.len());
        assert_eq!(copy.data(), pkbuf.data());
    }

    #[test]
    fn test_pkbuf_reset() {
        let mut pkbuf = OgsPkbuf::new(100);
        pkbuf.put_data(&[1, 2, 3, 4, 5]);
        
        pkbuf.reset();
        assert_eq!(pkbuf.len(), 0);
        assert!(pkbuf.is_empty());
    }

    #[test]
    fn test_pkbuf_headroom_tailroom() {
        let mut pkbuf = OgsPkbuf::new(100);
        let capacity = pkbuf.capacity();
        
        pkbuf.reserve(20);
        assert_eq!(pkbuf.headroom(), 20);
        assert_eq!(pkbuf.tailroom(), capacity - 20);
        
        pkbuf.put_data(&[1, 2, 3, 4, 5]);
        assert_eq!(pkbuf.headroom(), 20);
        assert_eq!(pkbuf.tailroom(), capacity - 25);
    }

    #[test]
    fn test_cluster_size_selection() {
        assert_eq!(OgsPkbuf::select_cluster_size(50), CLUSTER_128);
        assert_eq!(OgsPkbuf::select_cluster_size(128), CLUSTER_128);
        assert_eq!(OgsPkbuf::select_cluster_size(129), CLUSTER_256);
        assert_eq!(OgsPkbuf::select_cluster_size(1500), CLUSTER_2048);
        assert_eq!(OgsPkbuf::select_cluster_size(9000), CLUSTER_32768);
    }

    // Property-based tests
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            /// Property 1: Length invariant
            /// len should always equal tail - data
            #[test]
            fn prop_length_invariant(
                capacity in 100..1000usize,
                reserve_size in 0..50usize,
                put_sizes in prop::collection::vec(1..20usize, 0..10)
            ) {
                let mut pkbuf = OgsPkbuf::new(capacity);
                let actual_capacity = pkbuf.capacity();
                
                // Reserve some headroom
                let safe_reserve = reserve_size.min(actual_capacity / 2);
                pkbuf.reserve(safe_reserve);
                
                // Put some data
                let mut total_put = 0;
                for size in put_sizes {
                    if total_put + size <= pkbuf.tailroom() {
                        pkbuf.put(size);
                        total_put += size;
                    }
                }
                
                prop_assert_eq!(pkbuf.len(), total_put, "len should equal total put data");
            }

            /// Property 2: Headroom + len + tailroom = capacity
            #[test]
            fn prop_space_invariant(
                capacity in 100..1000usize,
                reserve_size in 0..50usize,
                data_size in 0..50usize
            ) {
                let mut pkbuf = OgsPkbuf::new(capacity);
                let actual_capacity = pkbuf.capacity();
                
                let safe_reserve = reserve_size.min(actual_capacity / 2);
                pkbuf.reserve(safe_reserve);
                
                let safe_data = data_size.min(pkbuf.tailroom());
                if safe_data > 0 {
                    pkbuf.put(safe_data);
                }
                
                prop_assert_eq!(
                    pkbuf.headroom() + pkbuf.len() + pkbuf.tailroom(),
                    actual_capacity,
                    "headroom + len + tailroom should equal capacity"
                );
            }

            /// Property 3: Put data is retrievable
            #[test]
            fn prop_put_data_retrievable(data in prop::collection::vec(any::<u8>(), 1..100)) {
                let mut pkbuf = OgsPkbuf::new(data.len() + 50);
                pkbuf.put_data(&data);
                
                prop_assert_eq!(pkbuf.data(), &data[..], "put data should be retrievable");
            }

            /// Property 4: Push prepends data correctly
            #[test]
            fn prop_push_prepends(
                header in prop::collection::vec(any::<u8>(), 1..20),
                payload in prop::collection::vec(any::<u8>(), 1..50)
            ) {
                let total_size = header.len() + payload.len();
                let mut pkbuf = OgsPkbuf::new(total_size + 50);
                
                // Reserve headroom for header
                pkbuf.reserve(header.len() + 10);
                
                // Put payload
                pkbuf.put_data(&payload);
                
                // Push header
                let h = pkbuf.push(header.len());
                h.copy_from_slice(&header);
                
                // Verify combined data
                let mut expected = header.clone();
                expected.extend_from_slice(&payload);
                
                prop_assert_eq!(pkbuf.data(), &expected[..], "push should prepend data");
            }

            /// Property 5: Pull removes data from head
            #[test]
            fn prop_pull_removes_head(
                data in prop::collection::vec(any::<u8>(), 10..100),
                pull_size in 1..10usize
            ) {
                let mut pkbuf = OgsPkbuf::new(data.len() + 50);
                pkbuf.put_data(&data);
                
                let safe_pull = pull_size.min(data.len());
                let pulled = pkbuf.pull(safe_pull).unwrap();
                
                prop_assert_eq!(pulled, &data[..safe_pull], "pulled data should match");
                prop_assert_eq!(pkbuf.data(), &data[safe_pull..], "remaining data should be correct");
            }

            /// Property 6: Trim reduces length correctly
            #[test]
            fn prop_trim_reduces_length(
                data in prop::collection::vec(any::<u8>(), 10..100),
                new_len in 1..10usize
            ) {
                let mut pkbuf = OgsPkbuf::new(data.len() + 50);
                pkbuf.put_data(&data);
                
                let safe_len = new_len.min(data.len());
                pkbuf.trim(safe_len).unwrap();
                
                prop_assert_eq!(pkbuf.len(), safe_len, "length should be trimmed");
                prop_assert_eq!(pkbuf.data(), &data[..safe_len], "data should be truncated");
            }

            /// Property 7: Copy creates independent buffer
            #[test]
            fn prop_copy_independent(data in prop::collection::vec(any::<u8>(), 1..100)) {
                let mut pkbuf = OgsPkbuf::new(data.len() + 50);
                pkbuf.put_data(&data);
                
                let copy = pkbuf.copy();
                
                prop_assert_eq!(copy.len(), pkbuf.len(), "copy should have same length");
                prop_assert_eq!(copy.data(), pkbuf.data(), "copy should have same data");
            }

            /// Property 8: Reset clears buffer
            #[test]
            fn prop_reset_clears(data in prop::collection::vec(any::<u8>(), 1..100)) {
                let mut pkbuf = OgsPkbuf::new(data.len() + 50);
                pkbuf.put_data(&data);
                
                pkbuf.reset();
                
                prop_assert_eq!(pkbuf.len(), 0, "reset should clear length");
                prop_assert!(pkbuf.is_empty(), "reset should make buffer empty");
            }

            /// Property 9: Big-endian encoding is correct
            #[test]
            fn prop_big_endian_encoding(val in any::<u32>()) {
                let mut pkbuf = OgsPkbuf::new(100);
                pkbuf.put_u32(val);
                
                let data = pkbuf.data();
                let decoded = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                
                prop_assert_eq!(decoded, val, "big-endian encoding should round-trip");
            }

            /// Property 10: Cluster size is always >= requested
            #[test]
            fn prop_cluster_size_sufficient(size in 1..100000usize) {
                let cluster_size = OgsPkbuf::select_cluster_size(size);
                prop_assert!(cluster_size >= size, "cluster size should be >= requested size");
            }
        }
    }
}
