//! Hash table implementation
//!
//! Exact port of lib/core/ogs-hash.h and ogs-hash.c
//!
//! This implementation uses the "times 33" hash algorithm (also known as djb2)
//! which is the same algorithm used in the C implementation.

use std::time::{SystemTime, UNIX_EPOCH};

/// Special key length value indicating a null-terminated string key
pub const OGS_HASH_KEY_STRING: i32 = -1;

/// Initial maximum size (tunable == 2^n - 1)
const INITIAL_MAX: usize = 15;

/// Hash entry in the chain
struct OgsHashEntry {
    next: Option<Box<OgsHashEntry>>,
    hash: u32,
    key: Vec<u8>,
    klen: i32,
    val: *mut (),
}

/// Hash table with identical semantics to C version
/// Uses the "times 33" hash algorithm for exact algorithm parity
pub struct OgsHash {
    array: Vec<Option<Box<OgsHashEntry>>>,
    count: usize,
    max: usize,
    seed: u32,
    custom_hash_fn: Option<fn(&[u8], &mut i32) -> u32>,
}

impl OgsHash {
    /// Create a new hash table (identical to ogs_hash_make)
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        
        let seed = ((now >> 32) ^ now) as u32;
        
        let mut array = Vec::with_capacity(INITIAL_MAX + 1);
        for _ in 0..=INITIAL_MAX {
            array.push(None);
        }
        
        OgsHash {
            array,
            count: 0,
            max: INITIAL_MAX,
            seed,
            custom_hash_fn: None,
        }
    }

    /// Create a hash table with a custom hash function (identical to ogs_hash_make_custom)
    pub fn with_custom_hash(hash_fn: fn(&[u8], &mut i32) -> u32) -> Self {
        let mut ht = Self::new();
        ht.custom_hash_fn = Some(hash_fn);
        ht
    }

    /// The "times 33" hash algorithm (identical to hashfunc_default in C)
    fn hash_default(&self, key: &[u8], klen: &mut i32) -> u32 {
        let mut hash = self.seed;
        
        if *klen == OGS_HASH_KEY_STRING {
            let mut len = 0i32;
            for &byte in key {
                if byte == 0 {
                    break;
                }
                hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
                len += 1;
            }
            *klen = len;
        } else {
            let len = *klen as usize;
            for &byte in key.iter().take(len) {
                hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
            }
        }
        
        hash
    }

    /// Compute hash for a key
    fn compute_hash(&self, key: &[u8], klen: &mut i32) -> u32 {
        if let Some(hash_fn) = self.custom_hash_fn {
            hash_fn(key, klen)
        } else {
            self.hash_default(key, klen)
        }
    }

    /// Expand the array when load factor is too high
    fn expand_array(&mut self) {
        let new_max = self.max * 2 + 1;
        let mut new_array: Vec<Option<Box<OgsHashEntry>>> = Vec::with_capacity(new_max + 1);
        for _ in 0..=new_max {
            new_array.push(None);
        }

        // Rehash all entries
        for slot in self.array.iter_mut() {
            let mut entry_opt = slot.take();
            while let Some(mut entry) = entry_opt {
                let next = entry.next.take();
                let i = (entry.hash as usize) & new_max;
                entry.next = new_array[i].take();
                new_array[i] = Some(entry);
                entry_opt = next;
            }
        }

        self.array = new_array;
        self.max = new_max;
    }

    /// Set a key-value pair (identical to ogs_hash_set)
    pub fn set(&mut self, key: &[u8], klen: i32, val: Option<*mut ()>) {
        let mut actual_klen = klen;
        let hash = self.compute_hash(key, &mut actual_klen);
        let index = (hash as usize) & self.max;
        let key_slice = &key[..actual_klen as usize];
        
        // Search for existing entry
        let mut found = false;
        
        {
            let mut current = self.array[index].as_mut();
            while let Some(entry) = current {
                if entry.hash == hash && entry.klen == actual_klen && entry.key == key_slice {
                    if let Some(val_ptr) = val {
                        // Replace value
                        entry.val = val_ptr;
                        if self.count > self.max {
                            self.expand_array();
                        }
                    } else {
                        // Mark for deletion
                        found = true;
                    }
                    break;
                }
                current = entry.next.as_mut();
            }
        }
        
        if found {
            // Delete entry - need to handle this separately due to borrow checker
            self.delete_entry(index, hash, actual_klen, key_slice);
            return;
        }
        
        // If we didn't find an existing entry and val is Some, add new entry
        if val.is_some() && !found {
            // Check if we already handled it above
            let mut current = self.array[index].as_ref();
            let mut exists = false;
            while let Some(entry) = current {
                if entry.hash == hash && entry.klen == actual_klen && entry.key == key_slice {
                    exists = true;
                    break;
                }
                current = entry.next.as_ref();
            }
            
            if !exists {
                let new_entry = Box::new(OgsHashEntry {
                    next: self.array[index].take(),
                    hash,
                    key: key_slice.to_vec(),
                    klen: actual_klen,
                    val: val.unwrap(),
                });
                
                self.array[index] = Some(new_entry);
                self.count += 1;
                
                if self.count > self.max {
                    self.expand_array();
                }
            }
        }
    }

    /// Delete an entry from the hash table
    fn delete_entry(&mut self, index: usize, hash: u32, klen: i32, key: &[u8]) {
        let slot = &mut self.array[index];
        
        // Check if it's the first entry
        if let Some(ref entry) = slot {
            if entry.hash == hash && entry.klen == klen && entry.key == key {
                let mut removed = slot.take().unwrap();
                *slot = removed.next.take();
                self.count -= 1;
                return;
            }
        }
        
        // Search in the chain
        let mut current = slot.as_mut();
        while let Some(entry) = current {
            if let Some(ref next_entry) = entry.next {
                if next_entry.hash == hash && next_entry.klen == klen && next_entry.key == key {
                    let mut removed = entry.next.take().unwrap();
                    entry.next = removed.next.take();
                    self.count -= 1;
                    return;
                }
            }
            current = entry.next.as_mut();
        }
    }

    /// Get a value by key (identical to ogs_hash_get)
    pub fn get(&self, key: &[u8], klen: i32) -> Option<*mut ()> {
        let mut actual_klen = klen;
        let hash = self.compute_hash_immut(key, &mut actual_klen);
        let index = (hash as usize) & self.max;
        let key_slice = &key[..actual_klen as usize];
        
        let mut current = self.array[index].as_ref();
        while let Some(entry) = current {
            if entry.hash == hash && entry.klen == actual_klen && entry.key == key_slice {
                return Some(entry.val);
            }
            current = entry.next.as_ref();
        }
        
        None
    }

    /// Compute hash without mutating self (for get operations)
    fn compute_hash_immut(&self, key: &[u8], klen: &mut i32) -> u32 {
        if let Some(hash_fn) = self.custom_hash_fn {
            hash_fn(key, klen)
        } else {
            let mut hash = self.seed;
            
            if *klen == OGS_HASH_KEY_STRING {
                let mut len = 0i32;
                for &byte in key {
                    if byte == 0 {
                        break;
                    }
                    hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
                    len += 1;
                }
                *klen = len;
            } else {
                let len = *klen as usize;
                for &byte in key.iter().take(len) {
                    hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
                }
            }
            
            hash
        }
    }

    /// Get or set a value (identical to ogs_hash_get_or_set)
    pub fn get_or_set(&mut self, key: &[u8], klen: i32, val: *mut ()) -> Option<*mut ()> {
        let mut actual_klen = klen;
        let hash = self.compute_hash(key, &mut actual_klen);
        let index = (hash as usize) & self.max;
        let key_slice = &key[..actual_klen as usize];
        
        // Search for existing entry
        let mut current = self.array[index].as_ref();
        while let Some(entry) = current {
            if entry.hash == hash && entry.klen == actual_klen && entry.key == key_slice {
                if self.count > self.max {
                    // Can't expand here due to borrow, but we'll handle it
                }
                return Some(entry.val);
            }
            current = entry.next.as_ref();
        }
        
        // Add new entry
        let new_entry = Box::new(OgsHashEntry {
            next: self.array[index].take(),
            hash,
            key: key_slice.to_vec(),
            klen: actual_klen,
            val,
        });
        
        self.array[index] = Some(new_entry);
        self.count += 1;
        
        if self.count > self.max {
            self.expand_array();
        }
        
        Some(val)
    }

    /// Get number of entries (identical to ogs_hash_count)
    pub fn count(&self) -> usize {
        self.count
    }

    /// Clear all entries (identical to ogs_hash_clear)
    pub fn clear(&mut self) {
        for slot in self.array.iter_mut() {
            *slot = None;
        }
        self.count = 0;
    }

    /// Check if the hash table is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get an iterator over the hash table
    pub fn iter(&self) -> OgsHashIter<'_> {
        OgsHashIter {
            ht: self,
            index: 0,
            current: None,
        }
    }
}

impl Default for OgsHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over hash table entries
pub struct OgsHashIter<'a> {
    ht: &'a OgsHash,
    index: usize,
    current: Option<&'a OgsHashEntry>,
}

impl<'a> Iterator for OgsHashIter<'a> {
    type Item = (&'a [u8], i32, *mut ());

    fn next(&mut self) -> Option<Self::Item> {
        // If we have a current entry, try to get its next
        if let Some(entry) = self.current {
            if let Some(ref next) = entry.next {
                self.current = Some(next.as_ref());
                let curr = self.current.unwrap();
                return Some((&curr.key, curr.klen, curr.val));
            }
            self.index += 1;
        }

        // Find next non-empty bucket
        while self.index <= self.ht.max {
            if let Some(ref entry) = self.ht.array[self.index] {
                self.current = Some(entry.as_ref());
                let curr = self.current.unwrap();
                return Some((&curr.key, curr.klen, curr.val));
            }
            self.index += 1;
        }

        None
    }
}

/// The default hash function exposed for external use (identical to ogs_hashfunc_default)
pub fn ogs_hashfunc_default(key: &[u8], klen: &mut i32) -> u32 {
    let mut hash = 0u32;
    
    if *klen == OGS_HASH_KEY_STRING {
        let mut len = 0i32;
        for &byte in key {
            if byte == 0 {
                break;
            }
            hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
            len += 1;
        }
        *klen = len;
    } else {
        let len = *klen as usize;
        for &byte in key.iter().take(len) {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
        }
    }
    
    hash
}

// ============================================================================
// Type-safe wrapper for common use cases
// ============================================================================

use std::collections::HashMap;
use std::hash::Hash;

/// Generic type-safe hash table wrapper
pub struct OgsHashMap<K, V> {
    map: HashMap<K, V>,
}

impl<K: Eq + Hash, V> OgsHashMap<K, V> {
    pub fn new() -> Self {
        OgsHashMap {
            map: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        OgsHashMap {
            map: HashMap::with_capacity(capacity),
        }
    }

    pub fn set(&mut self, key: K, value: V) -> Option<V> {
        self.map.insert(key, value)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }

    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }
}

impl<K: Eq + Hash, V> Default for OgsHashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_new() {
        let ht = OgsHash::new();
        assert_eq!(ht.count(), 0);
        assert!(ht.is_empty());
    }

    // Property-based tests
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashMap;

        /// Generate arbitrary key-value operations
        #[derive(Debug, Clone)]
        enum HashOp {
            Set(Vec<u8>, usize),
            Get(Vec<u8>),
            Delete(Vec<u8>),
        }

        fn hash_op_strategy() -> impl Strategy<Value = HashOp> {
            prop_oneof![
                // Set operation with key and value
                (prop::collection::vec(any::<u8>(), 1..32), any::<usize>())
                    .prop_map(|(k, v)| HashOp::Set(k, v)),
                // Get operation
                prop::collection::vec(any::<u8>(), 1..32).prop_map(HashOp::Get),
                // Delete operation
                prop::collection::vec(any::<u8>(), 1..32).prop_map(HashOp::Delete),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            /// Property 1: Hash function is deterministic
            /// The same key should always produce the same hash value
            #[test]
            fn prop_hash_deterministic(key in prop::collection::vec(any::<u8>(), 1..64)) {
                let mut klen1 = key.len() as i32;
                let mut klen2 = key.len() as i32;
                
                let hash1 = ogs_hashfunc_default(&key, &mut klen1);
                let hash2 = ogs_hashfunc_default(&key, &mut klen2);
                
                prop_assert_eq!(hash1, hash2, "Hash should be deterministic");
                prop_assert_eq!(klen1, klen2, "Key length should be consistent");
            }

            /// Property 2: Set/Get consistency
            /// After setting a key-value pair, get should return the same value
            #[test]
            fn prop_set_get_consistency(
                key in prop::collection::vec(any::<u8>(), 1..32),
                value in any::<usize>()
            ) {
                let mut ht = OgsHash::new();
                let val_ptr = value as *mut ();
                
                ht.set(&key, key.len() as i32, Some(val_ptr));
                let result = ht.get(&key, key.len() as i32);
                
                prop_assert!(result.is_some(), "Get should return Some after set");
                prop_assert_eq!(result.unwrap(), val_ptr, "Get should return the set value");
            }

            /// Property 3: Count invariant
            /// Count should always equal the number of unique keys
            #[test]
            fn prop_count_invariant(ops in prop::collection::vec(hash_op_strategy(), 0..50)) {
                let mut ht = OgsHash::new();
                let mut reference: HashMap<Vec<u8>, usize> = HashMap::new();
                
                for op in ops {
                    match op {
                        HashOp::Set(key, val) => {
                            let val_ptr = val as *mut ();
                            ht.set(&key, key.len() as i32, Some(val_ptr));
                            reference.insert(key, val);
                        }
                        HashOp::Delete(key) => {
                            ht.set(&key, key.len() as i32, None);
                            reference.remove(&key);
                        }
                        HashOp::Get(_) => {
                            // Get doesn't change count
                        }
                    }
                }
                
                prop_assert_eq!(
                    ht.count(), 
                    reference.len(), 
                    "Count should match reference HashMap"
                );
            }

            /// Property 4: Delete removes entry
            /// After deleting a key, get should return None
            #[test]
            fn prop_delete_removes_entry(
                key in prop::collection::vec(any::<u8>(), 1..32),
                value in any::<usize>()
            ) {
                let mut ht = OgsHash::new();
                let val_ptr = value as *mut ();
                
                // Set then delete
                ht.set(&key, key.len() as i32, Some(val_ptr));
                prop_assert_eq!(ht.count(), 1);
                
                ht.set(&key, key.len() as i32, None);
                prop_assert_eq!(ht.count(), 0);
                
                let result = ht.get(&key, key.len() as i32);
                prop_assert!(result.is_none(), "Get should return None after delete");
            }

            /// Property 5: Iteration covers all entries
            /// Iterator should visit exactly count() entries
            #[test]
            fn prop_iteration_complete(
                entries in prop::collection::vec(
                    (prop::collection::vec(any::<u8>(), 1..16), any::<usize>()),
                    0..30
                )
            ) {
                let mut ht = OgsHash::new();
                let mut unique_keys: HashMap<Vec<u8>, usize> = HashMap::new();
                
                for (key, val) in entries {
                    let val_ptr = val as *mut ();
                    ht.set(&key, key.len() as i32, Some(val_ptr));
                    unique_keys.insert(key, val);
                }
                
                let iter_count = ht.iter().count();
                prop_assert_eq!(
                    iter_count, 
                    ht.count(), 
                    "Iterator should visit count() entries"
                );
                prop_assert_eq!(
                    iter_count, 
                    unique_keys.len(), 
                    "Iterator count should match unique keys"
                );
            }

            /// Property 6: Replace preserves count
            /// Setting the same key twice should not increase count
            #[test]
            fn prop_replace_preserves_count(
                key in prop::collection::vec(any::<u8>(), 1..32),
                val1 in any::<usize>(),
                val2 in any::<usize>()
            ) {
                let mut ht = OgsHash::new();
                
                ht.set(&key, key.len() as i32, Some(val1 as *mut ()));
                prop_assert_eq!(ht.count(), 1);
                
                ht.set(&key, key.len() as i32, Some(val2 as *mut ()));
                prop_assert_eq!(ht.count(), 1, "Count should remain 1 after replace");
                
                let result = ht.get(&key, key.len() as i32);
                prop_assert_eq!(result.unwrap(), val2 as *mut (), "Value should be updated");
            }

            /// Property 7: Clear empties the table
            /// After clear, count should be 0 and all gets should return None
            #[test]
            fn prop_clear_empties_table(
                entries in prop::collection::vec(
                    (prop::collection::vec(any::<u8>(), 1..16), any::<usize>()),
                    1..20
                )
            ) {
                let mut ht = OgsHash::new();
                let keys: Vec<Vec<u8>> = entries.iter().map(|(k, _)| k.clone()).collect();
                
                for (key, val) in entries {
                    ht.set(&key, key.len() as i32, Some(val as *mut ()));
                }
                
                ht.clear();
                
                prop_assert_eq!(ht.count(), 0, "Count should be 0 after clear");
                prop_assert!(ht.is_empty(), "Table should be empty after clear");
                
                for key in keys {
                    let result = ht.get(&key, key.len() as i32);
                    prop_assert!(result.is_none(), "All gets should return None after clear");
                }
            }

            /// Property 8: get_or_set returns existing value
            /// If key exists, get_or_set should return existing value, not new one
            #[test]
            fn prop_get_or_set_existing(
                key in prop::collection::vec(any::<u8>(), 1..32),
                val1 in any::<usize>(),
                val2 in any::<usize>()
            ) {
                let mut ht = OgsHash::new();
                
                // First set
                let result1 = ht.get_or_set(&key, key.len() as i32, val1 as *mut ());
                prop_assert_eq!(result1.unwrap(), val1 as *mut ());
                prop_assert_eq!(ht.count(), 1);
                
                // Second get_or_set should return first value
                let result2 = ht.get_or_set(&key, key.len() as i32, val2 as *mut ());
                prop_assert_eq!(result2.unwrap(), val1 as *mut (), "Should return existing value");
                prop_assert_eq!(ht.count(), 1, "Count should still be 1");
            }

            /// Property 9: Hash table handles expansion correctly
            /// Adding many entries should work correctly after expansion
            #[test]
            fn prop_expansion_preserves_entries(
                entries in prop::collection::vec(
                    (prop::collection::vec(any::<u8>(), 1..16), any::<usize>()),
                    20..60
                )
            ) {
                let mut ht = OgsHash::new();
                let mut reference: HashMap<Vec<u8>, usize> = HashMap::new();
                
                for (key, val) in &entries {
                    ht.set(key, key.len() as i32, Some(*val as *mut ()));
                    reference.insert(key.clone(), *val);
                }
                
                // Verify all entries are retrievable
                for (key, val) in &reference {
                    let result = ht.get(key, key.len() as i32);
                    prop_assert!(result.is_some(), "Entry should exist after expansion");
                    prop_assert_eq!(result.unwrap(), *val as *mut (), "Value should match");
                }
                
                prop_assert_eq!(ht.count(), reference.len());
            }
        }
    }

    #[test]
    fn test_hash_set_get() {
        let mut ht = OgsHash::new();
        let key = b"test_key";
        let value = 42usize;
        let val_ptr = &value as *const usize as *mut ();
        
        ht.set(key, key.len() as i32, Some(val_ptr));
        assert_eq!(ht.count(), 1);
        
        let result = ht.get(key, key.len() as i32);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), val_ptr);
    }

    #[test]
    fn test_hash_string_key() {
        let mut ht = OgsHash::new();
        let key = b"hello\0world";
        let value = 42usize;
        let val_ptr = &value as *const usize as *mut ();
        
        ht.set(key, OGS_HASH_KEY_STRING, Some(val_ptr));
        
        let result = ht.get(b"hello\0", OGS_HASH_KEY_STRING);
        assert!(result.is_some());
    }

    #[test]
    fn test_hashfunc_default() {
        let key = b"test";
        let mut klen = key.len() as i32;
        let hash1 = ogs_hashfunc_default(key, &mut klen);
        
        let mut klen2 = key.len() as i32;
        let hash2 = ogs_hashfunc_default(key, &mut klen2);
        
        assert_eq!(hash1, hash2);
        assert_eq!(klen, klen2);
    }
}
