//! Object pool implementation
//!
//! Exact port of lib/core/ogs-pool.h
//!
//! This implementation uses a circular buffer for the free list,
//! matching the C implementation's head/tail approach.

use std::collections::HashMap;

/// Pool ID type (identical to ogs_pool_id_t)
pub type OgsPoolId = i32;

/// Invalid pool ID constant
pub const OGS_INVALID_POOL_ID: OgsPoolId = 0;
/// Minimum valid pool ID
pub const OGS_MIN_POOL_ID: OgsPoolId = 1;
/// Maximum valid pool ID
pub const OGS_MAX_POOL_ID: OgsPoolId = 0x7fffffff;

/// Trait for items that can be stored in a pool with ID
pub trait PoolItem {
    fn id(&self) -> OgsPoolId;
    fn set_id(&mut self, id: OgsPoolId);
}

/// Generic object pool with identical semantics to C version
/// 
/// Uses a circular buffer for the free list (head/tail pointers)
/// and maintains an index array for O(1) lookup by index.
pub struct OgsPool<T> {
    /// Name of the pool (for debugging)
    name: String,
    /// Circular buffer head pointer
    head: usize,
    /// Circular buffer tail pointer
    tail: usize,
    /// Total size of the pool
    size: usize,
    /// Number of available slots
    avail: usize,
    /// Free list (circular buffer of indices)
    free: Vec<Option<usize>>,
    /// Storage array for items
    array: Vec<Option<T>>,
    /// Index array for tracking allocated items (maps index to allocated status)
    index: Vec<bool>,
}

impl<T> OgsPool<T> {
    /// Create a new pool with the given capacity (identical to ogs_pool_init/ogs_pool_create)
    pub fn new(name: &str, size: usize) -> Self {
        let mut free = Vec::with_capacity(size);
        let mut array = Vec::with_capacity(size);
        let mut index = Vec::with_capacity(size);
        
        for i in 0..size {
            free.push(Some(i));
            array.push(None);
            index.push(false);
        }
        
        OgsPool {
            name: name.to_string(),
            head: 0,
            tail: 0,
            size,
            avail: size,
            free,
            array,
            index,
        }
    }

    /// Allocate an item from the pool (identical to ogs_pool_alloc)
    /// Returns the index (1-based) and mutable reference to the item
    pub fn alloc(&mut self) -> Option<usize>
    where
        T: Default,
    {
        if self.avail > 0 {
            self.avail -= 1;
            let idx = self.free[self.head].take()?;
            self.head = (self.head + 1) % self.size;
            self.array[idx] = Some(T::default());
            self.index[idx] = true;
            Some(idx + 1) // Return 1-based index
        } else {
            None
        }
    }

    /// Allocate an item with a custom initializer
    pub fn alloc_with<F>(&mut self, init: F) -> Option<usize>
    where
        F: FnOnce() -> T,
    {
        if self.avail > 0 {
            self.avail -= 1;
            let idx = self.free[self.head].take()?;
            self.head = (self.head + 1) % self.size;
            self.array[idx] = Some(init());
            self.index[idx] = true;
            Some(idx + 1) // Return 1-based index
        } else {
            None
        }
    }

    /// Free an item back to the pool (identical to ogs_pool_free)
    /// Takes a 1-based index
    pub fn free(&mut self, index: usize) {
        if index > 0 && index <= self.size && self.avail < self.size {
            let idx = index - 1;
            if self.index[idx] {
                self.avail += 1;
                self.free[self.tail] = Some(idx);
                self.tail = (self.tail + 1) % self.size;
                self.array[idx] = None;
                self.index[idx] = false;
            }
        }
    }

    /// Get item by 1-based index (identical to ogs_pool_find)
    pub fn find(&self, index: usize) -> Option<&T> {
        if index > 0 && index <= self.size {
            let idx = index - 1;
            if self.index[idx] {
                return self.array[idx].as_ref();
            }
        }
        None
    }

    /// Get mutable item by 1-based index
    pub fn find_mut(&mut self, index: usize) -> Option<&mut T> {
        if index > 0 && index <= self.size {
            let idx = index - 1;
            if self.index[idx] {
                return self.array[idx].as_mut();
            }
        }
        None
    }

    /// Get the 1-based index of an item (identical to ogs_pool_index)
    /// This requires the item to be in the pool's array
    pub fn index_of(&self, item: &T) -> Option<usize> {
        let item_ptr = item as *const T;
        for (i, slot) in self.array.iter().enumerate() {
            if let Some(ref stored) = slot {
                if std::ptr::eq(stored as *const T, item_ptr) {
                    return Some(i + 1);
                }
            }
        }
        None
    }

    /// Get number of available slots (identical to ogs_pool_avail)
    pub fn available(&self) -> usize {
        self.avail
    }

    /// Get total capacity (identical to ogs_pool_size)
    pub fn capacity(&self) -> usize {
        self.size
    }

    /// Get number of allocated objects
    pub fn allocated(&self) -> usize {
        self.size - self.avail
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.avail == self.size
    }

    /// Check if pool is full
    pub fn is_full(&self) -> bool {
        self.avail == 0
    }

    /// Get pool name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Iterate over allocated items
    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.array
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|item| (i + 1, item)))
    }

    /// Iterate over allocated items mutably
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> {
        self.array
            .iter_mut()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_mut().map(|item| (i + 1, item)))
    }
}

/// Pool with ID-based lookup (for items implementing PoolItem trait)
/// This matches the ogs_pool_id_calloc/ogs_pool_id_free functionality
pub struct OgsPoolWithId<T: PoolItem> {
    pool: OgsPool<T>,
    id_hash: HashMap<OgsPoolId, usize>,
    next_id: OgsPoolId,
}

impl<T: PoolItem + Default> OgsPoolWithId<T> {
    /// Create a new pool with ID support
    pub fn new(name: &str, size: usize) -> Self {
        OgsPoolWithId {
            pool: OgsPool::new(name, size),
            id_hash: HashMap::new(),
            next_id: OGS_MIN_POOL_ID,
        }
    }

    /// Allocate an item and assign it a unique ID (identical to ogs_pool_id_calloc)
    pub fn alloc(&mut self) -> Option<(OgsPoolId, usize)> {
        let index = self.pool.alloc()?;
        
        // Generate next ID (wrapping from MIN to MAX)
        let id = self.next_id;
        self.next_id = if self.next_id >= OGS_MAX_POOL_ID {
            OGS_MIN_POOL_ID
        } else {
            self.next_id + 1
        };
        
        // Set ID on the item
        if let Some(item) = self.pool.find_mut(index) {
            item.set_id(id);
        }
        
        // Add to hash
        self.id_hash.insert(id, index);
        
        Some((id, index))
    }

    /// Free an item by its ID (identical to ogs_pool_id_free)
    pub fn free_by_id(&mut self, id: OgsPoolId) {
        if let Some(index) = self.id_hash.remove(&id) {
            self.pool.free(index);
        }
    }

    /// Free an item by its index
    pub fn free(&mut self, index: usize) {
        if let Some(item) = self.pool.find(index) {
            let id = item.id();
            self.id_hash.remove(&id);
        }
        self.pool.free(index);
    }

    /// Find item by ID (identical to ogs_pool_find_by_id)
    pub fn find_by_id(&self, id: OgsPoolId) -> Option<&T> {
        let index = self.id_hash.get(&id)?;
        self.pool.find(*index)
    }

    /// Find mutable item by ID
    pub fn find_by_id_mut(&mut self, id: OgsPoolId) -> Option<&mut T> {
        let index = *self.id_hash.get(&id)?;
        self.pool.find_mut(index)
    }

    /// Find item by index
    pub fn find(&self, index: usize) -> Option<&T> {
        self.pool.find(index)
    }

    /// Find mutable item by index
    pub fn find_mut(&mut self, index: usize) -> Option<&mut T> {
        self.pool.find_mut(index)
    }

    /// Get number of available slots
    pub fn available(&self) -> usize {
        self.pool.available()
    }

    /// Get total capacity
    pub fn capacity(&self) -> usize {
        self.pool.capacity()
    }

    /// Get number of allocated objects
    pub fn allocated(&self) -> usize {
        self.pool.allocated()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Check if pool is full
    pub fn is_full(&self) -> bool {
        self.pool.is_full()
    }

    /// Get pool name
    pub fn name(&self) -> &str {
        self.pool.name()
    }

    /// Iterate over allocated items
    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.pool.iter()
    }
}

/// Helper macro to generate next ID with wrapping (identical to OGS_NEXT_ID)
#[macro_export]
macro_rules! ogs_next_id {
    ($id:expr, $min:expr, $max:expr) => {{
        let next = if $id >= $max { $min } else { $id + 1 };
        next
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug, Clone, PartialEq)]
    struct TestItem {
        id: OgsPoolId,
        value: i32,
    }

    impl PoolItem for TestItem {
        fn id(&self) -> OgsPoolId {
            self.id
        }
        fn set_id(&mut self, id: OgsPoolId) {
            self.id = id;
        }
    }

    #[test]
    fn test_pool_new() {
        let pool: OgsPool<TestItem> = OgsPool::new("test_pool", 10);
        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.available(), 10);
        assert_eq!(pool.allocated(), 0);
        assert!(pool.is_empty());
        assert!(!pool.is_full());
    }

    #[test]
    fn test_pool_alloc_free() {
        let mut pool: OgsPool<TestItem> = OgsPool::new("test_pool", 5);
        
        // Allocate
        let idx1 = pool.alloc().unwrap();
        assert_eq!(pool.available(), 4);
        assert_eq!(pool.allocated(), 1);
        
        let idx2 = pool.alloc().unwrap();
        assert_eq!(pool.available(), 3);
        assert_eq!(pool.allocated(), 2);
        
        // Free
        pool.free(idx1);
        assert_eq!(pool.available(), 4);
        assert_eq!(pool.allocated(), 1);
        
        pool.free(idx2);
        assert_eq!(pool.available(), 5);
        assert_eq!(pool.allocated(), 0);
    }

    #[test]
    fn test_pool_find() {
        let mut pool: OgsPool<TestItem> = OgsPool::new("test_pool", 5);
        
        let idx = pool.alloc().unwrap();
        
        // Modify the item
        if let Some(item) = pool.find_mut(idx) {
            item.value = 42;
        }
        
        // Find and verify
        let item = pool.find(idx).unwrap();
        assert_eq!(item.value, 42);
        
        // Invalid index should return None
        assert!(pool.find(0).is_none());
        assert!(pool.find(100).is_none());
    }

    #[test]
    fn test_pool_full() {
        let mut pool: OgsPool<TestItem> = OgsPool::new("test_pool", 3);
        
        let _idx1 = pool.alloc().unwrap();
        let _idx2 = pool.alloc().unwrap();
        let _idx3 = pool.alloc().unwrap();
        
        assert!(pool.is_full());
        assert!(pool.alloc().is_none());
    }

    #[test]
    fn test_pool_circular_reuse() {
        let mut pool: OgsPool<TestItem> = OgsPool::new("test_pool", 3);
        
        // Allocate all
        let idx1 = pool.alloc().unwrap();
        let idx2 = pool.alloc().unwrap();
        let idx3 = pool.alloc().unwrap();
        
        // Free in different order
        pool.free(idx2);
        pool.free(idx1);
        pool.free(idx3);
        
        // Reallocate - should get slots back in FIFO order
        let new_idx1 = pool.alloc().unwrap();
        let new_idx2 = pool.alloc().unwrap();
        let new_idx3 = pool.alloc().unwrap();
        
        // The indices should be reused
        assert!(new_idx1 > 0 && new_idx1 <= 3);
        assert!(new_idx2 > 0 && new_idx2 <= 3);
        assert!(new_idx3 > 0 && new_idx3 <= 3);
    }

    #[test]
    fn test_pool_with_id() {
        let mut pool: OgsPoolWithId<TestItem> = OgsPoolWithId::new("test_pool", 5);
        
        // Allocate with ID
        let (id1, _idx1) = pool.alloc().unwrap();
        let (id2, _idx2) = pool.alloc().unwrap();
        
        assert!(id1 >= OGS_MIN_POOL_ID && id1 <= OGS_MAX_POOL_ID);
        assert!(id2 >= OGS_MIN_POOL_ID && id2 <= OGS_MAX_POOL_ID);
        assert_ne!(id1, id2);
        
        // Find by ID
        let item1 = pool.find_by_id(id1).unwrap();
        assert_eq!(item1.id(), id1);
        
        // Free by ID
        pool.free_by_id(id1);
        assert!(pool.find_by_id(id1).is_none());
        assert!(pool.find_by_id(id2).is_some());
    }

    #[test]
    fn test_pool_iter() {
        let mut pool: OgsPool<TestItem> = OgsPool::new("test_pool", 5);
        
        let idx1 = pool.alloc().unwrap();
        let idx2 = pool.alloc().unwrap();
        
        if let Some(item) = pool.find_mut(idx1) {
            item.value = 10;
        }
        if let Some(item) = pool.find_mut(idx2) {
            item.value = 20;
        }
        
        let items: Vec<_> = pool.iter().collect();
        assert_eq!(items.len(), 2);
        
        let values: Vec<i32> = items.iter().map(|(_, item)| item.value).collect();
        assert!(values.contains(&10));
        assert!(values.contains(&20));
    }

    // Property-based tests
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashSet;

        /// Generate pool operations
        #[derive(Debug, Clone)]
        enum PoolOp {
            Alloc,
            Free(usize), // Index to free (will be mapped to actual allocated index)
        }

        fn pool_op_strategy() -> impl Strategy<Value = PoolOp> {
            prop_oneof![
                Just(PoolOp::Alloc),
                (0..10usize).prop_map(PoolOp::Free),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]

            /// Property 1: Capacity invariant
            /// available + allocated should always equal capacity
            #[test]
            fn prop_capacity_invariant(
                size in 1..50usize,
                ops in prop::collection::vec(pool_op_strategy(), 0..100)
            ) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                let mut allocated_indices: Vec<usize> = Vec::new();
                
                for op in ops {
                    match op {
                        PoolOp::Alloc => {
                            if let Some(idx) = pool.alloc() {
                                allocated_indices.push(idx);
                            }
                        }
                        PoolOp::Free(i) => {
                            if !allocated_indices.is_empty() {
                                let actual_idx = i % allocated_indices.len();
                                let idx = allocated_indices.remove(actual_idx);
                                pool.free(idx);
                            }
                        }
                    }
                    
                    // Invariant check
                    prop_assert_eq!(
                        pool.available() + pool.allocated(),
                        pool.capacity(),
                        "available + allocated should equal capacity"
                    );
                }
            }

            /// Property 2: Allocation returns valid indices
            /// All allocated indices should be in range [1, capacity]
            #[test]
            fn prop_valid_indices(
                size in 1..50usize,
                alloc_count in 0..100usize
            ) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                let mut indices: Vec<usize> = Vec::new();
                
                for _ in 0..alloc_count {
                    if let Some(idx) = pool.alloc() {
                        prop_assert!(idx >= 1 && idx <= size, "Index {} out of range [1, {}]", idx, size);
                        indices.push(idx);
                    }
                }
                
                // All indices should be unique
                let unique: HashSet<_> = indices.iter().collect();
                prop_assert_eq!(unique.len(), indices.len(), "All indices should be unique");
            }

            /// Property 3: Find returns allocated items
            /// After allocation, find should return the item
            #[test]
            fn prop_find_after_alloc(size in 1..20usize) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                
                // Allocate all
                let mut indices = Vec::new();
                while let Some(idx) = pool.alloc() {
                    indices.push(idx);
                }
                
                // All should be findable
                for idx in &indices {
                    prop_assert!(pool.find(*idx).is_some(), "Should find allocated item at index {}", idx);
                }
                
                // Free all
                for idx in &indices {
                    pool.free(*idx);
                }
                
                // None should be findable
                for idx in &indices {
                    prop_assert!(pool.find(*idx).is_none(), "Should not find freed item at index {}", idx);
                }
            }

            /// Property 4: Pool never exceeds capacity
            /// Cannot allocate more than capacity items
            #[test]
            fn prop_capacity_limit(size in 1..50usize) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                let mut count = 0;
                
                while pool.alloc().is_some() {
                    count += 1;
                    prop_assert!(count <= size, "Allocated more than capacity");
                }
                
                prop_assert_eq!(count, size, "Should allocate exactly capacity items");
                prop_assert!(pool.is_full(), "Pool should be full");
            }

            /// Property 5: Free enables reallocation
            /// After freeing, the slot can be reallocated
            #[test]
            fn prop_reallocation(size in 1..20usize, cycles in 1..5usize) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                
                for _ in 0..cycles {
                    // Allocate all
                    let mut indices = Vec::new();
                    while let Some(idx) = pool.alloc() {
                        indices.push(idx);
                    }
                    prop_assert_eq!(indices.len(), size);
                    prop_assert!(pool.is_full());
                    
                    // Free all
                    for idx in indices {
                        pool.free(idx);
                    }
                    prop_assert!(pool.is_empty());
                }
            }

            /// Property 6: Double free is safe
            /// Freeing the same index twice should not corrupt the pool
            #[test]
            fn prop_double_free_safe(size in 1..20usize) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                
                let idx = pool.alloc().unwrap();
                let initial_avail = pool.available();
                
                pool.free(idx);
                prop_assert_eq!(pool.available(), initial_avail + 1);
                
                // Double free should be a no-op
                pool.free(idx);
                prop_assert_eq!(pool.available(), initial_avail + 1, "Double free should not change available count");
            }

            /// Property 7: Iterator count matches allocated
            /// Iterator should visit exactly allocated() items
            #[test]
            fn prop_iter_count(
                size in 1..30usize,
                alloc_count in 0..30usize
            ) {
                let mut pool: OgsPool<TestItem> = OgsPool::new("test", size);
                
                let actual_alloc = alloc_count.min(size);
                for _ in 0..actual_alloc {
                    pool.alloc();
                }
                
                let iter_count = pool.iter().count();
                prop_assert_eq!(iter_count, pool.allocated(), "Iterator count should match allocated");
            }

            /// Property 8: ID uniqueness in OgsPoolWithId
            /// All allocated IDs should be unique
            #[test]
            fn prop_id_uniqueness(size in 1..30usize) {
                let mut pool: OgsPoolWithId<TestItem> = OgsPoolWithId::new("test", size);
                let mut ids: HashSet<OgsPoolId> = HashSet::new();
                
                while let Some((id, _)) = pool.alloc() {
                    prop_assert!(!ids.contains(&id), "ID {} should be unique", id);
                    ids.insert(id);
                }
                
                prop_assert_eq!(ids.len(), size, "Should have {} unique IDs", size);
            }

            /// Property 9: ID lookup consistency
            /// find_by_id should return the correct item
            #[test]
            fn prop_id_lookup(size in 1..20usize) {
                let mut pool: OgsPoolWithId<TestItem> = OgsPoolWithId::new("test", size);
                let mut id_to_idx: HashMap<OgsPoolId, usize> = HashMap::new();
                
                // Allocate all
                while let Some((id, idx)) = pool.alloc() {
                    id_to_idx.insert(id, idx);
                }
                
                // Verify all lookups
                for (id, _idx) in &id_to_idx {
                    let item = pool.find_by_id(*id);
                    prop_assert!(item.is_some(), "Should find item by ID {}", id);
                    prop_assert_eq!(item.unwrap().id(), *id, "Item ID should match lookup ID");
                }
            }
        }
    }
}
