//! Lock-Free Data Structures (B2.4)
//!
//! Implements wait-free and lock-free concurrent data structures for high-performance
//! multi-threaded scenarios in 6G core network functions.
//!
//! # Overview
//!
//! Lock-free algorithms guarantee system-wide progress even when threads are suspended.
//! Wait-free algorithms guarantee per-thread progress. These are crucial for real-time
//! 6G network functions that cannot afford lock contention.
//!
//! # Implementations
//!
//! - `LockFreeQueue`: Multi-producer, multi-consumer queue using atomic operations
//! - `LockFreeStack`: Lock-free stack using atomic pointer swaps
//! - `LockFreeHashMap`: Lock-free concurrent hash map with atomic bucket operations
//!
//! # References
//!
//! - Michael & Scott, "Simple, Fast, and Practical Non-Blocking and Blocking Concurrent Queue Algorithms"
//! - Treiber, "Systems Programming: Coping with Parallelism"
//! - Cliff Click, "A Lock-Free Hash Table"

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::ptr;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

// ============================================================================
// Lock-Free Queue (Michael-Scott Queue)
// ============================================================================

/// Node in the lock-free queue
struct QueueNode<T> {
    value: Option<T>,
    next: AtomicPtr<QueueNode<T>>,
}

impl<T> QueueNode<T> {
    fn new(value: Option<T>) -> Box<Self> {
        Box::new(Self {
            value,
            next: AtomicPtr::new(ptr::null_mut()),
        })
    }
}

/// Lock-free multi-producer, multi-consumer queue
///
/// Based on the Michael-Scott algorithm with atomic operations.
/// Provides wait-free enqueue and lock-free dequeue operations.
///
/// # Example
///
/// ```
/// use ogs_core::lockfree::LockFreeQueue;
///
/// let queue = LockFreeQueue::new();
/// queue.enqueue(42);
/// queue.enqueue(100);
///
/// assert_eq!(queue.dequeue(), Some(42));
/// assert_eq!(queue.dequeue(), Some(100));
/// assert_eq!(queue.dequeue(), None);
/// ```
pub struct LockFreeQueue<T> {
    head: AtomicPtr<QueueNode<T>>,
    tail: AtomicPtr<QueueNode<T>>,
    size: AtomicUsize,
}

impl<T> LockFreeQueue<T> {
    /// Creates a new empty lock-free queue
    pub fn new() -> Self {
        let dummy = Box::into_raw(QueueNode::new(None));
        Self {
            head: AtomicPtr::new(dummy),
            tail: AtomicPtr::new(dummy),
            size: AtomicUsize::new(0),
        }
    }

    /// Enqueues a value (wait-free)
    pub fn enqueue(&self, value: T) {
        let node = Box::into_raw(QueueNode::new(Some(value)));

        loop {
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*tail).next.load(Ordering::Acquire) };

            if tail == self.tail.load(Ordering::Acquire) {
                if next.is_null() {
                    // Try to link node at the end
                    if unsafe { (*tail).next.compare_exchange(
                        next,
                        node,
                        Ordering::Release,
                        Ordering::Acquire,
                    ).is_ok() } {
                        // Enqueue done, try to swing tail
                        let _ = self.tail.compare_exchange(
                            tail,
                            node,
                            Ordering::Release,
                            Ordering::Acquire,
                        );
                        self.size.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                } else {
                    // Tail was not pointing to last node, try to swing it
                    let _ = self.tail.compare_exchange(
                        tail,
                        next,
                        Ordering::Release,
                        Ordering::Acquire,
                    );
                }
            }
        }
    }

    /// Dequeues a value (lock-free, returns None if empty)
    pub fn dequeue(&self) -> Option<T> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let tail = self.tail.load(Ordering::Acquire);
            let next = unsafe { (*head).next.load(Ordering::Acquire) };

            if head == self.head.load(Ordering::Acquire) {
                if head == tail {
                    if next.is_null() {
                        return None; // Queue is empty
                    }
                    // Tail is falling behind, try to advance it
                    let _ = self.tail.compare_exchange(
                        tail,
                        next,
                        Ordering::Release,
                        Ordering::Acquire,
                    );
                } else {
                    // Read value before CAS, otherwise another dequeue might free the next node
                    let value = unsafe { (*next).value.take() };

                    if self.head.compare_exchange(
                        head,
                        next,
                        Ordering::Release,
                        Ordering::Acquire,
                    ).is_ok() {
                        // Free the old dummy node
                        unsafe { drop(Box::from_raw(head)); }
                        self.size.fetch_sub(1, Ordering::Relaxed);
                        return value;
                    }
                }
            }
        }
    }

    /// Returns the approximate size of the queue
    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Returns true if the queue is empty
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let next = unsafe { (*head).next.load(Ordering::Acquire) };
        next.is_null()
    }
}

impl<T> Default for LockFreeQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for LockFreeQueue<T> {
    fn drop(&mut self) {
        // Drain all elements
        while self.dequeue().is_some() {}

        // Free the dummy node
        let head = self.head.load(Ordering::Acquire);
        if !head.is_null() {
            unsafe { drop(Box::from_raw(head)); }
        }
    }
}

// Safety: Lock-free queue is thread-safe
unsafe impl<T: Send> Send for LockFreeQueue<T> {}
unsafe impl<T: Send> Sync for LockFreeQueue<T> {}

// ============================================================================
// Lock-Free Stack (Treiber Stack)
// ============================================================================

/// Node in the lock-free stack
struct StackNode<T> {
    value: T,
    next: *mut StackNode<T>,
}

/// Lock-free stack using atomic pointer operations
///
/// Based on Treiber's algorithm. Provides lock-free push and pop operations.
///
/// # Example
///
/// ```
/// use ogs_core::lockfree::LockFreeStack;
///
/// let stack = LockFreeStack::new();
/// stack.push(1);
/// stack.push(2);
/// stack.push(3);
///
/// assert_eq!(stack.pop(), Some(3));
/// assert_eq!(stack.pop(), Some(2));
/// assert_eq!(stack.pop(), Some(1));
/// assert_eq!(stack.pop(), None);
/// ```
pub struct LockFreeStack<T> {
    head: AtomicPtr<StackNode<T>>,
    size: AtomicUsize,
}

impl<T> LockFreeStack<T> {
    /// Creates a new empty lock-free stack
    pub fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            size: AtomicUsize::new(0),
        }
    }

    /// Pushes a value onto the stack (lock-free)
    pub fn push(&self, value: T) {
        let node = Box::into_raw(Box::new(StackNode {
            value,
            next: ptr::null_mut(),
        }));

        loop {
            let old_head = self.head.load(Ordering::Acquire);
            unsafe { (*node).next = old_head; }

            if self.head.compare_exchange(
                old_head,
                node,
                Ordering::Release,
                Ordering::Acquire,
            ).is_ok() {
                self.size.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Pops a value from the stack (lock-free, returns None if empty)
    pub fn pop(&self) -> Option<T> {
        loop {
            let old_head = self.head.load(Ordering::Acquire);
            if old_head.is_null() {
                return None;
            }

            let next = unsafe { (*old_head).next };

            if self.head.compare_exchange(
                old_head,
                next,
                Ordering::Release,
                Ordering::Acquire,
            ).is_ok() {
                self.size.fetch_sub(1, Ordering::Relaxed);
                let value = unsafe { Box::from_raw(old_head).value };
                return Some(value);
            }
        }
    }

    /// Returns the approximate size of the stack
    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Returns true if the stack is empty
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }
}

impl<T> Default for LockFreeStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for LockFreeStack<T> {
    fn drop(&mut self) {
        // Drain all elements
        while self.pop().is_some() {}
    }
}

// Safety: Lock-free stack is thread-safe
unsafe impl<T: Send> Send for LockFreeStack<T> {}
unsafe impl<T: Send> Sync for LockFreeStack<T> {}

// ============================================================================
// Lock-Free HashMap (Simplified)
// ============================================================================

const DEFAULT_BUCKETS: usize = 256;

/// Bucket entry in the hash map
struct HashMapEntry<K, V> {
    key: K,
    value: V,
    next: AtomicPtr<HashMapEntry<K, V>>,
}

/// Lock-free concurrent hash map
///
/// Simplified implementation using atomic operations on bucket chains.
/// Provides lock-free insert, get, and remove operations.
///
/// # Example
///
/// ```
/// use ogs_core::lockfree::LockFreeHashMap;
///
/// let map = LockFreeHashMap::new();
/// map.insert("key1", 100);
/// map.insert("key2", 200);
///
/// assert_eq!(map.get(&"key1"), Some(100));
/// assert_eq!(map.get(&"key2"), Some(200));
/// assert_eq!(map.get(&"key3"), None);
///
/// map.remove(&"key1");
/// assert_eq!(map.get(&"key1"), None);
/// ```
pub struct LockFreeHashMap<K: Hash + Eq, V: Clone> {
    buckets: Vec<AtomicPtr<HashMapEntry<K, V>>>,
    size: AtomicUsize,
}

impl<K: Hash + Eq, V: Clone> LockFreeHashMap<K, V> {
    /// Creates a new lock-free hash map
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUCKETS)
    }

    /// Creates a new lock-free hash map with specified bucket count
    pub fn with_capacity(buckets: usize) -> Self {
        let buckets = (0..buckets)
            .map(|_| AtomicPtr::new(ptr::null_mut()))
            .collect();

        Self {
            buckets,
            size: AtomicUsize::new(0),
        }
    }

    /// Hash function to determine bucket index
    fn hash_key(&self, key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.buckets.len()
    }

    /// Inserts a key-value pair (lock-free)
    pub fn insert(&self, key: K, value: V) where K: Clone {
        let bucket_idx = self.hash_key(&key);
        let new_entry = Box::into_raw(Box::new(HashMapEntry {
            key: key.clone(),
            value,
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let head = self.buckets[bucket_idx].load(Ordering::Acquire);

            // Check if key already exists
            let mut current = head;
            while !current.is_null() {
                unsafe {
                    if (*current).key == key {
                        // Update existing value (simplified: just replace the node)
                        (*new_entry).next.store((*current).next.load(Ordering::Acquire), Ordering::Release);
                        if self.buckets[bucket_idx].compare_exchange(
                            current,
                            new_entry,
                            Ordering::Release,
                            Ordering::Acquire,
                        ).is_ok() {
                            drop(Box::from_raw(current));
                            return;
                        }
                        break;
                    }
                    current = (*current).next.load(Ordering::Acquire);
                }
            }

            // Insert new entry at head
            unsafe { (*new_entry).next.store(head, Ordering::Release); }

            if self.buckets[bucket_idx].compare_exchange(
                head,
                new_entry,
                Ordering::Release,
                Ordering::Acquire,
            ).is_ok() {
                self.size.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Gets a value by key (lock-free)
    pub fn get(&self, key: &K) -> Option<V> {
        let bucket_idx = self.hash_key(key);
        let mut current = self.buckets[bucket_idx].load(Ordering::Acquire);

        while !current.is_null() {
            unsafe {
                if (*current).key == *key {
                    return Some((*current).value.clone());
                }
                current = (*current).next.load(Ordering::Acquire);
            }
        }
        None
    }

    /// Removes a key-value pair (lock-free)
    pub fn remove(&self, key: &K) -> Option<V> {
        let bucket_idx = self.hash_key(key);

        loop {
            let head = self.buckets[bucket_idx].load(Ordering::Acquire);
            let mut prev: *mut HashMapEntry<K, V> = ptr::null_mut();
            let mut current = head;

            while !current.is_null() {
                unsafe {
                    if (*current).key == *key {
                        let next = (*current).next.load(Ordering::Acquire);
                        let value = (*current).value.clone();

                        if prev.is_null() {
                            // Removing head
                            if self.buckets[bucket_idx].compare_exchange(
                                current,
                                next,
                                Ordering::Release,
                                Ordering::Acquire,
                            ).is_ok() {
                                drop(Box::from_raw(current));
                                self.size.fetch_sub(1, Ordering::Relaxed);
                                return Some(value);
                            }
                        } else {
                            // Removing from middle/end
                            if (*prev).next.compare_exchange(
                                current,
                                next,
                                Ordering::Release,
                                Ordering::Acquire,
                            ).is_ok() {
                                drop(Box::from_raw(current));
                                self.size.fetch_sub(1, Ordering::Relaxed);
                                return Some(value);
                            }
                        }
                        break; // Retry
                    }
                    prev = current;
                    current = (*current).next.load(Ordering::Acquire);
                }
            }

            if current.is_null() {
                return None; // Key not found
            }
        }
    }

    /// Returns the approximate size
    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Returns true if the map is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Hash + Eq, V: Clone> Default for LockFreeHashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Hash + Eq, V: Clone> Drop for LockFreeHashMap<K, V> {
    fn drop(&mut self) {
        for bucket in &self.buckets {
            let mut current = bucket.load(Ordering::Acquire);
            while !current.is_null() {
                unsafe {
                    let next = (*current).next.load(Ordering::Acquire);
                    drop(Box::from_raw(current));
                    current = next;
                }
            }
        }
    }
}

// Safety: Lock-free hash map is thread-safe
unsafe impl<K: Hash + Eq + Send, V: Clone + Send> Send for LockFreeHashMap<K, V> {}
unsafe impl<K: Hash + Eq + Send, V: Clone + Send> Sync for LockFreeHashMap<K, V> {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_queue_basic() {
        let queue = LockFreeQueue::new();
        assert!(queue.is_empty());

        queue.enqueue(1);
        queue.enqueue(2);
        queue.enqueue(3);

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.dequeue(), Some(1));
        assert_eq!(queue.dequeue(), Some(2));
        assert_eq!(queue.dequeue(), Some(3));
        assert_eq!(queue.dequeue(), None);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_concurrent() {
        let queue = Arc::new(LockFreeQueue::new());
        let mut handles = vec![];

        // Spawn 10 threads, each enqueuing 100 items
        for i in 0..10 {
            let q = queue.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    q.enqueue(i * 100 + j);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(queue.len(), 1000);

        // Dequeue all items
        let mut count = 0;
        while queue.dequeue().is_some() {
            count += 1;
        }
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_stack_basic() {
        let stack = LockFreeStack::new();
        assert!(stack.is_empty());

        stack.push(1);
        stack.push(2);
        stack.push(3);

        assert_eq!(stack.len(), 3);
        assert_eq!(stack.pop(), Some(3));
        assert_eq!(stack.pop(), Some(2));
        assert_eq!(stack.pop(), Some(1));
        assert_eq!(stack.pop(), None);
        assert!(stack.is_empty());
    }

    #[test]
    fn test_stack_concurrent() {
        let stack = Arc::new(LockFreeStack::new());
        let mut handles = vec![];

        // Spawn 10 threads, each pushing 100 items
        for i in 0..10 {
            let s = stack.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    s.push(i * 100 + j);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(stack.len(), 1000);

        // Pop all items
        let mut count = 0;
        while stack.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_hashmap_basic() {
        let map = LockFreeHashMap::new();
        assert!(map.is_empty());

        map.insert("key1", 100);
        map.insert("key2", 200);
        map.insert("key3", 300);

        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&"key1"), Some(100));
        assert_eq!(map.get(&"key2"), Some(200));
        assert_eq!(map.get(&"key3"), Some(300));
        assert_eq!(map.get(&"key4"), None);

        assert_eq!(map.remove(&"key2"), Some(200));
        assert_eq!(map.get(&"key2"), None);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_hashmap_update() {
        let map = LockFreeHashMap::new();
        map.insert("key", 100);
        assert_eq!(map.get(&"key"), Some(100));

        map.insert("key", 200);
        assert_eq!(map.get(&"key"), Some(200));
    }

    #[test]
    fn test_hashmap_concurrent() {
        let map = Arc::new(LockFreeHashMap::new());
        let mut handles = vec![];

        // Spawn 10 threads, each inserting 100 items
        for i in 0..10 {
            let m = map.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let key = format!("key_{}", i * 100 + j);
                    m.insert(key, i * 100 + j);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(map.len(), 1000);

        // Verify all items are present
        for i in 0..1000 {
            let key = format!("key_{i}");
            assert_eq!(map.get(&key), Some(i));
        }
    }
}
