//! Doubly-linked list implementation
//!
//! Exact port of lib/core/ogs-list.h

use std::ptr::NonNull;

/// List node - embedded in structures that participate in lists
#[repr(C)]
pub struct OgsLnode {
    pub prev: Option<NonNull<OgsLnode>>,
    pub next: Option<NonNull<OgsLnode>>,
}

impl OgsLnode {
    pub const fn new() -> Self {
        OgsLnode { prev: None, next: None }
    }
}

impl Default for OgsLnode {
    fn default() -> Self {
        Self::new()
    }
}

/// Doubly-linked list head
#[repr(C)]
pub struct OgsList {
    pub prev: Option<NonNull<OgsLnode>>,  // Points to last element
    pub next: Option<NonNull<OgsLnode>>,  // Points to first element
}

impl OgsList {
    pub const fn new() -> Self {
        OgsList { prev: None, next: None }
    }

    pub fn init(&mut self) {
        self.prev = None;
        self.next = None;
    }

    pub fn first(&self) -> Option<NonNull<OgsLnode>> {
        self.next
    }

    pub fn last(&self) -> Option<NonNull<OgsLnode>> {
        self.prev
    }

    pub fn is_empty(&self) -> bool {
        self.next.is_none()
    }

    /// Add node to end of list (identical to ogs_list_add)
    /// 
    /// # Safety
    /// The caller must ensure the node pointer is valid and not already in a list.
    pub unsafe fn add(&mut self, node: NonNull<OgsLnode>) {
        let node_ptr = node.as_ptr();
        (*node_ptr).prev = self.prev;
        (*node_ptr).next = None;
        
        if let Some(prev) = self.prev {
            (*prev.as_ptr()).next = Some(node);
        } else {
            self.next = Some(node);
        }
        self.prev = Some(node);
    }

    /// Add node to beginning of list (identical to ogs_list_prepend)
    /// 
    /// # Safety
    /// The caller must ensure the node pointer is valid and not already in a list.
    pub unsafe fn prepend(&mut self, node: NonNull<OgsLnode>) {
        let node_ptr = node.as_ptr();
        (*node_ptr).prev = None;
        (*node_ptr).next = self.next;
        
        if let Some(next) = self.next {
            (*next.as_ptr()).prev = Some(node);
        } else {
            self.prev = Some(node);
        }
        self.next = Some(node);
    }

    /// Remove node from list (identical to ogs_list_remove)
    /// 
    /// # Safety
    /// The caller must ensure the node is actually in this list.
    pub unsafe fn remove(&mut self, node: NonNull<OgsLnode>) {
        let node_ptr = node.as_ptr();
        let prev = (*node_ptr).prev;
        let next = (*node_ptr).next;

        if let Some(prev_node) = prev {
            (*prev_node.as_ptr()).next = next;
        } else {
            self.next = next;
        }

        if let Some(next_node) = next {
            (*next_node.as_ptr()).prev = prev;
        } else {
            self.prev = prev;
        }

        (*node_ptr).prev = None;
        (*node_ptr).next = None;
    }

    /// Insert node after another node (identical to ogs_list_insert_next)
    /// 
    /// # Safety
    /// The caller must ensure both nodes are valid and `after` is in this list.
    pub unsafe fn insert_next(&mut self, after: NonNull<OgsLnode>, node: NonNull<OgsLnode>) {
        let after_ptr = after.as_ptr();
        let node_ptr = node.as_ptr();
        
        (*node_ptr).prev = Some(after);
        (*node_ptr).next = (*after_ptr).next;
        
        if let Some(next) = (*after_ptr).next {
            (*next.as_ptr()).prev = Some(node);
        } else {
            self.prev = Some(node);
        }
        (*after_ptr).next = Some(node);
    }

    /// Insert node before another node (identical to ogs_list_insert_prev)
    /// 
    /// # Safety
    /// The caller must ensure both nodes are valid and `before` is in this list.
    pub unsafe fn insert_prev(&mut self, before: NonNull<OgsLnode>, node: NonNull<OgsLnode>) {
        let before_ptr = before.as_ptr();
        let node_ptr = node.as_ptr();
        
        (*node_ptr).next = Some(before);
        (*node_ptr).prev = (*before_ptr).prev;
        
        if let Some(prev) = (*before_ptr).prev {
            (*prev.as_ptr()).next = Some(node);
        } else {
            self.next = Some(node);
        }
        (*before_ptr).prev = Some(node);
    }

    pub fn count(&self) -> usize {
        let mut count = 0;
        let mut current = self.next;
        while let Some(node) = current {
            count += 1;
            current = unsafe { (*node.as_ptr()).next };
        }
        count
    }
}

impl Default for OgsList {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over list nodes
pub struct OgsListIter {
    current: Option<NonNull<OgsLnode>>,
}

impl Iterator for OgsListIter {
    type Item = NonNull<OgsLnode>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        self.current = unsafe { (*current.as_ptr()).next };
        Some(current)
    }
}

impl OgsList {
    /// Copy list pointers from another list (identical to ogs_list_copy)
    pub fn copy_from(&mut self, src: &OgsList) {
        self.prev = src.prev;
        self.next = src.next;
    }

    /// Check if a node exists in the list (identical to ogs_list_exists)
    /// 
    /// # Safety
    /// The caller must ensure the node pointer is valid.
    pub unsafe fn exists(&self, node: NonNull<OgsLnode>) -> bool {
        let mut current = self.next;
        while let Some(iter) = current {
            if iter == node {
                return true;
            }
            current = (*iter.as_ptr()).next;
        }
        false
    }

    /// Get an iterator over the list nodes
    pub fn iter(&self) -> OgsListIter {
        OgsListIter { current: self.next }
    }

    /// Get the next node after the given node (identical to ogs_list_next)
    /// 
    /// # Safety
    /// The caller must ensure the node pointer is valid.
    pub unsafe fn next_node(node: NonNull<OgsLnode>) -> Option<NonNull<OgsLnode>> {
        (*node.as_ptr()).next
    }

    /// Get the previous node before the given node (identical to ogs_list_prev)
    /// 
    /// # Safety
    /// The caller must ensure the node pointer is valid.
    pub unsafe fn prev_node(node: NonNull<OgsLnode>) -> Option<NonNull<OgsLnode>> {
        (*node.as_ptr()).prev
    }

    /// Insert node in sorted order using a comparison function
    /// (identical to ogs_list_insert_sorted)
    /// 
    /// # Safety
    /// The caller must ensure the node pointer is valid and not already in a list.
    pub unsafe fn insert_sorted<F>(&mut self, node: NonNull<OgsLnode>, compare: F)
    where
        F: Fn(NonNull<OgsLnode>, NonNull<OgsLnode>) -> std::cmp::Ordering,
    {
        let mut current = self.next;
        while let Some(iter) = current {
            if compare(node, iter) == std::cmp::Ordering::Less {
                self.insert_prev(iter, node);
                return;
            }
            current = (*iter.as_ptr()).next;
        }
        // If we get here, add to end
        self.add(node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct TestNode {
        lnode: OgsLnode,
        value: i32,
    }

    impl TestNode {
        fn new(value: i32) -> Self {
            TestNode {
                lnode: OgsLnode::new(),
                value,
            }
        }
    }

    #[test]
    fn test_list_init() {
        let list = OgsList::new();
        assert!(list.is_empty());
        assert_eq!(list.count(), 0);
        assert!(list.first().is_none());
        assert!(list.last().is_none());
    }

    #[test]
    fn test_list_add() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.add(NonNull::new(&mut node1.lnode).unwrap());
            assert_eq!(list.count(), 1);
            assert_eq!(list.first(), NonNull::new(&mut node1.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node1.lnode));

            list.add(NonNull::new(&mut node2.lnode).unwrap());
            assert_eq!(list.count(), 2);
            assert_eq!(list.first(), NonNull::new(&mut node1.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node2.lnode));

            list.add(NonNull::new(&mut node3.lnode).unwrap());
            assert_eq!(list.count(), 3);
            assert_eq!(list.first(), NonNull::new(&mut node1.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node3.lnode));
        }
    }

    #[test]
    fn test_list_prepend() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.prepend(NonNull::new(&mut node1.lnode).unwrap());
            assert_eq!(list.count(), 1);
            assert_eq!(list.first(), NonNull::new(&mut node1.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node1.lnode));

            list.prepend(NonNull::new(&mut node2.lnode).unwrap());
            assert_eq!(list.count(), 2);
            assert_eq!(list.first(), NonNull::new(&mut node2.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node1.lnode));

            list.prepend(NonNull::new(&mut node3.lnode).unwrap());
            assert_eq!(list.count(), 3);
            assert_eq!(list.first(), NonNull::new(&mut node3.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node1.lnode));
        }
    }

    #[test]
    fn test_list_remove() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.add(NonNull::new(&mut node1.lnode).unwrap());
            list.add(NonNull::new(&mut node2.lnode).unwrap());
            list.add(NonNull::new(&mut node3.lnode).unwrap());

            // Remove middle
            list.remove(NonNull::new(&mut node2.lnode).unwrap());
            assert_eq!(list.count(), 2);
            assert_eq!(list.first(), NonNull::new(&mut node1.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node3.lnode));

            // Remove first
            list.remove(NonNull::new(&mut node1.lnode).unwrap());
            assert_eq!(list.count(), 1);
            assert_eq!(list.first(), NonNull::new(&mut node3.lnode));
            assert_eq!(list.last(), NonNull::new(&mut node3.lnode));

            // Remove last
            list.remove(NonNull::new(&mut node3.lnode).unwrap());
            assert!(list.is_empty());
        }
    }

    #[test]
    fn test_list_insert_prev() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.add(NonNull::new(&mut node1.lnode).unwrap());
            list.add(NonNull::new(&mut node3.lnode).unwrap());

            // Insert node2 before node3
            list.insert_prev(
                NonNull::new(&mut node3.lnode).unwrap(),
                NonNull::new(&mut node2.lnode).unwrap(),
            );

            assert_eq!(list.count(), 3);
            
            // Verify order: node1 -> node2 -> node3
            let first = list.first().unwrap();
            let second = OgsList::next_node(first).unwrap();
            let third = OgsList::next_node(second).unwrap();
            
            assert_eq!(first, NonNull::new(&mut node1.lnode).unwrap());
            assert_eq!(second, NonNull::new(&mut node2.lnode).unwrap());
            assert_eq!(third, NonNull::new(&mut node3.lnode).unwrap());
        }
    }

    #[test]
    fn test_list_insert_next() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.add(NonNull::new(&mut node1.lnode).unwrap());
            list.add(NonNull::new(&mut node3.lnode).unwrap());

            // Insert node2 after node1
            list.insert_next(
                NonNull::new(&mut node1.lnode).unwrap(),
                NonNull::new(&mut node2.lnode).unwrap(),
            );

            assert_eq!(list.count(), 3);
            
            // Verify order: node1 -> node2 -> node3
            let first = list.first().unwrap();
            let second = OgsList::next_node(first).unwrap();
            let third = OgsList::next_node(second).unwrap();
            
            assert_eq!(first, NonNull::new(&mut node1.lnode).unwrap());
            assert_eq!(second, NonNull::new(&mut node2.lnode).unwrap());
            assert_eq!(third, NonNull::new(&mut node3.lnode).unwrap());
        }
    }

    #[test]
    fn test_list_exists() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.add(NonNull::new(&mut node1.lnode).unwrap());
            list.add(NonNull::new(&mut node2.lnode).unwrap());

            assert!(list.exists(NonNull::new(&mut node1.lnode).unwrap()));
            assert!(list.exists(NonNull::new(&mut node2.lnode).unwrap()));
            assert!(!list.exists(NonNull::new(&mut node3.lnode).unwrap()));
        }
    }

    #[test]
    fn test_list_insert_sorted() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);
        let mut node4 = TestNode::new(4);

        unsafe {
            // Insert in random order, should end up sorted
            list.insert_sorted(NonNull::new(&mut node3.lnode).unwrap(), |a, b| {
                let a_val = &*(a.as_ptr() as *const TestNode);
                let b_val = &*(b.as_ptr() as *const TestNode);
                a_val.value.cmp(&b_val.value)
            });

            list.insert_sorted(NonNull::new(&mut node1.lnode).unwrap(), |a, b| {
                let a_val = &*(a.as_ptr() as *const TestNode);
                let b_val = &*(b.as_ptr() as *const TestNode);
                a_val.value.cmp(&b_val.value)
            });

            list.insert_sorted(NonNull::new(&mut node4.lnode).unwrap(), |a, b| {
                let a_val = &*(a.as_ptr() as *const TestNode);
                let b_val = &*(b.as_ptr() as *const TestNode);
                a_val.value.cmp(&b_val.value)
            });

            list.insert_sorted(NonNull::new(&mut node2.lnode).unwrap(), |a, b| {
                let a_val = &*(a.as_ptr() as *const TestNode);
                let b_val = &*(b.as_ptr() as *const TestNode);
                a_val.value.cmp(&b_val.value)
            });

            assert_eq!(list.count(), 4);
            
            // Verify order: 1 -> 2 -> 3 -> 4
            let first = list.first().unwrap();
            let second = OgsList::next_node(first).unwrap();
            let third = OgsList::next_node(second).unwrap();
            let fourth = OgsList::next_node(third).unwrap();
            
            assert_eq!(first, NonNull::new(&mut node1.lnode).unwrap());
            assert_eq!(second, NonNull::new(&mut node2.lnode).unwrap());
            assert_eq!(third, NonNull::new(&mut node3.lnode).unwrap());
            assert_eq!(fourth, NonNull::new(&mut node4.lnode).unwrap());
        }
    }

    #[test]
    fn test_list_iter() {
        let mut list = OgsList::new();
        let mut node1 = TestNode::new(1);
        let mut node2 = TestNode::new(2);
        let mut node3 = TestNode::new(3);

        unsafe {
            list.add(NonNull::new(&mut node1.lnode).unwrap());
            list.add(NonNull::new(&mut node2.lnode).unwrap());
            list.add(NonNull::new(&mut node3.lnode).unwrap());
        }

        let nodes: Vec<_> = list.iter().collect();
        assert_eq!(nodes.len(), 3);
    }
}


#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;

    /// Property 1: Linked List Operation Equivalence
    /// For all sequences of linked list operations (add, remove, prepend, insert_prev, insert_next),
    /// the resulting list state in Rust SHALL be identical to a reference implementation.
    /// **Validates: Requirements 1.2**

    #[derive(Debug, Clone)]
    enum ListOp {
        Add(i32),
        Prepend(i32),
        RemoveFirst,
        RemoveLast,
        RemoveAt(usize),
        InsertPrevAt(usize, i32),
        InsertNextAt(usize, i32),
    }

    fn arb_list_op() -> impl Strategy<Value = ListOp> {
        prop_oneof![
            any::<i32>().prop_map(ListOp::Add),
            any::<i32>().prop_map(ListOp::Prepend),
            Just(ListOp::RemoveFirst),
            Just(ListOp::RemoveLast),
            (0usize..100).prop_map(ListOp::RemoveAt),
            ((0usize..100), any::<i32>()).prop_map(|(idx, val)| ListOp::InsertPrevAt(idx, val)),
            ((0usize..100), any::<i32>()).prop_map(|(idx, val)| ListOp::InsertNextAt(idx, val)),
        ]
    }

    /// Reference implementation using VecDeque for comparison
    fn apply_op_to_reference(reference: &mut VecDeque<i32>, op: &ListOp) {
        match op {
            ListOp::Add(val) => {
                reference.push_back(*val);
            }
            ListOp::Prepend(val) => {
                reference.push_front(*val);
            }
            ListOp::RemoveFirst => {
                reference.pop_front();
            }
            ListOp::RemoveLast => {
                reference.pop_back();
            }
            ListOp::RemoveAt(idx) => {
                if !reference.is_empty() {
                    let actual_idx = idx % reference.len();
                    reference.remove(actual_idx);
                }
            }
            ListOp::InsertPrevAt(idx, val) => {
                if reference.is_empty() {
                    reference.push_back(*val);
                } else {
                    let actual_idx = idx % reference.len();
                    reference.insert(actual_idx, *val);
                }
            }
            ListOp::InsertNextAt(idx, val) => {
                if reference.is_empty() {
                    reference.push_back(*val);
                } else {
                    let actual_idx = idx % reference.len();
                    reference.insert(actual_idx + 1, *val);
                }
            }
        }
    }

    /// Node storage for property tests
    struct NodeStorage {
        nodes: Vec<Box<TestNodeProp>>,
    }

    #[repr(C)]
    struct TestNodeProp {
        lnode: OgsLnode,
        value: i32,
    }

    impl NodeStorage {
        fn new() -> Self {
            NodeStorage { nodes: Vec::new() }
        }

        fn add_node(&mut self, value: i32) -> NonNull<OgsLnode> {
            let node = Box::new(TestNodeProp {
                lnode: OgsLnode::new(),
                value,
            });
            let ptr = NonNull::new(&node.lnode as *const _ as *mut OgsLnode).unwrap();
            self.nodes.push(node);
            ptr
        }

        fn get_node_ptr(&self, idx: usize) -> Option<NonNull<OgsLnode>> {
            self.nodes.get(idx).map(|n| {
                NonNull::new(&n.lnode as *const _ as *mut OgsLnode).unwrap()
            })
        }
    }

    /// Extract values from list in order
    fn extract_list_values(list: &OgsList, storage: &NodeStorage) -> Vec<i32> {
        let mut values = Vec::new();
        let mut current = list.first();
        while let Some(node) = current {
            // Find the value by matching the node pointer
            for stored in &storage.nodes {
                let stored_ptr = NonNull::new(&stored.lnode as *const _ as *mut OgsLnode).unwrap();
                if stored_ptr == node {
                    values.push(stored.value);
                    break;
                }
            }
            current = unsafe { (*node.as_ptr()).next };
        }
        values
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Feature: nextgcore-rust-conversion, Property 1: Linked List Operation Equivalence
        /// For all sequences of operations, the Rust list maintains identical state to reference.
        /// **Validates: Requirements 1.2**
        #[test]
        fn prop_list_operations_equivalence(ops in proptest::collection::vec(arb_list_op(), 0..50)) {
            let mut list = OgsList::new();
            let mut reference: VecDeque<i32> = VecDeque::new();
            let mut storage = NodeStorage::new();
            let mut list_node_indices: Vec<usize> = Vec::new(); // Track which storage indices are in list

            for op in &ops {
                match op {
                    ListOp::Add(val) => {
                        let node_ptr = storage.add_node(*val);
                        let node_idx = storage.nodes.len() - 1;
                        unsafe { list.add(node_ptr); }
                        list_node_indices.push(node_idx);
                        apply_op_to_reference(&mut reference, op);
                    }
                    ListOp::Prepend(val) => {
                        let node_ptr = storage.add_node(*val);
                        let node_idx = storage.nodes.len() - 1;
                        unsafe { list.prepend(node_ptr); }
                        list_node_indices.insert(0, node_idx);
                        apply_op_to_reference(&mut reference, op);
                    }
                    ListOp::RemoveFirst => {
                        if !list_node_indices.is_empty() {
                            let node_idx = list_node_indices.remove(0);
                            if let Some(node_ptr) = storage.get_node_ptr(node_idx) {
                                unsafe { list.remove(node_ptr); }
                            }
                            apply_op_to_reference(&mut reference, op);
                        }
                    }
                    ListOp::RemoveLast => {
                        if !list_node_indices.is_empty() {
                            let node_idx = list_node_indices.pop().unwrap();
                            if let Some(node_ptr) = storage.get_node_ptr(node_idx) {
                                unsafe { list.remove(node_ptr); }
                            }
                            apply_op_to_reference(&mut reference, op);
                        }
                    }
                    ListOp::RemoveAt(idx) => {
                        if !list_node_indices.is_empty() {
                            let actual_idx = idx % list_node_indices.len();
                            let node_idx = list_node_indices.remove(actual_idx);
                            if let Some(node_ptr) = storage.get_node_ptr(node_idx) {
                                unsafe { list.remove(node_ptr); }
                            }
                            apply_op_to_reference(&mut reference, op);
                        }
                    }
                    ListOp::InsertPrevAt(idx, val) => {
                        let node_ptr = storage.add_node(*val);
                        let new_node_idx = storage.nodes.len() - 1;
                        
                        if list_node_indices.is_empty() {
                            unsafe { list.add(node_ptr); }
                            list_node_indices.push(new_node_idx);
                        } else {
                            let actual_idx = idx % list_node_indices.len();
                            let before_node_idx = list_node_indices[actual_idx];
                            if let Some(before_ptr) = storage.get_node_ptr(before_node_idx) {
                                unsafe { list.insert_prev(before_ptr, node_ptr); }
                                list_node_indices.insert(actual_idx, new_node_idx);
                            }
                        }
                        apply_op_to_reference(&mut reference, op);
                    }
                    ListOp::InsertNextAt(idx, val) => {
                        let node_ptr = storage.add_node(*val);
                        let new_node_idx = storage.nodes.len() - 1;
                        
                        if list_node_indices.is_empty() {
                            unsafe { list.add(node_ptr); }
                            list_node_indices.push(new_node_idx);
                        } else {
                            let actual_idx = idx % list_node_indices.len();
                            let after_node_idx = list_node_indices[actual_idx];
                            if let Some(after_ptr) = storage.get_node_ptr(after_node_idx) {
                                unsafe { list.insert_next(after_ptr, node_ptr); }
                                list_node_indices.insert(actual_idx + 1, new_node_idx);
                            }
                        }
                        apply_op_to_reference(&mut reference, op);
                    }
                }

                // Verify count matches
                prop_assert_eq!(list.count(), reference.len(), 
                    "Count mismatch after {:?}", op);
            }

            // Final verification: extract all values and compare
            let list_values = extract_list_values(&list, &storage);
            let reference_values: Vec<i32> = reference.iter().copied().collect();
            prop_assert_eq!(list_values, reference_values, 
                "Final list values don't match reference");
        }

        /// Property: List count is always non-negative and matches actual node count
        #[test]
        fn prop_list_count_invariant(ops in proptest::collection::vec(arb_list_op(), 0..30)) {
            let mut list = OgsList::new();
            let mut storage = NodeStorage::new();
            let mut expected_count = 0usize;
            let mut list_node_indices: Vec<usize> = Vec::new();

            for op in &ops {
                match op {
                    ListOp::Add(val) => {
                        let node_ptr = storage.add_node(*val);
                        let node_idx = storage.nodes.len() - 1;
                        unsafe { list.add(node_ptr); }
                        list_node_indices.push(node_idx);
                        expected_count += 1;
                    }
                    ListOp::Prepend(val) => {
                        let node_ptr = storage.add_node(*val);
                        let node_idx = storage.nodes.len() - 1;
                        unsafe { list.prepend(node_ptr); }
                        list_node_indices.insert(0, node_idx);
                        expected_count += 1;
                    }
                    ListOp::RemoveFirst | ListOp::RemoveLast => {
                        if !list_node_indices.is_empty() {
                            let node_idx = if matches!(op, ListOp::RemoveFirst) {
                                list_node_indices.remove(0)
                            } else {
                                list_node_indices.pop().unwrap()
                            };
                            if let Some(node_ptr) = storage.get_node_ptr(node_idx) {
                                unsafe { list.remove(node_ptr); }
                            }
                            expected_count -= 1;
                        }
                    }
                    ListOp::RemoveAt(idx) => {
                        if !list_node_indices.is_empty() {
                            let actual_idx = idx % list_node_indices.len();
                            let node_idx = list_node_indices.remove(actual_idx);
                            if let Some(node_ptr) = storage.get_node_ptr(node_idx) {
                                unsafe { list.remove(node_ptr); }
                            }
                            expected_count -= 1;
                        }
                    }
                    ListOp::InsertPrevAt(idx, val) | ListOp::InsertNextAt(idx, val) => {
                        let node_ptr = storage.add_node(*val);
                        let new_node_idx = storage.nodes.len() - 1;
                        
                        if list_node_indices.is_empty() {
                            unsafe { list.add(node_ptr); }
                            list_node_indices.push(new_node_idx);
                        } else {
                            let actual_idx = idx % list_node_indices.len();
                            let ref_node_idx = list_node_indices[actual_idx];
                            if let Some(ref_ptr) = storage.get_node_ptr(ref_node_idx) {
                                if matches!(op, ListOp::InsertPrevAt(_, _)) {
                                    unsafe { list.insert_prev(ref_ptr, node_ptr); }
                                    list_node_indices.insert(actual_idx, new_node_idx);
                                } else {
                                    unsafe { list.insert_next(ref_ptr, node_ptr); }
                                    list_node_indices.insert(actual_idx + 1, new_node_idx);
                                }
                            }
                        }
                        expected_count += 1;
                    }
                }

                prop_assert_eq!(list.count(), expected_count, 
                    "Count invariant violated after {:?}", op);
                prop_assert_eq!(list.is_empty(), expected_count == 0,
                    "is_empty() inconsistent with count after {:?}", op);
            }
        }

        /// Property: First and last pointers are consistent with list state
        #[test]
        fn prop_list_first_last_consistency(adds in proptest::collection::vec(any::<i32>(), 0..20)) {
            let mut list = OgsList::new();
            let mut storage = NodeStorage::new();

            // Empty list should have None for first and last
            prop_assert!(list.first().is_none());
            prop_assert!(list.last().is_none());

            for val in &adds {
                let node_ptr = storage.add_node(*val);
                unsafe { list.add(node_ptr); }
            }

            if adds.is_empty() {
                prop_assert!(list.first().is_none());
                prop_assert!(list.last().is_none());
            } else {
                prop_assert!(list.first().is_some());
                prop_assert!(list.last().is_some());
                
                // First node's prev should be None
                if let Some(first) = list.first() {
                    let prev_is_none = unsafe { (*first.as_ptr()).prev.is_none() };
                    prop_assert!(prev_is_none, "First node's prev should be None");
                }
                
                // Last node's next should be None
                if let Some(last) = list.last() {
                    let next_is_none = unsafe { (*last.as_ptr()).next.is_none() };
                    prop_assert!(next_is_none, "Last node's next should be None");
                }
            }
        }
    }
}
