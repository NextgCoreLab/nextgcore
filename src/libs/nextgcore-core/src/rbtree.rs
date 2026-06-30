//! Red-Black Tree implementation
//!
//! Exact port of lib/core/nextgcore-rbtree.h and nextgcore-rbtree.c
//!
//! This is an intrusive red-black tree implementation where nodes
//! are embedded in user structures.

use std::ptr;

/// Node color
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NextgcoreRbtreeColor {
    #[default]
    Black = 0,
    Red = 1,
}

/// Red-black tree node (intrusive)
#[derive(Debug)]
pub struct NextgcoreRbnode {
    pub parent: *mut NextgcoreRbnode,
    pub left: *mut NextgcoreRbnode,
    pub right: *mut NextgcoreRbnode,
    pub color: NextgcoreRbtreeColor,
}

impl Default for NextgcoreRbnode {
    fn default() -> Self {
        NextgcoreRbnode {
            parent: ptr::null_mut(),
            left: ptr::null_mut(),
            right: ptr::null_mut(),
            color: NextgcoreRbtreeColor::Black,
        }
    }
}

impl NextgcoreRbnode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if node is empty (parent points to self)
    pub fn is_empty(&self) -> bool {
        std::ptr::eq(self.parent, self)
    }
}

/// Red-black tree
#[derive(Debug)]
pub struct NextgcoreRbtree {
    pub root: *mut NextgcoreRbnode,
}

impl Default for NextgcoreRbtree {
    fn default() -> Self {
        NextgcoreRbtree {
            root: std::ptr::null_mut(),
        }
    }
}

impl NextgcoreRbtree {
    pub fn new() -> Self {
        NextgcoreRbtree {
            root: ptr::null_mut(),
        }
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.root.is_null()
    }

    /// Link a node into the tree at the specified position
    ///
    /// # Safety
    /// - `node` must be a valid pointer to an NextgcoreRbnode
    /// - `parent` must be null or a valid pointer to an NextgcoreRbnode in this tree
    /// - `link` must be a valid pointer to either parent->left or parent->right
    pub unsafe fn link_node(
        node: *mut NextgcoreRbnode,
        parent: *mut NextgcoreRbnode,
        link: *mut *mut NextgcoreRbnode,
    ) {
        (*node).parent = parent;
        (*node).left = ptr::null_mut();
        (*node).right = ptr::null_mut();
        (*node).color = NextgcoreRbtreeColor::Red;
        *link = node;
    }

    /// Rebalance tree after insertion
    ///
    /// # Safety
    /// `node` must be a valid pointer to a node that was just linked into the tree
    pub unsafe fn insert_color(&mut self, node: *mut NextgcoreRbnode) {
        let mut node = node;

        while !(*node).parent.is_null() && (*(*node).parent).color == NextgcoreRbtreeColor::Red {
            let parent = (*node).parent;
            let gparent = (*parent).parent;

            if gparent.is_null() {
                break;
            }

            if parent == (*gparent).left {
                let uncle = (*gparent).right;

                if !uncle.is_null() && (*uncle).color == NextgcoreRbtreeColor::Red {
                    // Case 1: Uncle is red - color flip
                    (*uncle).color = NextgcoreRbtreeColor::Black;
                    (*parent).color = NextgcoreRbtreeColor::Black;
                    (*gparent).color = NextgcoreRbtreeColor::Red;
                    node = gparent;
                } else {
                    // Uncle is black
                    if node == (*parent).right {
                        // Case 2: Node is right child - left rotate at parent
                        node = parent;
                        self.rotate_left(node);
                    }
                    // Case 3: Node is left child - right rotate at grandparent
                    (*(*node).parent).color = NextgcoreRbtreeColor::Black;
                    (*gparent).color = NextgcoreRbtreeColor::Red;
                    self.rotate_right(gparent);
                }
            } else {
                let uncle = (*gparent).left;

                if !uncle.is_null() && (*uncle).color == NextgcoreRbtreeColor::Red {
                    // Case 1: Uncle is red - color flip
                    (*uncle).color = NextgcoreRbtreeColor::Black;
                    (*parent).color = NextgcoreRbtreeColor::Black;
                    (*gparent).color = NextgcoreRbtreeColor::Red;
                    node = gparent;
                } else {
                    // Uncle is black
                    if node == (*parent).left {
                        // Case 2: Node is left child - right rotate at parent
                        node = parent;
                        self.rotate_right(node);
                    }
                    // Case 3: Node is right child - left rotate at grandparent
                    (*(*node).parent).color = NextgcoreRbtreeColor::Black;
                    (*gparent).color = NextgcoreRbtreeColor::Red;
                    self.rotate_left(gparent);
                }
            }
        }

        if !self.root.is_null() {
            (*self.root).color = NextgcoreRbtreeColor::Black;
        }
    }

    /// Delete a node from the tree
    ///
    /// # Safety
    /// `node` must be a valid pointer to a node in this tree
    pub unsafe fn delete(&mut self, node: *mut NextgcoreRbnode) {
        let child: *mut NextgcoreRbnode;
        let parent: *mut NextgcoreRbnode;
        let color: NextgcoreRbtreeColor;

        if (*node).left.is_null() {
            child = (*node).right;
            parent = (*node).parent;
            color = (*node).color;
            self.replace_node(node, child, parent);
        } else if (*node).right.is_null() {
            child = (*node).left;
            parent = (*node).parent;
            color = (*node).color;
            self.replace_node(node, child, parent);
        } else {
            let successor = self.min((*node).right);
            child = (*successor).right;
            let mut new_parent = (*successor).parent;
            color = (*successor).color;

            (*successor).left = (*node).left;
            (*(*node).left).parent = successor;

            if new_parent == node {
                new_parent = successor;
            } else {
                if !child.is_null() {
                    (*child).parent = new_parent;
                }
                (*new_parent).left = child;
                (*successor).right = (*node).right;
                (*(*node).right).parent = successor;
            }

            (*successor).color = (*node).color;
            self.replace_node(node, successor, (*node).parent);

            // Use the correct parent for delete_color
            if color == NextgcoreRbtreeColor::Black {
                self.delete_color(child, new_parent);
            }
            return;
        }

        if color == NextgcoreRbtreeColor::Black {
            self.delete_color(child, parent);
        }
    }

    /// Get the first (minimum) node in the tree
    pub fn first(&self) -> *mut NextgcoreRbnode {
        if self.root.is_null() {
            return ptr::null_mut();
        }
        unsafe { self.min(self.root) }
    }

    /// Get the last (maximum) node in the tree
    pub fn last(&self) -> *mut NextgcoreRbnode {
        if self.root.is_null() {
            return ptr::null_mut();
        }
        unsafe { self.max(self.root) }
    }

    /// Get the next node in order
    ///
    /// # Safety
    /// `node` must be a valid pointer to a node in this tree
    pub unsafe fn next(&self, node: *mut NextgcoreRbnode) -> *mut NextgcoreRbnode {
        if node.is_null() {
            return ptr::null_mut();
        }

        // Check if node is empty (parent points to self)
        if (*node).parent == node {
            return ptr::null_mut();
        }

        if !(*node).right.is_null() {
            return self.min((*node).right);
        }

        let mut current = node;
        let mut parent = (*current).parent;
        while !parent.is_null() && current == (*parent).right {
            current = parent;
            parent = (*current).parent;
        }
        parent
    }

    /// Get the previous node in order
    ///
    /// # Safety
    /// `node` must be a valid pointer to a node in this tree
    pub unsafe fn prev(&self, node: *mut NextgcoreRbnode) -> *mut NextgcoreRbnode {
        if node.is_null() {
            return ptr::null_mut();
        }

        // Check if node is empty (parent points to self)
        if (*node).parent == node {
            return ptr::null_mut();
        }

        if !(*node).left.is_null() {
            return self.max((*node).left);
        }

        let mut current = node;
        let mut parent = (*current).parent;
        while !parent.is_null() && current == (*parent).left {
            current = parent;
            parent = (*current).parent;
        }
        parent
    }

    /// Count nodes in the tree
    pub fn count(&self) -> usize {
        let mut count = 0;
        let mut node = self.first();
        while !node.is_null() {
            count += 1;
            node = unsafe { self.next(node) };
        }
        count
    }

    // Private helper methods

    unsafe fn min(&self, node: *mut NextgcoreRbnode) -> *mut NextgcoreRbnode {
        let mut current = node;
        while !(*current).left.is_null() {
            current = (*current).left;
        }
        current
    }

    unsafe fn max(&self, node: *mut NextgcoreRbnode) -> *mut NextgcoreRbnode {
        let mut current = node;
        while !(*current).right.is_null() {
            current = (*current).right;
        }
        current
    }

    unsafe fn change_child(
        &mut self,
        old: *mut NextgcoreRbnode,
        new: *mut NextgcoreRbnode,
        parent: *mut NextgcoreRbnode,
    ) {
        if parent.is_null() {
            self.root = new;
        } else if old == (*parent).left {
            (*parent).left = new;
        } else {
            (*parent).right = new;
        }
    }

    unsafe fn replace_node(
        &mut self,
        old: *mut NextgcoreRbnode,
        new: *mut NextgcoreRbnode,
        parent: *mut NextgcoreRbnode,
    ) {
        self.change_child(old, new, parent);
        if !new.is_null() {
            (*new).parent = parent;
        }
    }

    unsafe fn rotate_left(&mut self, node: *mut NextgcoreRbnode) {
        let right = (*node).right;
        (*node).right = (*right).left;
        if !(*right).left.is_null() {
            (*(*right).left).parent = node;
        }
        self.replace_node(node, right, (*node).parent);
        (*right).left = node;
        (*node).parent = right;
    }

    unsafe fn rotate_right(&mut self, node: *mut NextgcoreRbnode) {
        let left = (*node).left;
        (*node).left = (*left).right;
        if !(*left).right.is_null() {
            (*(*left).right).parent = node;
        }
        self.replace_node(node, left, (*node).parent);
        (*left).right = node;
        (*node).parent = left;
    }

    unsafe fn delete_color(&mut self, mut node: *mut NextgcoreRbnode, mut parent: *mut NextgcoreRbnode) {
        fn is_black(node: *mut NextgcoreRbnode) -> bool {
            node.is_null() || unsafe { (*node).color == NextgcoreRbtreeColor::Black }
        }

        while node != self.root && is_black(node) {
            if parent.is_null() {
                break;
            }

            if node == (*parent).left {
                let mut sibling = (*parent).right;
                if sibling.is_null() {
                    break;
                }

                if (*sibling).color == NextgcoreRbtreeColor::Red {
                    (*sibling).color = NextgcoreRbtreeColor::Black;
                    (*parent).color = NextgcoreRbtreeColor::Red;
                    self.rotate_left(parent);
                    sibling = (*parent).right;
                    if sibling.is_null() {
                        break;
                    }
                }

                if is_black((*sibling).left) && is_black((*sibling).right) {
                    (*sibling).color = NextgcoreRbtreeColor::Red;
                    node = parent;
                    parent = (*node).parent;
                } else {
                    if is_black((*sibling).right) {
                        if !(*sibling).left.is_null() {
                            (*(*sibling).left).color = NextgcoreRbtreeColor::Black;
                        }
                        (*sibling).color = NextgcoreRbtreeColor::Red;
                        self.rotate_right(sibling);
                        sibling = (*parent).right;
                    }
                    if !sibling.is_null() {
                        (*sibling).color = (*parent).color;
                        (*parent).color = NextgcoreRbtreeColor::Black;
                        if !(*sibling).right.is_null() {
                            (*(*sibling).right).color = NextgcoreRbtreeColor::Black;
                        }
                        self.rotate_left(parent);
                    }
                    node = self.root;
                    break;
                }
            } else {
                let mut sibling = (*parent).left;
                if sibling.is_null() {
                    break;
                }

                if (*sibling).color == NextgcoreRbtreeColor::Red {
                    (*sibling).color = NextgcoreRbtreeColor::Black;
                    (*parent).color = NextgcoreRbtreeColor::Red;
                    self.rotate_right(parent);
                    sibling = (*parent).left;
                    if sibling.is_null() {
                        break;
                    }
                }

                if is_black((*sibling).left) && is_black((*sibling).right) {
                    (*sibling).color = NextgcoreRbtreeColor::Red;
                    node = parent;
                    parent = (*node).parent;
                } else {
                    if is_black((*sibling).left) {
                        if !(*sibling).right.is_null() {
                            (*(*sibling).right).color = NextgcoreRbtreeColor::Black;
                        }
                        (*sibling).color = NextgcoreRbtreeColor::Red;
                        self.rotate_left(sibling);
                        sibling = (*parent).left;
                    }
                    if !sibling.is_null() {
                        (*sibling).color = (*parent).color;
                        (*parent).color = NextgcoreRbtreeColor::Black;
                        if !(*sibling).left.is_null() {
                            (*(*sibling).left).color = NextgcoreRbtreeColor::Black;
                        }
                        self.rotate_right(parent);
                    }
                    node = self.root;
                    break;
                }
            }
        }

        if !node.is_null() {
            (*node).color = NextgcoreRbtreeColor::Black;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test node that embeds NextgcoreRbnode
    struct TestNode {
        rb: NextgcoreRbnode,
        key: i32,
    }

    impl TestNode {
        fn new(key: i32) -> Box<Self> {
            Box::new(TestNode {
                rb: NextgcoreRbnode::new(),
                key,
            })
        }
    }

    #[test]
    fn test_rbtree_new() {
        let tree = NextgcoreRbtree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.count(), 0);
    }

    #[test]
    fn test_rbtree_insert_single() {
        let mut tree = NextgcoreRbtree::new();
        let mut node = TestNode::new(10);

        unsafe {
            NextgcoreRbtree::link_node(&mut node.rb, ptr::null_mut(), &mut tree.root);
            tree.insert_color(&mut node.rb);
        }

        assert!(!tree.is_empty());
        assert_eq!(tree.count(), 1);

        // Root should be black
        unsafe {
            assert_eq!((*tree.root).color, NextgcoreRbtreeColor::Black);
        }
    }

    #[test]
    fn test_rbtree_insert_multiple() {
        let mut tree = NextgcoreRbtree::new();
        let mut nodes: Vec<Box<TestNode>> = (0..10).map(TestNode::new).collect();

        for node in &mut nodes {
            unsafe {
                // Find insertion point
                let mut parent: *mut NextgcoreRbnode = ptr::null_mut();
                let mut link: *mut *mut NextgcoreRbnode = &mut tree.root;

                while !(*link).is_null() {
                    parent = *link;
                    let parent_node = &*(parent as *const TestNode);
                    if node.key < parent_node.key {
                        link = &mut (*parent).left;
                    } else {
                        link = &mut (*parent).right;
                    }
                }

                NextgcoreRbtree::link_node(&mut node.rb, parent, link);
                tree.insert_color(&mut node.rb);
            }
        }

        assert_eq!(tree.count(), 10);
    }

    #[test]
    fn test_rbtree_iteration() {
        let mut tree = NextgcoreRbtree::new();
        let keys = [5, 3, 7, 1, 9, 2, 8, 4, 6, 0];
        let mut nodes: Vec<Box<TestNode>> = keys.iter().map(|&k| TestNode::new(k)).collect();

        for node in &mut nodes {
            unsafe {
                let mut parent: *mut NextgcoreRbnode = ptr::null_mut();
                let mut link: *mut *mut NextgcoreRbnode = &mut tree.root;

                while !(*link).is_null() {
                    parent = *link;
                    let parent_node = &*(parent as *const TestNode);
                    if node.key < parent_node.key {
                        link = &mut (*parent).left;
                    } else {
                        link = &mut (*parent).right;
                    }
                }

                NextgcoreRbtree::link_node(&mut node.rb, parent, link);
                tree.insert_color(&mut node.rb);
            }
        }

        // Iterate and verify sorted order
        let mut collected = Vec::new();
        let mut current = tree.first();
        while !current.is_null() {
            unsafe {
                let node = &*(current as *const TestNode);
                collected.push(node.key);
                current = tree.next(current);
            }
        }

        assert_eq!(collected, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_rbtree_delete() {
        let mut tree = NextgcoreRbtree::new();
        let mut nodes: Vec<Box<TestNode>> = (0..5).map(TestNode::new).collect();

        // Insert all nodes
        for node in &mut nodes {
            unsafe {
                let mut parent: *mut NextgcoreRbnode = ptr::null_mut();
                let mut link: *mut *mut NextgcoreRbnode = &mut tree.root;

                while !(*link).is_null() {
                    parent = *link;
                    let parent_node = &*(parent as *const TestNode);
                    if node.key < parent_node.key {
                        link = &mut (*parent).left;
                    } else {
                        link = &mut (*parent).right;
                    }
                }

                NextgcoreRbtree::link_node(&mut node.rb, parent, link);
                tree.insert_color(&mut node.rb);
            }
        }

        assert_eq!(tree.count(), 5);

        // Delete middle node (key=2)
        unsafe {
            tree.delete(&mut nodes[2].rb);
        }

        assert_eq!(tree.count(), 4);

        // Verify remaining nodes
        let mut collected = Vec::new();
        let mut current = tree.first();
        while !current.is_null() {
            unsafe {
                let node = &*(current as *const TestNode);
                collected.push(node.key);
                current = tree.next(current);
            }
        }

        assert_eq!(collected, vec![0, 1, 3, 4]);
    }
}
