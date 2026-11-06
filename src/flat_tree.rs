//! Port of npm `flat-tree`: a binary tree laid out in a flat array where even
//! indexes are leaves (blocks) and odd indexes are parents.

pub fn depth(index: u64) -> u64 {
    (index + 1).trailing_zeros() as u64
}

pub fn offset(index: u64) -> u64 {
    if index & 1 == 0 {
        index / 2
    } else {
        ((index + 1) >> depth(index)) / 2
    }
}

pub fn index(depth: u64, offset: u64) -> u64 {
    ((1 + 2 * offset) << depth) - 1
}

pub fn parent(i: u64) -> u64 {
    let d = depth(i);
    index(d + 1, offset(i) >> 1)
}

pub fn sibling(i: u64) -> u64 {
    let d = depth(i);
    index(d, offset(i) ^ 1)
}

pub fn left_child(i: u64) -> Option<u64> {
    (i & 1 == 1).then(|| {
        let d = depth(i);
        index(d - 1, offset(i) * 2)
    })
}

pub fn right_child(i: u64) -> Option<u64> {
    (i & 1 == 1).then(|| {
        let d = depth(i);
        index(d - 1, offset(i) * 2 + 1)
    })
}

pub fn left_span(i: u64) -> u64 {
    if i & 1 == 0 {
        i
    } else {
        offset(i) << (depth(i) + 1)
    }
}

pub fn right_span(i: u64) -> u64 {
    if i & 1 == 0 {
        i
    } else {
        ((offset(i) + 1) << (depth(i) + 1)) - 2
    }
}

pub fn spans(i: u64) -> (u64, u64) {
    (left_span(i), right_span(i))
}

/// Number of nodes in the subtree rooted at `i`.
pub fn count(i: u64) -> u64 {
    if i & 1 == 0 { 1 } else { (2 << depth(i)) - 1 }
}

pub fn count_leaves(i: u64) -> u64 {
    count(i).div_ceil(2)
}

/// The roots of the full subtrees covering leaves `[0, index / 2)`.
/// `index` must be even.
pub fn full_roots(index: u64) -> Vec<u64> {
    assert!(
        index & 1 == 0,
        "You can only look up roots for depth(0) blocks"
    );
    let mut out = Vec::with_capacity(index.count_ones() as usize);
    let mut leaves = index / 2;
    let mut offset = 0;
    while leaves > 0 {
        let factor = 1u64 << (63 - leaves.leading_zeros());
        out.push(offset + factor - 1);
        offset += 2 * factor;
        leaves -= factor;
    }
    out
}

/// Stateful walker, mirroring flat-tree's `Iterator` (including its quirks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iter {
    pub index: u64,
    pub offset: u64,
    pub factor: u64,
}

impl Iter {
    pub fn new(index: u64) -> Self {
        let mut it = Self {
            index: 0,
            offset: 0,
            factor: 0,
        };
        it.seek(index);
        it
    }

    pub fn seek(&mut self, index: u64) {
        self.index = index;
        if index & 1 == 1 {
            self.offset = offset(index);
            self.factor = 2 << depth(index);
        } else {
            self.offset = index / 2;
            self.factor = 2;
        }
    }

    pub fn is_left(&self) -> bool {
        self.offset & 1 == 0
    }

    pub fn is_right(&self) -> bool {
        !self.is_left()
    }

    pub fn contains(&self, index: u64) -> bool {
        let half = self.factor / 2;
        if index > self.index {
            index < self.index + half
        } else if index < self.index {
            index + half > self.index
        } else {
            true
        }
    }

    pub fn prev(&mut self) -> u64 {
        if self.offset == 0 {
            return self.index;
        }
        self.offset -= 1;
        self.index -= self.factor;
        self.index
    }

    #[allow(clippy::should_implement_trait)] // mirrors flat-tree's `next()`, not an Iterator
    pub fn next(&mut self) -> u64 {
        self.offset += 1;
        self.index += self.factor;
        self.index
    }

    pub fn count(&self) -> u64 {
        if self.index & 1 == 0 {
            1
        } else {
            self.factor - 1
        }
    }

    pub fn count_leaves(&self) -> u64 {
        self.count().div_ceil(2)
    }

    pub fn sibling(&mut self) -> u64 {
        if self.is_left() {
            self.next()
        } else {
            self.prev()
        }
    }

    pub fn parent(&mut self) -> u64 {
        if self.offset & 1 == 1 {
            self.index -= self.factor / 2;
            self.offset = (self.offset - 1) / 2;
        } else {
            self.index += self.factor / 2;
            self.offset /= 2;
        }
        self.factor *= 2;
        self.index
    }

    pub fn left_span(&mut self) -> u64 {
        self.index = self.index + 1 - self.factor / 2;
        self.offset = self.index / 2;
        self.factor = 2;
        self.index
    }

    pub fn right_span(&mut self) -> u64 {
        self.index = self.index + self.factor / 2 - 1;
        self.offset = self.index / 2;
        self.factor = 2;
        self.index
    }

    pub fn peek_right_span(&self) -> u64 {
        self.index + self.factor / 2 - 1
    }

    pub fn left_child(&mut self) -> u64 {
        if self.factor == 2 {
            return self.index;
        }
        self.factor /= 2;
        self.index -= self.factor / 2;
        self.offset *= 2;
        self.index
    }

    pub fn right_child(&mut self) -> u64 {
        if self.factor == 2 {
            return self.index;
        }
        self.factor /= 2;
        self.index += self.factor / 2;
        self.offset = 2 * self.offset + 1;
        self.index
    }

    pub fn next_tree(&mut self) -> u64 {
        self.index = self.index + self.factor / 2 + 1;
        self.offset = self.index / 2;
        self.factor = 2;
        self.index
    }

    /// Grows the iterator to the largest full root starting at its current
    /// leaf that lies below `index`; false once `index` is reached.
    pub fn full_root(&mut self, index: u64) -> bool {
        if index <= self.index || self.index & 1 == 1 {
            return false;
        }
        while index > self.index + self.factor + self.factor / 2 {
            self.index += self.factor / 2;
            self.factor *= 2;
            self.offset /= 2;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cases from flat-tree's own test suite.
    #[test]
    fn base_blocks() {
        assert_eq!(index(0, 0), 0);
        assert_eq!(index(0, 1), 2);
        assert_eq!(index(0, 2), 4);
    }

    #[test]
    fn parents_children_siblings() {
        assert_eq!(index(1, 0), 1);
        assert_eq!(index(1, 1), 5);
        assert_eq!(index(2, 0), 3);
        assert_eq!(parent(0), 1);
        assert_eq!(parent(2), 1);
        assert_eq!(parent(1), 3);
        assert_eq!(left_child(0), None);
        assert_eq!(left_child(1), Some(0));
        assert_eq!(left_child(3), Some(1));
        assert_eq!(right_child(3), Some(5));
        assert_eq!(sibling(0), 2);
        assert_eq!(sibling(2), 0);
        assert_eq!(sibling(1), 5);
        assert_eq!(sibling(5), 1);
    }

    #[test]
    fn roots_and_spans() {
        assert_eq!(full_roots(0), Vec::<u64>::new());
        assert_eq!(full_roots(2), vec![0]);
        assert_eq!(full_roots(8), vec![3]);
        assert_eq!(full_roots(20), vec![7, 17]);
        assert_eq!(full_roots(18), vec![7, 16]);
        assert_eq!(full_roots(16), vec![7]);
        assert_eq!(depth(0), 0);
        assert_eq!(depth(1), 1);
        assert_eq!(depth(3), 2);
        assert_eq!(offset(0), 0);
        assert_eq!(offset(1), 0);
        assert_eq!(offset(2), 1);
        assert_eq!(offset(3), 0);
        assert_eq!(offset(5), 1);
        assert_eq!(spans(0), (0, 0));
        assert_eq!(spans(3), (0, 6));
        assert_eq!(spans(23), (16, 30));
        assert_eq!(spans(27), (24, 30));
        assert_eq!(left_span(23), 16);
        assert_eq!(right_span(27), 30);
        assert_eq!(count(0), 1);
        assert_eq!(count(1), 3);
        assert_eq!(count(3), 7);
        assert_eq!(count(5), 3);
        assert_eq!(count(23), 15);
        assert_eq!(count_leaves(3), 4);
    }

    #[test]
    fn large_indexes() {
        let big = index(40, 3);
        assert_eq!(depth(big), 40);
        assert_eq!(offset(big), 3);
        assert_eq!(parent(big), index(41, 1));
        assert_eq!(
            full_roots(2 * ((1u64 << 45) + 1)),
            vec![(1u64 << 45) - 1, 1u64 << 46]
        );
    }

    #[test]
    fn iterator_walks() {
        let mut it = Iter::new(0);
        assert_eq!((it.index, it.is_left()), (0, true));
        assert_eq!(it.parent(), 1);
        assert_eq!(it.parent(), 3);
        assert_eq!(it.parent(), 7);
        assert_eq!(it.right_child(), 11);
        assert_eq!(it.left_child(), 9);
        assert_eq!(it.next(), 13);
        assert!(it.is_right());
        assert_eq!(it.prev(), 9);
        assert_eq!(it.sibling(), 13);
        assert_eq!(it.sibling(), 9);
        assert!(it.contains(8) && it.contains(10) && !it.contains(12));
        it.seek(23);
        assert_eq!(it.left_span(), 16);
        it.seek(23);
        assert_eq!(it.right_span(), 30);
        it.seek(3);
        assert_eq!(it.next_tree(), 8);
    }

    #[test]
    fn iterator_full_roots_match_full_roots() {
        for leaves in 0..300u64 {
            let to = 2 * leaves;
            let mut seen = vec![];
            let mut it = Iter::new(0);
            while it.full_root(to) {
                seen.push(it.index);
                it.next_tree();
            }
            assert_eq!(seen, full_roots(to), "leaves={leaves}");
        }
    }
}
