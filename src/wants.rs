//! Port of `hypercore/lib/wants.js`: which block ranges we asked a peer to
//! describe (`want`/`unwant`), and which ranges a peer asked us to describe.
//! Only the compat batch size (2^21 blocks) is on the wire today.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use compact_encoding::hypercore::Want;

pub const WANT_BATCH: u64 = 65536 * 4 * 8;
const MAX_REMOTE_BATCHES: usize = 4;
const MAX_RANGE: u64 = 8 * 256 * 1024;
const MIN_RANGE: u64 = 32;
const MAX: usize = 512;
const MAX_ANY: usize = 16;

struct AnyWant<H> {
    start: u64,
    length: u64,
    handles: HashSet<H>,
}

/// Messages to send after a local want change.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WantUpdate {
    pub want: Option<Want>,
    pub unwant: Option<Want>,
}

pub struct LocalWants<H> {
    destroyed: bool,
    wants: HashMap<u64, HashSet<H>>,
    free: Vec<u64>,
    any: Vec<AnyWant<H>>,
}

impl<H: Eq + Hash + Copy> Default for LocalWants<H> {
    fn default() -> Self {
        Self {
            destroyed: false,
            wants: HashMap::new(),
            free: vec![],
            any: vec![],
        }
    }
}

impl<H: Eq + Hash + Copy> LocalWants<H> {
    pub fn add(&mut self, index: u64, handle: H) -> Option<WantUpdate> {
        self.add_batch(index / WANT_BATCH, handle)
    }

    pub fn add_any_range(&mut self, start: u64, length: u64, handle: H) -> Option<Want> {
        if self.destroyed {
            return None;
        }
        let r = start & (WANT_BATCH - 1);
        let start = start - r;
        let mut length = length + r;
        let r = length & (WANT_BATCH - 1);
        if r != 0 {
            length = length - r + WANT_BATCH;
        }
        if let Some(w) = self
            .any
            .iter_mut()
            .find(|w| w.start == start && w.length == length)
        {
            w.handles.insert(handle);
            return None;
        }
        self.any.push(AnyWant {
            start,
            length,
            handles: HashSet::from([handle]),
        });
        Some(Want {
            start,
            length,
            any: false,
        })
    }

    pub fn remove_any_range(&mut self, start: u64, length: u64, handle: H) -> Option<Want> {
        let i = self
            .any
            .iter()
            .position(|w| w.start == start && w.length == length)?;
        self.any[i].handles.remove(&handle);
        if !self.any[i].handles.is_empty() {
            return None;
        }
        self.any.swap_remove(i);
        Some(Want {
            start,
            length,
            any: false,
        })
    }

    /// Any-range wants held by `handle`, as `(start, length)`.
    pub fn any_ranges_of(&self, handle: H) -> Vec<(u64, u64)> {
        self.any
            .iter()
            .filter(|w| w.handles.contains(&handle))
            .map(|w| (w.start, w.length))
            .collect()
    }

    fn add_batch(&mut self, batch: u64, handle: H) -> Option<WantUpdate> {
        if self.destroyed {
            return None;
        }
        if let Some(w) = self.wants.get_mut(&batch) {
            w.insert(handle);
            return None;
        }
        if let Some(i) = self.free.iter().position(|&f| f == batch) {
            self.free.swap_remove(i);
            self.wants.insert(batch, HashSet::from([handle]));
            return None;
        }
        let mut unwant = None;
        if self.wants.len() + self.free.len() == MAX {
            let f = self.free.pop()?;
            unwant = Some(Want {
                start: f * WANT_BATCH,
                length: WANT_BATCH,
                any: false,
            });
        }
        self.wants.insert(batch, HashSet::from([handle]));
        Some(WantUpdate {
            want: Some(Want {
                start: batch * WANT_BATCH,
                length: WANT_BATCH,
                any: false,
            }),
            unwant,
        })
    }

    /// Drops `handle` from every batch want. True if the peer has room for
    /// more wants again (JS `removeBatch` signalling).
    pub fn remove_handle(&mut self, handle: H) -> bool {
        if self.destroyed {
            return false;
        }
        let mut freed = false;
        let batches: Vec<u64> = self
            .wants
            .iter()
            .filter(|(_, h)| h.contains(&handle))
            .map(|(b, _)| *b)
            .collect();
        for b in batches {
            let w = self.wants.get_mut(&b).expect("present");
            w.remove(&handle);
            if w.is_empty() {
                self.wants.remove(&b);
                self.free.push(b);
                freed |= self.free.len() == 1 && self.wants.len() == MAX - 1;
            }
        }
        freed
    }

    pub fn destroy(&mut self) {
        self.destroyed = true;
        self.wants.clear();
    }
}

struct RemoteBatch {
    length: u64,
    ranges: HashSet<u64>,
}

#[derive(Default)]
pub struct RemoteWants {
    any: Option<Vec<Want>>,
    all: bool,
    size: usize,
    batches: Vec<RemoteBatch>,
}

fn valid_batch_range(r: &Want) -> bool {
    (MIN_RANGE..=MAX_RANGE).contains(&r.length)
        && r.length.is_power_of_two()
        && r.start & (r.length - 1) == 0
}

impl RemoteWants {
    fn has_any(&self, start: u64, length: u64) -> bool {
        let e = start + length;
        for a in self.any.iter().flatten() {
            let end = a.start + a.length;
            if a.start <= start && start < end {
                return true;
            }
            if a.start < e && e <= end {
                return true;
            }
        }
        self.all
    }

    pub fn has_range(&self, start: u64, length: u64) -> bool {
        if self.any.is_some() && self.has_any(start, length) {
            return true;
        }
        if length == 1 {
            return self.has(start);
        }
        let Some(smallest) = self.batches.iter().map(|b| b.length).min() else {
            return self.all;
        };
        let r = start & (smallest - 1);
        let end = start + length;
        let mut max = 3;
        let mut i = start - r;
        while i < end {
            if max == 0 {
                return true;
            }
            max -= 1;
            if self.has(i) {
                return true;
            }
            i += smallest;
        }
        self.all
    }

    pub fn has(&self, index: u64) -> bool {
        self.batches
            .iter()
            .any(|b| b.ranges.contains(&(index / b.length)))
            || self.all
    }

    /// False if the range is too large to accept (JS ignores it then).
    pub fn add(&mut self, range: Want) -> bool {
        if range.any {
            let any = self.any.get_or_insert_with(Vec::new);
            if any.len() < MAX_ANY {
                any.push(range);
            } else {
                self.all = true;
            }
            return true;
        }
        if range.length > MAX_RANGE {
            return false;
        }
        if !valid_batch_range(&range) || self.size >= MAX {
            self.all = true;
            return true;
        }
        if let Some(b) = self.batches.iter_mut().find(|b| b.length == range.length) {
            b.ranges.insert(range.start / range.length);
            self.size += 1;
            return true;
        }
        if self.batches.len() >= MAX_REMOTE_BATCHES {
            self.all = true;
            return true;
        }
        self.batches.push(RemoteBatch {
            length: range.length,
            ranges: HashSet::from([range.start / range.length]),
        });
        self.size += 1;
        true
    }

    pub fn remove(&mut self, range: Want) -> bool {
        if range.any {
            let Some(any) = self.any.as_mut() else {
                return false;
            };
            let Some(i) = any
                .iter()
                .position(|a| a.start == range.start && a.length == range.length)
            else {
                return false;
            };
            any.swap_remove(i);
            return true;
        }
        if !valid_batch_range(&range) {
            return false;
        }
        let Some(i) = self.batches.iter().position(|b| b.length == range.length) else {
            return false;
        };
        if self.batches[i].ranges.remove(&(range.start / range.length)) {
            self.size -= 1;
        }
        if self.batches[i].ranges.is_empty() {
            self.batches.swap_remove(i);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_batches_dedupe_and_free() {
        let mut w = LocalWants::<u32>::default();
        let u = w.add(5, 1).unwrap();
        assert_eq!(
            u.want,
            Some(Want {
                start: 0,
                length: WANT_BATCH,
                any: false
            })
        );
        assert!(w.add(10, 2).is_none(), "same batch, second handle");
        w.remove_handle(1);
        w.remove_handle(2);
        assert!(w.add(WANT_BATCH + 1, 3).is_some());
        assert!(
            w.add(7, 4).is_none(),
            "freed batch is reused without a new want"
        );
    }

    #[test]
    fn any_ranges_round_to_batches() {
        let mut w = LocalWants::<u32>::default();
        let want = w.add_any_range(10, 5, 1).unwrap();
        assert_eq!((want.start, want.length), (0, WANT_BATCH));
        assert!(w.add_any_range(0, 100, 2).is_none());
        assert!(w.remove_any_range(0, WANT_BATCH, 1).is_none());
        assert!(w.remove_any_range(0, WANT_BATCH, 2).is_some());
    }

    #[test]
    fn remote_ranges() {
        let mut r = RemoteWants::default();
        assert!(!r.has(3));
        assert!(r.add(Want {
            start: 64,
            length: 32,
            any: false
        }));
        assert!(r.has(70) && !r.has(10));
        assert!(r.has_range(0, 100));
        assert!(!r.add(Want {
            start: 0,
            length: MAX_RANGE * 2,
            any: false
        }));
        assert!(
            r.add(Want {
                start: 3,
                length: 33,
                any: false
            }),
            "invalid ranges flip to all"
        );
        assert!(r.has(1_000_000));
    }
}
