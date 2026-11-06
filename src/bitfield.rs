//! Sparse local bitfield, a port of `hypercore/lib/bitfield.js`.
//!
//! Pages are 4096 bytes (32768 bits). A page is only materialised when bits are
//! set (or loaded), so a core of 2^40 blocks costs memory proportional to what
//! it actually has. Segments stay allocated once created, mirroring the JS
//! allocation policy, because [`Bitfield::want`] output is derived from them.

use std::collections::BTreeMap;

/// Bits covered by one persisted page.
pub const BITS_PER_PAGE: u64 = 32768;
/// Bytes per persisted page.
pub const BYTES_PER_PAGE: usize = 4096;
/// Bits covered by one segment, the unit of [`Bitfield::want`] output.
pub const BITS_PER_SEGMENT: u64 = 2097152;

pub(crate) const WORDS_PER_PAGE: usize = 1024;
pub(crate) const PAGES_PER_SEGMENT: u64 = BITS_PER_SEGMENT / BITS_PER_PAGE;
const WORDS_PER_SEGMENT: usize = (BITS_PER_SEGMENT / 32) as usize;
const INITIAL_WORDS_PER_SEGMENT: usize = 1024;
const SEGMENT_GROWTH_FACTOR: usize = 4;

#[derive(Debug)]
struct Page {
    words: Box<[u32; WORDS_PER_PAGE]>,
    dirty: bool,
}

/// Sparse set of block indexes.
#[derive(Debug)]
pub struct Bitfield {
    pages: BTreeMap<u64, Page>,
    /// Allocated words per segment, mirroring the JS allocation policy: 1024
    /// words with 4x growth for segment 0, a full segment for every other one,
    /// never shrunk. Only the size matters; bits live in pages.
    segments: BTreeMap<u64, usize>,
}

impl Default for Bitfield {
    fn default() -> Self {
        Self::new()
    }
}

impl Bitfield {
    /// Bits covered by one persisted page.
    pub const BITS_PER_PAGE: u64 = crate::bitfield::BITS_PER_PAGE;
    /// Bytes per persisted page.
    pub const BYTES_PER_PAGE: usize = crate::bitfield::BYTES_PER_PAGE;
    /// Bits covered by one segment.
    pub const BITS_PER_SEGMENT: u64 = crate::bitfield::BITS_PER_SEGMENT;

    /// Creates an empty bitfield holding the same initial segment as JS.
    pub fn new() -> Self {
        let mut segments = BTreeMap::new();
        segments.insert(0, INITIAL_WORDS_PER_SEGMENT);
        Self {
            pages: BTreeMap::new(),
            segments,
        }
    }

    /// Rebuilds a bitfield from persisted `(page index, 4096-byte page)` pairs.
    ///
    /// All-zero pages are dropped from memory; their segment allocation is kept
    /// so `want` output keeps the JS layout.
    pub fn from_pages<I, B>(pages: I) -> Self
    where
        I: IntoIterator<Item = (u64, B)>,
        B: AsRef<[u8]>,
    {
        let mut bitfield = Self::new();
        for (index, bytes) in pages {
            bitfield.insert_page(index, bytes.as_ref());
        }
        bitfield
    }

    fn insert_page(&mut self, page_index: u64, bytes: &[u8]) {
        assert_eq!(
            bytes.len(),
            BYTES_PER_PAGE,
            "bitfield page must be 4096 bytes"
        );
        let page = self.ensure_page(page_index);
        for (word, chunk) in page.words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        page.dirty = false;
        if page.words.iter().all(|&w| w == 0) {
            self.pages.remove(&page_index);
        }
    }

    /// Allocates the page, growing (never shrinking) its segment like JS does.
    fn ensure_page(&mut self, page_index: u64) -> &mut Page {
        let seg_index = page_index / PAGES_PER_SEGMENT;
        let page_in_segment = page_index % PAGES_PER_SEGMENT;
        let allocated = self.segments.entry(seg_index).or_insert(if seg_index == 0 {
            INITIAL_WORDS_PER_SEGMENT
        } else {
            WORDS_PER_SEGMENT
        });
        let needed = ((page_in_segment + 1) as usize) * WORDS_PER_PAGE;
        if *allocated < needed {
            let mut target = *allocated;
            while target < needed {
                target *= SEGMENT_GROWTH_FACTOR;
            }
            *allocated = target;
        }
        self.pages.entry(page_index).or_insert_with(|| Page {
            words: Box::new([0; WORDS_PER_PAGE]),
            dirty: false,
        })
    }

    /// Returns bit `index`; unallocated bits read as false.
    pub fn get(&self, index: u64) -> bool {
        match self.pages.get(&(index / BITS_PER_PAGE)) {
            Some(page) => get_bit(&page.words[..], (index % BITS_PER_PAGE) as u32),
            None => false,
        }
    }

    /// Sets bit `index`. A false value on an unallocated page is a no-op.
    pub fn set(&mut self, index: u64, val: bool) {
        let page_index = index / BITS_PER_PAGE;
        let bit = (index % BITS_PER_PAGE) as u32;
        if val {
            let page = self.ensure_page(page_index);
            if set_bit(&mut page.words[..], bit, true) {
                page.dirty = true;
            }
        } else if let Some(page) = self.pages.get_mut(&page_index)
            && set_bit(&mut page.words[..], bit, false)
        {
            page.dirty = true;
        }
    }

    /// Fills bits `[start, end)` with `val`. Pages are created only for `true`.
    pub fn set_range(&mut self, start: u64, end: u64, val: bool) {
        if !val {
            // Clearing never touches missing pages, so only visit the existing ones.
            if end <= start {
                return;
            }
            let first_page = start / BITS_PER_PAGE;
            let last_page = (end - 1) / BITS_PER_PAGE;
            for (&page_index, page) in self.pages.range_mut(first_page..=last_page) {
                let offset = page_index * BITS_PER_PAGE;
                let from = start.saturating_sub(offset) as u32;
                let to = std::cmp::min(end - offset, BITS_PER_PAGE) as u32;
                if fill_bits(&mut page.words[..], from, to, false) {
                    page.dirty = true;
                }
            }
            return;
        }

        let mut pos = start;
        while pos < end {
            let page_index = pos / BITS_PER_PAGE;
            let offset = page_index * BITS_PER_PAGE;
            let from = (pos - offset) as u32;
            let to = std::cmp::min(end - offset, BITS_PER_PAGE) as u32;
            let page = self.ensure_page(page_index);
            if fill_bits(&mut page.words[..], from, to, true) {
                page.dirty = true;
            }
            pos += (to - from) as u64;
        }
    }

    /// Pages as they would be after `set_range(start, end, val)`, without
    /// mutating; `None` bytes mean the page becomes all zero and can be deleted.
    pub fn preview_range(&self, start: u64, end: u64, val: bool) -> Vec<(u64, Option<Vec<u8>>)> {
        let mut preview = Vec::new();
        if end <= start {
            return preview;
        }
        let zero = [0u32; WORDS_PER_PAGE];
        let first_page = start / BITS_PER_PAGE;
        let last_page = (end - 1) / BITS_PER_PAGE;
        for page_index in first_page..=last_page {
            let current: &[u32] = match self.pages.get(&page_index) {
                Some(page) => &page.words[..],
                None => &zero[..],
            };
            let mut words = current.to_vec();
            let offset = page_index * BITS_PER_PAGE;
            let from = start.saturating_sub(offset) as u32;
            let to = std::cmp::min(end - offset, BITS_PER_PAGE) as u32;
            fill_bits(&mut words, from, to, val);
            if words.as_slice() == current {
                continue;
            }
            if words.iter().all(|&w| w == 0) {
                preview.push((page_index, None));
            } else {
                let bytes = words.iter().flat_map(|w| w.to_le_bytes()).collect();
                preview.push((page_index, Some(bytes)));
            }
        }
        preview
    }

    /// Words of the page containing `index` (JS `getBitfield`); `None` if the
    /// page has no bits in memory.
    pub fn page_words(&self, index: u64) -> Option<&[u32]> {
        self.pages
            .get(&(index / BITS_PER_PAGE))
            .map(|page| &page.words[..])
    }

    /// First bit equal to `val` at or after `position` (JS `findFirst`).
    pub fn find_first(&self, val: bool, position: u64) -> Option<u64> {
        let mut idx = position / BITS_PER_SEGMENT;
        let mut offset = position % BITS_PER_SEGMENT;

        loop {
            let Some((&seg, _)) = self.segments.range(idx..).next() else {
                return if val {
                    None
                } else {
                    Some(idx * BITS_PER_SEGMENT + offset)
                };
            };
            if seg > idx {
                if !val {
                    return Some(idx * BITS_PER_SEGMENT + offset);
                }
                offset = 0;
            }

            let base_page = seg * PAGES_PER_SEGMENT;
            let first_page = base_page + offset / BITS_PER_PAGE;
            let mut local = (offset % BITS_PER_PAGE) as u32;
            for page_index in first_page..base_page + PAGES_PER_SEGMENT {
                match self.pages.get(&page_index) {
                    Some(page) => {
                        if let Some(bit) = find_first_in(&page.words[..], val, local) {
                            return Some(page_index * BITS_PER_PAGE + bit as u64);
                        }
                    }
                    None => {
                        if !val {
                            return Some(page_index * BITS_PER_PAGE + local as u64);
                        }
                    }
                }
                local = 0;
            }

            idx = seg + 1;
            offset = 0;
        }
    }

    /// First set bit at or after `position`.
    pub fn first_set(&self, position: u64) -> Option<u64> {
        self.find_first(true, position)
    }

    /// First unset bit at or after `position`.
    pub fn first_unset(&self, position: u64) -> Option<u64> {
        self.find_first(false, position)
    }

    /// Last bit equal to `val` at or before `position` (JS `findLast`).
    pub fn find_last(&self, val: bool, position: u64) -> Option<u64> {
        let mut idx = position / BITS_PER_SEGMENT;
        let mut offset = position % BITS_PER_SEGMENT;

        loop {
            let Some((&seg, _)) = self.segments.range(..=idx).next_back() else {
                return if val {
                    None
                } else {
                    Some(idx * BITS_PER_SEGMENT + offset)
                };
            };
            if seg < idx {
                if !val {
                    return Some(idx * BITS_PER_SEGMENT + offset);
                }
                idx = seg;
                offset = BITS_PER_SEGMENT - 1;
                continue;
            }

            let base_page = seg * PAGES_PER_SEGMENT;
            let mut page_index = base_page + offset / BITS_PER_PAGE;
            let mut local = (offset % BITS_PER_PAGE) as u32;
            loop {
                match self.pages.get(&page_index) {
                    Some(page) => {
                        if let Some(bit) = find_last_in(&page.words[..], val, local) {
                            return Some(page_index * BITS_PER_PAGE + bit as u64);
                        }
                    }
                    None => {
                        if !val {
                            return Some(page_index * BITS_PER_PAGE + local as u64);
                        }
                    }
                }
                if page_index == base_page {
                    break;
                }
                page_index -= 1;
                local = (BITS_PER_PAGE - 1) as u32;
            }

            if seg == 0 {
                return None;
            }
            idx = seg - 1;
            offset = BITS_PER_SEGMENT - 1;
        }
    }

    /// Last set bit at or before `position`.
    pub fn last_set(&self, position: u64) -> Option<u64> {
        self.find_last(true, position)
    }

    /// Last unset bit at or before `position`.
    pub fn last_unset(&self, position: u64) -> Option<u64> {
        self.find_last(false, position)
    }

    /// True if any bit in `[start, start + length)` is unset.
    pub fn has_unset(&self, start: u64, length: u64) -> bool {
        let end = start.saturating_add(length);
        self.find_first(false, start).is_some_and(|bit| bit < end)
    }

    /// True if any bit in `[start, start + length)` is set.
    pub fn has_set(&self, start: u64, length: u64) -> bool {
        let end = start.saturating_add(length);
        self.find_first(true, start).is_some_and(|bit| bit < end)
    }

    /// Counts bits equal to `val` in `[start, start + length)`.
    pub fn count(&self, start: u64, length: u64, val: bool) -> u64 {
        let end = start.saturating_add(length);
        if end <= start {
            return 0;
        }
        if !val {
            return (end - start) - self.count_set(start, length);
        }

        // Missing pages hold no set bits, so only existing pages matter.
        let first_page = start / BITS_PER_PAGE;
        let last_page = (end - 1) / BITS_PER_PAGE;
        let mut total = 0;
        for (&page_index, page) in self.pages.range(first_page..=last_page) {
            let offset = page_index * BITS_PER_PAGE;
            let from = start.saturating_sub(offset) as u32;
            let to = std::cmp::min(end - offset, BITS_PER_PAGE) as u32;
            total += count_bits(&page.words[..], from, to) as u64;
        }
        total
    }

    /// Number of set bits in `[start, start + length)`.
    pub fn count_set(&self, start: u64, length: u64) -> u64 {
        self.count(start, length, true)
    }

    /// Number of unset bits in `[start, start + length)`.
    pub fn count_unset(&self, start: u64, length: u64) -> u64 {
        self.count(start, length, false)
    }

    /// Word ranges to send for `[start, start + length)`, per segment, as
    /// `(32-bit aligned start bit, little-endian words)`; JS `*want` order.
    pub fn want(&self, start: u64, length: u64) -> Want<'_> {
        let mut start = start;
        let mut length = length;
        if start & 31 != 0 {
            let delta = start & 31;
            start -= delta;
            length = length.saturating_add(delta);
        }
        Want {
            bitfield: self,
            index: start / BITS_PER_SEGMENT,
            offset: start % BITS_PER_SEGMENT,
            length,
        }
    }

    /// Returns pages changed since the previous call, sorted by page index.
    /// `None` means the page is all zero and can be deleted.
    pub fn take_dirty(&mut self) -> Vec<(u64, Option<Vec<u8>>)> {
        let mut dirty = Vec::new();
        let mut emptied = Vec::new();

        for (&index, page) in self.pages.iter_mut() {
            if !page.dirty {
                continue;
            }
            page.dirty = false;
            if page.words.iter().all(|&w| w == 0) {
                emptied.push(index);
                dirty.push((index, None));
            } else {
                let bytes = page.words.iter().flat_map(|w| w.to_le_bytes()).collect();
                dirty.push((index, Some(bytes)));
            }
        }
        for index in emptied {
            self.pages.remove(&index);
        }

        dirty
    }
}

/// Lazy iterator over [`Bitfield::want`] output.
#[derive(Debug)]
pub struct Want<'a> {
    bitfield: &'a Bitfield,
    index: u64,
    offset: u64,
    length: u64,
}

impl Iterator for Want<'_> {
    type Item = (u64, Vec<u32>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.length > 0 {
            let index = self.index;
            let offset = self.offset;
            let mut end = std::cmp::min(offset.saturating_add(self.length), BITS_PER_SEGMENT);
            if end & 31 != 0 {
                end += 32 - (end & 31);
            }

            self.index += 1;
            self.offset = 0;
            self.length = self.length.saturating_sub(BITS_PER_SEGMENT);

            if let Some(&allocated) = self.bitfield.segments.get(&index) {
                let from = (offset / 32) as usize;
                let to = std::cmp::min((end / 32) as usize, allocated);
                let mut words = Vec::with_capacity(to.saturating_sub(from));
                let base_page = index * PAGES_PER_SEGMENT;
                for word in from..to {
                    let page_index = base_page + (word / WORDS_PER_PAGE) as u64;
                    let word_in_page = word % WORDS_PER_PAGE;
                    words.push(match self.bitfield.pages.get(&page_index) {
                        Some(page) => page.words[word_in_page],
                        None => 0,
                    });
                }
                return Some((index * BITS_PER_SEGMENT + offset, words));
            }
        }
        None
    }
}

pub(crate) fn get_bit(words: &[u32], bit: u32) -> bool {
    words[(bit / 32) as usize] & (1 << (bit % 32)) != 0
}

pub(crate) fn set_bit(words: &mut [u32], bit: u32, val: bool) -> bool {
    let word = &mut words[(bit / 32) as usize];
    let mask = 1u32 << (bit % 32);
    let old = *word;
    *word = if val { old | mask } else { old & !mask };
    *word != old
}

fn low_mask(bit: u32) -> u32 {
    if bit >= 32 {
        u32::MAX
    } else {
        (1u32 << bit).wrapping_sub(1)
    }
}

/// JS `quickbit.fill` for the word range covering bits `[start, end)`.
/// Returns whether any bit changed.
pub(crate) fn fill_bits(words: &mut [u32], start: u32, end: u32, val: bool) -> bool {
    let limit = (words.len() as u32) * 32;
    let end = std::cmp::min(end, limit);
    if start >= end {
        return false;
    }

    let first = start / 32;
    let last = (end - 1) / 32;
    let mut changed = false;
    for index in first..=last {
        let lo = if index == first { start % 32 } else { 0 };
        let hi = if index == last { (end - 1) % 32 } else { 31 };
        let mask = low_mask(hi + 1) & !low_mask(lo);
        let word = &mut words[index as usize];
        let old = *word;
        *word = if val { old | mask } else { old & !mask };
        changed |= *word != old;
    }
    changed
}

fn count_bits(words: &[u32], start: u32, end: u32) -> u32 {
    let limit = (words.len() as u32) * 32;
    let end = std::cmp::min(end, limit);
    if start >= end {
        return 0;
    }

    let first = start / 32;
    let last = (end - 1) / 32;
    let mut total = 0;
    for index in first..=last {
        let lo = if index == first { start % 32 } else { 0 };
        let hi = if index == last { (end - 1) % 32 } else { 31 };
        let mask = low_mask(hi + 1) & !low_mask(lo);
        total += (words[index as usize] & mask).count_ones();
    }
    total
}

pub(crate) fn find_first_in(words: &[u32], val: bool, position: u32) -> Option<u32> {
    let mut index = (position / 32) as usize;
    let mut bit = position % 32;
    while index < words.len() {
        let mut word = words[index];
        if !val {
            word = !word;
        }
        word &= u32::MAX << bit;
        if word != 0 {
            return Some(index as u32 * 32 + word.trailing_zeros());
        }
        bit = 0;
        index += 1;
    }
    None
}

pub(crate) fn find_last_in(words: &[u32], val: bool, position: u32) -> Option<u32> {
    if words.is_empty() {
        return None;
    }
    let position = std::cmp::min(position, (words.len() as u32) * 32 - 1);
    let mut index = (position / 32) as usize;
    let mut bit = position % 32;
    loop {
        let mut word = words[index];
        if !val {
            word = !word;
        }
        word &= low_mask(bit + 1);
        if word != 0 {
            return Some(index as u32 * 32 + (31 - word.leading_zeros()));
        }
        if index == 0 {
            return None;
        }
        index -= 1;
        bit = 31;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::BTreeSet;

    fn empty_page() -> Vec<u8> {
        vec![0; BYTES_PER_PAGE]
    }

    #[test]
    fn set_and_get() {
        let mut bitfield = Bitfield::new();

        assert!(!bitfield.get(42));
        bitfield.set(42, true);
        assert!(bitfield.get(42));

        // bigger offsets
        assert!(!bitfield.get(42000000));
        bitfield.set(42000000, true);
        assert!(bitfield.get(42000000));
        bitfield.set(42000000, false);
        assert!(!bitfield.get(42000000));
    }

    #[test]
    fn random_set_and_gets() {
        let mut rng = StdRng::seed_from_u64(0xB17F1E1D);
        let mut bitfield = Bitfield::new();
        let mut set = BTreeSet::new();

        for _ in 0..200 {
            let index = rng.gen_range(0..1u64 << 26);
            bitfield.set(index, true);
            set.insert(index);
        }

        for _ in 0..500 {
            let index = rng.gen_range(0..1u64 << 26);
            assert_eq!(bitfield.get(index), set.contains(&index), "at {index}");
        }

        for &index in &set {
            assert!(bitfield.get(index), "at {index}");
        }
    }

    #[test]
    fn spare_far_index_does_not_overflow() {
        let mut bitfield = Bitfield::new();
        bitfield.set(7_995_511_118_690_925, true);
        assert!(bitfield.get(7_995_511_118_690_925));
        assert_eq!(bitfield.take_dirty().len(), 1);
    }

    #[test]
    fn pages_round_trip() {
        let mut bitfield = Bitfield::new();
        bitfield.set_range(142, 143, true);
        bitfield.set_range(40000, 40001, true);
        bitfield.set_range(1_424_242_424, 1_424_242_425, true);

        let pages: Vec<(u64, Vec<u8>)> = bitfield
            .take_dirty()
            .into_iter()
            .map(|(index, page)| (index, page.expect("page has data")))
            .collect();
        assert_eq!(pages.len(), 3);
        assert!(bitfield.take_dirty().is_empty(), "take_dirty drains");

        let mut reopened = Bitfield::from_pages(pages.clone());
        assert!(reopened.get(142));
        assert!(reopened.get(40000));
        assert!(reopened.get(1_424_242_424));
        assert!(reopened.take_dirty().is_empty(), "loaded pages are clean");

        // Reopen with only the first two pages, like opening a shorter core.
        let truncated = Bitfield::from_pages(pages[..2].to_vec());
        assert!(truncated.get(142));
        assert!(truncated.get(40000));
        assert!(!truncated.get(1_424_242_424));
    }

    #[test]
    fn take_dirty_deletes_emptied_pages() {
        let mut bitfield = Bitfield::new();
        bitfield.set_range(0, 100, true);

        let dirty = bitfield.take_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].0, 0);
        let page = dirty[0].1.as_ref().expect("page has data");
        let mut expected = empty_page();
        expected[0] = 0xff;
        expected[1] = 0xff;
        expected[2] = 0xff;
        expected[3] = 0xff;
        expected[4] = 0xff;
        expected[5] = 0xff;
        expected[6] = 0xff;
        expected[7] = 0xff;
        expected[8] = 0xff;
        expected[9] = 0xff;
        expected[10] = 0xff;
        expected[11] = 0xff;
        expected[12] = 0x0f;
        assert_eq!(page, &expected);

        bitfield.set_range(0, 100, false);
        let dirty = bitfield.take_dirty();
        assert_eq!(dirty, vec![(0, None)]);
        assert!(bitfield.pages.is_empty(), "all-zero page is dropped");
        assert!(!bitfield.get(0));
    }

    #[test]
    fn set_unchanged_bit_is_not_dirty() {
        let mut bitfield = Bitfield::new();
        bitfield.set(7, true);
        bitfield.take_dirty();
        bitfield.set(7, true);
        bitfield.set_range(7, 8, true);
        bitfield.set_range(0, 0, true);
        assert!(bitfield.take_dirty().is_empty());
    }

    #[test]
    fn preview_range_matches_mutation() {
        fn base() -> Bitfield {
            let mut bitfield = Bitfield::new();
            bitfield.set(200, true);
            bitfield.set_range(40000, 70000, true);
            bitfield
        }

        for (start, end, val) in [
            (0, 100, true),
            (0, 100, false),
            (199, 201, false),
            (32700, 33000, false),
            (39999, 70001, true),
            (32768 * 3, 32768 * 5, false),
            (0, 0, true),
            (BITS_PER_SEGMENT - 10, BITS_PER_SEGMENT + 10, true),
        ] {
            let preview = base().preview_range(start, end, val);
            let mut mutated = base();
            mutated.take_dirty();
            mutated.set_range(start, end, val);
            assert_eq!(
                preview,
                mutated.take_dirty(),
                "preview_range({start}, {end}, {val})"
            );
        }

        // A page whose last bits are cleared is reported as deleted.
        assert_eq!(
            base().preview_range(0, BITS_PER_PAGE, false),
            vec![(0, None)]
        );
        // Nothing to write when the range is already in that state.
        assert!(base().preview_range(201, 202, false).is_empty());
    }

    #[test]
    fn page_words_returns_page_bits() {
        let mut bitfield = Bitfield::new();
        assert!(bitfield.page_words(0).is_none());

        bitfield.set(42, true);
        let words = bitfield.page_words(42 + 10).expect("page 0");
        assert_eq!(words.len(), WORDS_PER_PAGE);
        assert!(get_bit(words, 42));
        assert!(bitfield.page_words(BITS_PER_PAGE).is_none());

        assert_eq!(Bitfield::BITS_PER_PAGE, BITS_PER_PAGE);
        assert_eq!(Bitfield::BYTES_PER_PAGE, BYTES_PER_PAGE);
        assert_eq!(Bitfield::BITS_PER_SEGMENT, BITS_PER_SEGMENT);
    }

    #[test]
    fn page_growth_matches_js() {
        let mut bitfield = Bitfield::new();
        assert_eq!(bitfield.segments[&0], 1024);

        bitfield.set(32768, true);
        assert_eq!(bitfield.segments[&0], 4096);

        bitfield.set(4 * BITS_PER_PAGE, true);
        assert_eq!(bitfield.segments[&0], 16384);

        bitfield.set(16 * BITS_PER_PAGE, true);
        assert_eq!(bitfield.segments[&0], 65536);

        bitfield.set(20 * BITS_PER_PAGE, true);
        assert_eq!(bitfield.segments[&0], 65536);

        // Later segments are allocated at full size.
        bitfield.set(64 * BITS_PER_PAGE, true);
        assert_eq!(bitfield.segments[&1], WORDS_PER_SEGMENT);
    }

    #[test]
    fn want_matches_js() {
        // 512 KiB of pages, the JS test uses a resumed buffer of that length.
        let pages: Vec<(u64, Vec<u8>)> = (0..128).map(|i| (i, empty_page())).collect();
        let mut bitfield = Bitfield::from_pages(pages);

        assert_eq!(bitfield.want(0, 0).count(), 0);

        let want: Vec<(u64, usize)> = bitfield.want(0, 1).map(|(s, w)| (s, w.len())).collect();
        assert_eq!(want, vec![(0, 1)]);

        let want: Vec<(u64, usize)> = bitfield
            .want(0, 1024 * 4 * 8)
            .map(|(s, w)| (s, w.len()))
            .collect();
        assert_eq!(want, vec![(0, 1024)]);

        let want: Vec<(u64, usize)> = bitfield
            .want(0, 1024 * 13 * 8)
            .map(|(s, w)| (s, w.len()))
            .collect();
        assert_eq!(want, vec![(0, 3328)]);

        let want: Vec<(u64, usize)> = bitfield
            .want(0, 1024 * 260 * 8)
            .map(|(s, w)| (s, w.len()))
            .collect();
        assert_eq!(want, vec![(0, 65536), (BITS_PER_SEGMENT, 1024)]);

        // Words carry the real bits, start is rounded to 32.
        bitfield.set(40, true);
        let want: Vec<(u64, Vec<u32>)> = bitfield.want(0, 64).collect();
        assert_eq!(want.len(), 1);
        assert_eq!(want[0].0, 0);
        assert_eq!(want[0].1, vec![0, 1 << 8]);

        let want: Vec<(u64, usize)> = bitfield.want(33, 10).map(|(s, w)| (s, w.len())).collect();
        assert_eq!(want, vec![(32, 1)]);
    }

    #[test]
    fn count() {
        let mut bitfield = Bitfield::new();

        for (start, end) in [(0, 2), (5, 6), (7, 9), (13, 14), (16, 19), (20, 25)] {
            bitfield.set_range(start, end, true);
        }

        assert_eq!(bitfield.count(3, 18, true), 8);
        assert_eq!(bitfield.count(3, 18, false), 10);
        assert_eq!(bitfield.count_set(3, 18), 8);
        assert_eq!(bitfield.count_unset(3, 18), 10);

        // Across pages and beyond allocated data.
        bitfield.set_range(BITS_PER_PAGE - 2, BITS_PER_PAGE + 2, true);
        assert_eq!(bitfield.count(BITS_PER_PAGE - 4, 8, true), 4);
        assert_eq!(bitfield.count(10 * BITS_PER_PAGE, 100, false), 100);
        assert_eq!(bitfield.count(10 * BITS_PER_PAGE, 100, true), 0);
        assert_eq!(bitfield.count(0, 0, false), 0);
    }

    #[test]
    fn find_first_all_zeroes() {
        let bitfield = Bitfield::new();

        assert_eq!(bitfield.find_first(false, 0), Some(0));
        assert_eq!(bitfield.find_first(true, 0), None);
        assert_eq!(bitfield.first_set(0), None);
        assert_eq!(bitfield.first_unset(0), Some(0));

        for position in [
            2u64.pow(15),
            2u64.pow(15) - 1,
            2u64.pow(15) + 1,
            2u64.pow(16),
            2u64.pow(16) - 1,
            2u64.pow(16) + 1,
            2u64.pow(21),
            2u64.pow(21) - 1,
            2u64.pow(21) + 1,
            2u64.pow(22),
            2u64.pow(22) - 1,
            2u64.pow(22) + 1,
        ] {
            assert_eq!(bitfield.find_first(false, position), Some(position));
            assert_eq!(bitfield.find_first(true, position), None);
        }
    }

    #[test]
    fn find_first_all_ones() {
        let mut bitfield = Bitfield::new();
        bitfield.set_range(0, 2u64.pow(24), true);

        assert_eq!(bitfield.find_first(true, 0), Some(0));
        assert_eq!(bitfield.find_first(true, 2u64.pow(24)), None);
        assert_eq!(bitfield.find_first(false, 0), Some(2u64.pow(24)));
        assert_eq!(bitfield.find_first(false, 2u64.pow(24)), Some(2u64.pow(24)));

        for position in [
            2u64.pow(15),
            2u64.pow(15) - 1,
            2u64.pow(15) + 1,
            2u64.pow(16),
            2u64.pow(16) - 1,
            2u64.pow(16) + 1,
            2u64.pow(21),
            2u64.pow(21) - 1,
            2u64.pow(21) + 1,
            2u64.pow(22),
            2u64.pow(22) - 1,
            2u64.pow(22) + 1,
        ] {
            assert_eq!(bitfield.find_first(true, position), Some(position));
            assert_eq!(bitfield.find_first(false, position), Some(2u64.pow(24)));
        }
    }

    #[test]
    fn find_last_all_zeroes() {
        let bitfield = Bitfield::new();

        assert_eq!(bitfield.find_last(false, 0), Some(0));
        assert_eq!(bitfield.find_last(true, 0), None);
        assert_eq!(bitfield.last_set(0), None);
        assert_eq!(bitfield.last_unset(0), Some(0));

        for position in [
            2u64.pow(15),
            2u64.pow(15) - 1,
            2u64.pow(15) + 1,
            2u64.pow(16),
            2u64.pow(16) - 1,
            2u64.pow(16) + 1,
            2u64.pow(21),
            2u64.pow(21) - 1,
            2u64.pow(21) + 1,
            2u64.pow(22),
            2u64.pow(22) - 1,
            2u64.pow(22) + 1,
        ] {
            assert_eq!(bitfield.find_last(false, position), Some(position));
            assert_eq!(bitfield.find_last(true, position), None);
        }
    }

    #[test]
    fn find_last_all_ones() {
        let mut bitfield = Bitfield::new();
        bitfield.set_range(0, 2u64.pow(24), true);

        assert_eq!(bitfield.find_last(false, 0), None);
        assert_eq!(bitfield.find_last(false, 2u64.pow(24)), Some(2u64.pow(24)));
        assert_eq!(bitfield.find_last(true, 0), Some(0));
        assert_eq!(
            bitfield.find_last(true, 2u64.pow(24)),
            Some(2u64.pow(24) - 1)
        );

        for position in [
            2u64.pow(15),
            2u64.pow(15) - 1,
            2u64.pow(15) + 1,
            2u64.pow(16),
            2u64.pow(16) - 1,
            2u64.pow(16) + 1,
            2u64.pow(21),
            2u64.pow(21) - 1,
            2u64.pow(21) + 1,
            2u64.pow(22),
            2u64.pow(22) - 1,
            2u64.pow(22) + 1,
        ] {
            assert_eq!(bitfield.find_last(true, position), Some(position));
        }
    }

    #[test]
    fn find_last_ones_around_page_boundary() {
        let mut bitfield = Bitfield::new();
        bitfield.set(32767, true);
        bitfield.set(32768, true);

        assert_eq!(bitfield.last_unset(32768), Some(32766));
        assert_eq!(bitfield.last_unset(32769), Some(32769));
        assert_eq!(bitfield.last_set(32768), Some(32768));
        assert_eq!(bitfield.last_set(32766), None);
    }

    #[test]
    fn set_range_on_page_boundary() {
        let mut bitfield = Bitfield::new();
        bitfield.set_range(2032, 2058, true);
        assert_eq!(bitfield.find_first(true, 2048), Some(2048));
    }

    #[test]
    fn set_false_range_on_missing_page() {
        let mut bitfield = Bitfield::new();
        bitfield.set_range(32769, 32780, false);
        assert!(!bitfield.get(32769));
        assert!(bitfield.pages.is_empty());
        assert!(bitfield.take_dirty().is_empty());
    }

    #[test]
    fn set_last_bits_in_segment_and_find_first() {
        let mut bitfield = Bitfield::new();
        bitfield.set(2097150, true);
        assert_eq!(bitfield.find_first(false, 2097150), Some(2097151));

        bitfield.set(2097151, true);
        assert_eq!(bitfield.find_first(false, 2097150), Some(2097152));
        assert_eq!(bitfield.find_first(false, 2097151), Some(2097152));
    }

    #[test]
    fn set_range_over_multiple_pages() {
        let mut bitfield = Bitfield::new();

        bitfield.set_range(32768, 32769, true);
        assert!(!bitfield.get(0));
        assert!(bitfield.get(32768));
        assert!(!bitfield.get(32769));

        bitfield.set_range(0, 32768 * 2, false);
        bitfield.set_range(32768, 32768 * 2 + 1, true);
        assert!(!bitfield.get(0));
        assert!(bitfield.get(32768));
        assert!(bitfield.get(32768 * 2));
        assert!(!bitfield.get(32768 * 2 + 1));
        assert_eq!(bitfield.count_set(32768, 32768 * 2 + 1), 32769);
    }

    #[test]
    fn has_set_and_has_unset() {
        let mut bitfield = Bitfield::new();

        assert!(!bitfield.has_set(0, 0));
        assert!(!bitfield.has_unset(0, 0));
        assert!(!bitfield.has_set(0, 100));
        assert!(bitfield.has_unset(0, 100));

        bitfield.set_range(50, 60, true);
        assert!(bitfield.has_set(40, 20));
        assert!(!bitfield.has_set(60, 20));
        assert!(bitfield.has_unset(0, 60));
        assert!(!bitfield.has_unset(50, 10));

        // Across a segment boundary, where the next segment is a hole.
        bitfield.set_range(BITS_PER_SEGMENT - 2, BITS_PER_SEGMENT + 2, true);
        assert!(!bitfield.has_unset(BITS_PER_SEGMENT - 2, 4));
        assert!(bitfield.has_unset(BITS_PER_SEGMENT - 2, 5));
        assert!(bitfield.has_set(BITS_PER_SEGMENT + 1, 1));
        assert!(!bitfield.has_set(BITS_PER_SEGMENT + 2, 10));
    }

    fn model_first(model: &BTreeSet<u64>, val: bool, position: u64, limit: u64) -> Option<u64> {
        if val {
            return model.range(position..=limit).next().copied();
        }
        let mut expected = position;
        for &bit in model.range(position..=limit) {
            if bit != expected {
                return Some(expected);
            }
            expected += 1;
        }
        Some(expected).filter(|&bit| bit <= limit)
    }

    fn model_last(model: &BTreeSet<u64>, val: bool, position: u64) -> Option<u64> {
        if val {
            return model.range(..=position).next_back().copied();
        }
        let mut expected = position as i64;
        for &bit in model.range(..=position).rev() {
            if bit as i64 != expected {
                return Some(expected as u64);
            }
            if expected == 0 {
                return None;
            }
            expected -= 1;
        }
        Some(expected as u64)
    }

    #[test]
    fn random_against_naive_model() {
        const LIMIT: u64 = 3 * BITS_PER_SEGMENT + 1000;
        const MAX_RANGE: u64 = 8192;
        const QUERY_LIMIT: u64 = LIMIT + 2 * BITS_PER_SEGMENT + 100;

        let mut rng = StdRng::seed_from_u64(0x9E37_79B9_7F4A_7C15);
        let mut bitfield = Bitfield::new();
        let mut model: BTreeSet<u64> = BTreeSet::new();

        for _ in 0..400 {
            match rng.gen_range(0..5u32) {
                0 => {
                    let index = rng.gen_range(0..LIMIT);
                    bitfield.set(index, true);
                    model.insert(index);
                }
                1 => {
                    let index = rng.gen_range(0..LIMIT);
                    bitfield.set(index, false);
                    model.remove(&index);
                }
                2 | 3 => {
                    // Ranges cross page and, near the ends, segment boundaries.
                    let start = rng.gen_range(0..LIMIT);
                    let max = std::cmp::min(MAX_RANGE, LIMIT - start);
                    let end = start + rng.gen_range(0..=max);
                    let val = rng.gen_bool(0.5);
                    bitfield.set_range(start, end, val);
                    for index in start..end {
                        if val {
                            model.insert(index);
                        } else {
                            model.remove(&index);
                        }
                    }
                }
                _ => {
                    let index = rng.gen_range(0..LIMIT);
                    assert_eq!(bitfield.get(index), model.contains(&index), "get({index})");
                }
            }
        }

        for &index in &model {
            assert!(bitfield.get(index), "set bit {index}");
        }
        for _ in 0..2000 {
            let index = rng.gen_range(0..QUERY_LIMIT);
            assert_eq!(bitfield.get(index), model.contains(&index), "get({index})");
        }

        for _ in 0..200 {
            let start = rng.gen_range(0..LIMIT);
            let max = std::cmp::min(MAX_RANGE, LIMIT - start);
            let length = rng.gen_range(0..=max);
            let set = (start..start + length)
                .filter(|i| model.contains(i))
                .count() as u64;
            assert_eq!(
                bitfield.count_set(start, length),
                set,
                "count_set({start}, {length})"
            );
            assert_eq!(bitfield.count_unset(start, length), length - set);
            assert_eq!(bitfield.count(start, length, true), set);
            assert_eq!(bitfield.has_set(start, length), set > 0);
            let unset = (start..start + length).any(|i| !model.contains(&i));
            assert_eq!(bitfield.has_unset(start, length), unset);
        }

        for _ in 0..300 {
            let position = rng.gen_range(0..QUERY_LIMIT);
            for val in [true, false] {
                assert_eq!(
                    bitfield.find_first(val, position),
                    model_first(&model, val, position, QUERY_LIMIT),
                    "find_first({val}, {position})"
                );
                assert_eq!(
                    bitfield.find_last(val, position),
                    model_last(&model, val, position),
                    "find_last({val}, {position})"
                );
            }
        }
    }
}
