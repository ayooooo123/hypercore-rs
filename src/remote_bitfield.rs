//! Sparse remote bitfield, a port of `hypercore/lib/remote-bitfield.js`.
//!
//! Holds what a peer has announced (wire `bitfield` messages and range updates).
//! Everything a peer never announced is implicitly unset, so only pages that
//! were touched are kept in memory.

use std::collections::BTreeMap;

use crate::bitfield::{
    BITS_PER_PAGE, BITS_PER_SEGMENT, PAGES_PER_SEGMENT, WORDS_PER_PAGE, fill_bits, find_first_in,
    find_last_in, get_bit, set_bit,
};

type Page = Box<[u32; WORDS_PER_PAGE]>;

/// Sparse bitfield of the blocks a remote peer has.
#[derive(Debug)]
pub struct RemoteBitfield {
    pages: BTreeMap<u64, Page>,
    /// Per segment, the number of pages up to the highest created one (JS
    /// `pagesLength`); missing pages below it read as all zero.
    segment_pages: BTreeMap<u64, u64>,
    max_segments: u64,
    max_pages: u64,
}

impl Default for RemoteBitfield {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteBitfield {
    /// Bits covered by one page.
    pub const BITS_PER_PAGE: u64 = crate::bitfield::BITS_PER_PAGE;
    /// Bits covered by one segment.
    pub const BITS_PER_SEGMENT: u64 = crate::bitfield::BITS_PER_SEGMENT;

    /// Creates an empty remote bitfield.
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            segment_pages: BTreeMap::new(),
            max_segments: 0,
            max_pages: 0,
        }
    }

    fn ensure_page(&mut self, page_index: u64) -> &mut Page {
        let seg_index = page_index / PAGES_PER_SEGMENT;
        let page_in_segment = page_index % PAGES_PER_SEGMENT;
        let pages_len = self.segment_pages.entry(seg_index).or_insert(0);
        if *pages_len <= page_in_segment {
            *pages_len = page_in_segment + 1;
        }
        if self.max_segments <= seg_index {
            self.max_segments = seg_index + 1;
        }
        if self.max_pages <= page_index {
            self.max_pages = page_index + 1;
        }
        self.pages
            .entry(page_index)
            .or_insert_with(|| Box::new([0; WORDS_PER_PAGE]))
    }

    /// Returns bit `index`; unannounced bits read as false.
    pub fn get(&self, index: u64) -> bool {
        match self.pages.get(&(index / BITS_PER_PAGE)) {
            Some(words) => get_bit(&words[..], (index % BITS_PER_PAGE) as u32),
            None => false,
        }
    }

    /// Sets bit `index`. A false value on an unannounced page is a no-op.
    pub fn set(&mut self, index: u64, val: bool) {
        let page_index = index / BITS_PER_PAGE;
        let bit = (index % BITS_PER_PAGE) as u32;
        if val {
            set_bit(&mut self.ensure_page(page_index)[..], bit, true);
        } else if let Some(words) = self.pages.get_mut(&page_index) {
            set_bit(&mut words[..], bit, false);
        }
    }

    /// Fills bits `[start, end)` with `val`; pages are created only for `true`
    /// and clearing is capped at the highest page ever touched.
    pub fn set_range(&mut self, start: u64, end: u64, val: bool) {
        if val {
            let mut pos = start;
            while pos < end {
                let page_index = pos / BITS_PER_PAGE;
                let offset = page_index * BITS_PER_PAGE;
                let from = (pos - offset) as u32;
                let to = std::cmp::min(end - offset, BITS_PER_PAGE) as u32;
                fill_bits(&mut self.ensure_page(page_index)[..], from, to, true);
                pos += (to - from) as u64;
            }
            return;
        }

        // Clearing never touches missing pages, so only visit the existing ones.
        let end = std::cmp::min(end, self.max_pages.saturating_mul(BITS_PER_PAGE));
        if end <= start {
            return;
        }
        let first_page = start / BITS_PER_PAGE;
        let last_page = (end - 1) / BITS_PER_PAGE;
        for (&page_index, words) in self.pages.range_mut(first_page..=last_page) {
            let offset = page_index * BITS_PER_PAGE;
            let from = start.saturating_sub(offset) as u32;
            let to = std::cmp::min(end - offset, BITS_PER_PAGE) as u32;
            fill_bits(&mut words[..], from, to, false);
        }
    }

    /// Existing pages overlapping `[start, end)` as `(page start bit, words)`,
    /// the JS `getBitfield` view used for missing-block bookkeeping.
    pub fn pages_in(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, &[u32])> + '_ {
        let first_page = start / BITS_PER_PAGE;
        let last_page = if end > start {
            (end - 1) / BITS_PER_PAGE + 1
        } else {
            first_page
        };
        self.pages
            .range(first_page..last_page)
            .map(|(&page, words)| (page * BITS_PER_PAGE, &words[..]))
    }

    /// First bit equal to `val` at or after `position` (JS `findFirst`).
    pub fn find_first(&self, val: bool, position: u64) -> Option<u64> {
        let mut idx = position / BITS_PER_SEGMENT;
        let mut offset = position % BITS_PER_SEGMENT;

        loop {
            let Some((&seg, &pages_len)) = self.segment_pages.range(idx..).next() else {
                // Past every announced segment: nothing set, everything unset.
                return if val { None } else { Some(position) };
            };
            if seg > idx {
                if !val {
                    return Some(idx * BITS_PER_SEGMENT + offset);
                }
                offset = 0;
            }

            let base_page = seg * PAGES_PER_SEGMENT;
            let mut page = offset / BITS_PER_PAGE;
            let mut local = (offset % BITS_PER_PAGE) as u32;
            while page < pages_len {
                match self.pages.get(&(base_page + page)) {
                    Some(words) => {
                        if let Some(bit) = find_first_in(&words[..], val, local) {
                            return Some((base_page + page) * BITS_PER_PAGE + bit as u64);
                        }
                    }
                    None => {
                        if !val {
                            return Some((base_page + page) * BITS_PER_PAGE + local as u64);
                        }
                    }
                }
                page += 1;
                local = 0;
            }
            if !val && pages_len < PAGES_PER_SEGMENT {
                return Some(
                    seg.saturating_mul(BITS_PER_SEGMENT)
                        .saturating_add(pages_len * BITS_PER_PAGE),
                );
            }

            idx = seg + 1;
            offset = 0;
        }
    }

    /// First announced bit at or after `position`.
    pub fn first_set(&self, position: u64) -> Option<u64> {
        self.find_first(true, position)
    }

    /// First unannounced bit at or after `position`.
    pub fn first_unset(&self, position: u64) -> Option<u64> {
        self.find_first(false, position)
    }

    /// Last bit equal to `val` at or before `position` (JS `findLast`).
    pub fn find_last(&self, val: bool, position: u64) -> Option<u64> {
        let mut idx = position / BITS_PER_SEGMENT;
        let mut offset = position % BITS_PER_SEGMENT;
        if idx >= self.max_segments {
            return None;
        }

        loop {
            let Some((&seg, _)) = self.segment_pages.range(..=idx).next_back() else {
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
            let mut page = offset / BITS_PER_PAGE;
            let mut local = (offset % BITS_PER_PAGE) as u32;
            loop {
                match self.pages.get(&(base_page + page)) {
                    Some(words) => {
                        if let Some(bit) = find_last_in(&words[..], val, local) {
                            return Some((base_page + page) * BITS_PER_PAGE + bit as u64);
                        }
                    }
                    None => {
                        if !val {
                            return Some((base_page + page) * BITS_PER_PAGE + local as u64);
                        }
                    }
                }
                if page == 0 {
                    break;
                }
                page -= 1;
                local = (BITS_PER_PAGE - 1) as u32;
            }

            if seg == 0 {
                return None;
            }
            idx = seg - 1;
            offset = BITS_PER_SEGMENT - 1;
        }
    }

    /// Last announced bit at or before `position`.
    pub fn last_set(&self, position: u64) -> Option<u64> {
        self.find_last(true, position)
    }

    /// Last unannounced bit at or before `position`.
    pub fn last_unset(&self, position: u64) -> Option<u64> {
        self.find_last(false, position)
    }

    /// Applies a wire `bitfield` message: overwrites `words` at 32-bit aligned
    /// bit `start`. Returns false when `start` is not 32-bit aligned.
    pub fn insert(&mut self, start: u64, words: &[u32]) -> bool {
        if !start.is_multiple_of(32) {
            return false;
        }
        // Truncate at the end of the u64 bit space instead of overflowing.
        let end = start.saturating_add((words.len() as u64).saturating_mul(32));
        let mut remaining = (end - start) / 32 * 32;
        let mut word_offset = 0;
        let mut pos = start;

        while remaining > 0 {
            let page_index = pos / BITS_PER_PAGE;
            let offset = page_index * BITS_PER_PAGE;
            let from = (pos - offset) as u32;
            let to = std::cmp::min(from as u64 + remaining, BITS_PER_PAGE);
            let count = ((to - from as u64) / 32) as usize;

            let page = self.ensure_page(page_index);
            let first_word = (from / 32) as usize;
            page[first_word..first_word + count]
                .copy_from_slice(&words[word_offset..word_offset + count]);

            word_offset += count;
            let bits = count as u64 * 32;
            remaining -= bits;
            pos += bits;
        }
        true
    }

    /// Clears with a wire `bitfield` message: removes `words` at 32-bit aligned
    /// bit `start` from existing pages only.
    pub fn clear(&mut self, start: u64, words: &[u32]) -> bool {
        if !start.is_multiple_of(32) {
            return false;
        }
        let end = start.saturating_add((words.len() as u64).saturating_mul(32));
        let mut remaining = (end - start) / 32 * 32;
        let mut word_offset = 0;
        let mut pos = start;

        while remaining > 0 {
            let page_index = pos / BITS_PER_PAGE;
            let offset = page_index * BITS_PER_PAGE;
            let from = (pos - offset) as u32;
            let to = std::cmp::min(from as u64 + remaining, BITS_PER_PAGE);
            let count = ((to - from as u64) / 32) as usize;

            if let Some(page) = self.pages.get_mut(&page_index) {
                let first_word = (from / 32) as usize;
                for i in 0..count {
                    page[first_word + i] &= !words[word_offset + i];
                }
            }

            word_offset += count;
            let bits = count as u64 * 32;
            remaining -= bits;
            pos += bits;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn find_first() {
        let mut bitfield = RemoteBitfield::new();
        bitfield.set(1000000, true);
        assert_eq!(bitfield.find_first(true, 0), Some(1000000));
        assert_eq!(bitfield.first_set(0), Some(1000000));
        assert_eq!(bitfield.find_first(true, 1000001), None);
        assert_eq!(bitfield.find_first(false, 0), Some(0));
    }

    #[test]
    fn set_range_on_page_boundary() {
        let mut bitfield = RemoteBitfield::new();
        bitfield.set_range(2032, 2058, true);
        assert_eq!(bitfield.find_first(true, 2048), Some(2048));
    }

    #[test]
    fn set_range_to_false() {
        let mut bitfield = RemoteBitfield::new();
        bitfield.set(1000, true); // something to overwrite
        bitfield.set(5001, true); // something to remain

        bitfield.set_range(0, 5000, false);

        assert_eq!(bitfield.find_first(true, 0), Some(5001));
        assert!(!bitfield.get(1000));
        assert!(bitfield.get(5001));
    }

    #[test]
    fn find_last_large_position_on_empty() {
        let bitfield = RemoteBitfield::new();
        assert_eq!(bitfield.find_last(true, 2u64.pow(53)), None);
        assert_eq!(bitfield.find_last(false, 2u64.pow(53)), None);
        assert_eq!(bitfield.last_set(0), None);
        assert_eq!(bitfield.last_unset(0), None);
    }

    #[test]
    fn set_last_bits_in_segment_and_find_first() {
        let mut bitfield = RemoteBitfield::new();

        bitfield.set(32766, true);
        assert_eq!(bitfield.find_first(false, 32766), Some(32767));

        bitfield.set(32767, true);
        assert_eq!(bitfield.find_first(false, 32766), Some(32768));
        assert_eq!(bitfield.find_first(false, 32767), Some(32768));
    }

    #[test]
    fn clear() {
        let mut bitfield = RemoteBitfield::new();

        assert_eq!(bitfield.max_segments, 0, "starts empty");
        assert!(bitfield.clear(0, &[0xffff_ffff; 1024]));
        assert_eq!(bitfield.max_segments, 0, "clear does not allocate");
        assert_eq!(bitfield.max_pages, 0);

        assert!(!bitfield.get(7), "no bit");
        bitfield.set_range(0, 16, true);
        assert!(bitfield.get(7), "set range");

        // Clears the first byte, like the JS clear buffer of `[255, 0, 0, 0]`.
        assert!(bitfield.clear(0, &[0xff]));
        assert!(!bitfield.get(7), "cleared bit");
        assert!(bitfield.get(10), "cleared only first byte");
    }

    #[test]
    fn set_range_false_does_not_make_pages() {
        let mut bitfield = RemoteBitfield::new();

        assert_eq!(bitfield.max_segments, 0);
        bitfield.set_range(1, 2u64.pow(42) - 1, false);
        assert_eq!(bitfield.max_segments, 0, "no pages allocated");
        assert_eq!(bitfield.max_pages, 0);

        bitfield.set_range(0, 10, true);
        assert_eq!(bitfield.max_segments, 1);

        bitfield.set_range(BITS_PER_SEGMENT, BITS_PER_SEGMENT + 1, true);
        assert_eq!(bitfield.max_segments, 2);
    }

    #[test]
    fn insert_requires_word_alignment() {
        let mut bitfield = RemoteBitfield::new();
        assert!(!bitfield.insert(33, &[1]));
        assert!(!bitfield.clear(31, &[1]));
        assert_eq!(bitfield.max_segments, 0);
        assert!(bitfield.insert(0, &[]));
        assert!(bitfield.clear(0, &[]));
    }

    #[test]
    fn insert_overwrites_and_spans_pages() {
        let mut bitfield = RemoteBitfield::new();

        assert!(bitfield.insert(0, &[0xffff_ffff]));
        assert!(bitfield.get(0));
        assert!(bitfield.get(31));
        assert!(!bitfield.get(32));
        assert_eq!(bitfield.last_set(100), Some(31));

        // Words replace, they do not OR.
        assert!(bitfield.insert(0, &[0]));
        assert!(!bitfield.get(31));
        assert_eq!(bitfield.max_segments, 1, "page stays allocated");

        // Two words across a page boundary.
        let start = BITS_PER_PAGE - 32;
        assert!(bitfield.insert(start, &[0xffff_ffff, 0xffff_ffff]));
        assert!(!bitfield.get(start - 1));
        assert!(bitfield.get(start));
        assert!(bitfield.get(start + 63));
        assert!(!bitfield.get(start + 64));
        assert_eq!(bitfield.segment_pages[&0], 2);

        assert!(bitfield.clear(start, &[0xffff_ffff, 0xffff_ffff]));
        assert!(!bitfield.get(start));
        assert!(!bitfield.get(start + 63));
    }

    #[test]
    fn insert_pages_length_tail_matches_js() {
        // Values verified against hypercore 11.39.5 remote-bitfield.js.
        let mut bitfield = RemoteBitfield::new();
        bitfield.insert(5 * BITS_PER_PAGE, &[0xffff_ffff]);

        assert_eq!(bitfield.max_segments, 1);
        assert_eq!(bitfield.segment_pages[&0], 6);
        assert_eq!(
            bitfield.find_first(false, 10 * BITS_PER_PAGE),
            Some(6 * BITS_PER_PAGE),
            "JS caps at pagesLength, even before the position"
        );
        assert_eq!(
            bitfield.find_first(false, 5 * BITS_PER_PAGE + 8),
            Some(5 * BITS_PER_PAGE + 32)
        );
        assert_eq!(
            bitfield.find_last(false, 10 * BITS_PER_PAGE),
            Some(10 * BITS_PER_PAGE)
        );
        assert_eq!(
            bitfield.find_last(false, 6 * BITS_PER_PAGE),
            Some(6 * BITS_PER_PAGE)
        );
        assert_eq!(
            bitfield.find_last(true, 10 * BITS_PER_PAGE),
            Some(5 * BITS_PER_PAGE + 31)
        );
    }

    #[test]
    fn insert_near_u64_max_does_not_overflow() {
        let mut bitfield = RemoteBitfield::new();
        let start = u64::MAX - 63; // 32-bit aligned

        assert!(bitfield.insert(start, &[0xffff_ffff, 0xffff_ffff]));
        assert!(bitfield.get(start));
        assert!(
            !bitfield.get(u64::MAX),
            "range is truncated at the bit space end"
        );
        assert_eq!(bitfield.first_set(0), Some(start));

        // Caps the clear at the highest page, which saturates at the u64 bit space.
        bitfield.set_range(start, u64::MAX, false);
        assert!(!bitfield.get(start));
    }

    #[test]
    fn pages_in_yields_existing_pages() {
        let mut bitfield = RemoteBitfield::new();
        assert_eq!(bitfield.pages_in(0, BITS_PER_SEGMENT).count(), 0);

        bitfield.insert(0, &[0xffff_ffff]);
        bitfield.insert(2 * BITS_PER_PAGE, &[0xff]);

        let pages: Vec<(u64, usize)> = bitfield
            .pages_in(0, 3 * BITS_PER_PAGE)
            .map(|(start, words)| (start, words.len()))
            .collect();
        assert_eq!(
            pages,
            vec![(0, WORDS_PER_PAGE), (2 * BITS_PER_PAGE, WORDS_PER_PAGE)]
        );

        let words = bitfield
            .pages_in(0, BITS_PER_PAGE)
            .next()
            .expect("page 0")
            .1;
        assert!(get_bit(words, 0));

        assert_eq!(bitfield.pages_in(0, 0).count(), 0);
        assert_eq!(
            bitfield.pages_in(BITS_PER_PAGE, 2 * BITS_PER_PAGE).count(),
            0
        );

        assert_eq!(RemoteBitfield::BITS_PER_PAGE, BITS_PER_PAGE);
        assert_eq!(RemoteBitfield::BITS_PER_SEGMENT, BITS_PER_SEGMENT);
    }

    #[derive(Default)]
    struct Model {
        bits: BTreeSet<u64>,
        pages_len: BTreeMap<u64, u64>,
        max_segments: u64,
        max_pages: u64,
    }

    impl Model {
        fn allocate_page(&mut self, page: u64) {
            let seg = page / PAGES_PER_SEGMENT;
            let in_segment = page % PAGES_PER_SEGMENT;
            let len = self.pages_len.entry(seg).or_insert(0);
            if *len <= in_segment {
                *len = in_segment + 1;
            }
            self.max_segments = self.max_segments.max(seg + 1);
            self.max_pages = self.max_pages.max(page + 1);
        }

        fn allocate_range(&mut self, start: u64, end: u64) {
            if start >= end {
                return;
            }
            for page in start / BITS_PER_PAGE..=(end - 1) / BITS_PER_PAGE {
                self.allocate_page(page);
            }
        }

        fn first_gap(&self, from: u64, end: u64) -> Option<u64> {
            let mut expected = from;
            for &bit in self.bits.range(from..end) {
                if bit != expected {
                    return Some(expected);
                }
                expected += 1;
            }
            Some(expected).filter(|&bit| bit < end)
        }

        fn find_first(&self, val: bool, position: u64) -> Option<u64> {
            if val {
                return self.bits.range(position..).next().copied();
            }

            let mut seg = position / BITS_PER_SEGMENT;
            let mut from = position;
            loop {
                if seg >= self.max_segments {
                    return Some(position.max(self.max_segments * BITS_PER_SEGMENT));
                }
                match self.pages_len.get(&seg) {
                    None => return Some(from),
                    Some(&len) => {
                        let page_in_segment = (from - seg * BITS_PER_SEGMENT) / BITS_PER_PAGE;
                        if page_in_segment >= len {
                            return Some(seg * BITS_PER_SEGMENT + len * BITS_PER_PAGE);
                        }
                        let end = seg * BITS_PER_SEGMENT + len * BITS_PER_PAGE;
                        if let Some(bit) = self.first_gap(from, end) {
                            return Some(bit);
                        }
                        if len < PAGES_PER_SEGMENT {
                            return Some(end);
                        }
                        seg += 1;
                        from = seg * BITS_PER_SEGMENT;
                    }
                }
            }
        }

        fn find_last(&self, val: bool, position: u64) -> Option<u64> {
            if position / BITS_PER_SEGMENT >= self.max_segments {
                return None;
            }
            if val {
                return self.bits.range(..=position).next_back().copied();
            }
            let mut expected = position as i64;
            for &bit in self.bits.range(..=position).rev() {
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
    }

    #[test]
    fn random_against_naive_model() {
        const WINDOW: u64 = 2 * BITS_PER_SEGMENT + 1000;
        const MAX_RANGE: u64 = 1024;

        let mut rng = StdRng::seed_from_u64(0x5EED_5EED_1234_5678);
        let mut bitfield = RemoteBitfield::new();
        let mut model = Model::default();

        for _ in 0..250 {
            match rng.gen_range(0..6u32) {
                0 => {
                    let index = rng.gen_range(0..WINDOW);
                    bitfield.set(index, true);
                    model.allocate_page(index / BITS_PER_PAGE);
                    model.bits.insert(index);
                }
                1 => {
                    let index = rng.gen_range(0..WINDOW);
                    bitfield.set(index, false);
                    model.bits.remove(&index);
                }
                2 | 3 => {
                    let start = rng.gen_range(0..WINDOW);
                    let max = std::cmp::min(MAX_RANGE, WINDOW - start);
                    let end = start + rng.gen_range(0..=max);
                    let val = rng.gen_bool(0.5);
                    bitfield.set_range(start, end, val);
                    if val {
                        model.allocate_range(start, end);
                    }
                    for index in start..end {
                        if val {
                            model.bits.insert(index);
                        } else {
                            model.bits.remove(&index);
                        }
                    }
                }
                4 => {
                    let words: Vec<u32> = (0..rng.gen_range(1..=8))
                        .map(|_| rng.gen_range(0..=u32::MAX))
                        .collect();
                    let start = rng.gen_range(0..WINDOW / 32) * 32;
                    assert!(bitfield.insert(start, &words));
                    model.allocate_range(start, start + words.len() as u64 * 32);
                    for (n, word) in words.iter().enumerate() {
                        for bit in 0..32 {
                            let index = start + n as u64 * 32 + bit;
                            if word & (1 << bit) != 0 {
                                model.bits.insert(index);
                            } else {
                                model.bits.remove(&index);
                            }
                        }
                    }
                }
                _ => {
                    let words: Vec<u32> = (0..rng.gen_range(1..=4))
                        .map(|_| rng.gen_range(0..=u32::MAX))
                        .collect();
                    let start = rng.gen_range(0..WINDOW / 32) * 32;
                    assert!(bitfield.clear(start, &words));
                    for (n, word) in words.iter().enumerate() {
                        for bit in 0..32 {
                            if word & (1 << bit) != 0 {
                                model.bits.remove(&(start + n as u64 * 32 + bit));
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(bitfield.max_segments, model.max_segments);
        assert_eq!(bitfield.max_pages, model.max_pages);
        assert_eq!(
            bitfield.segment_pages.iter().collect::<Vec<_>>(),
            model.pages_len.iter().collect::<Vec<_>>()
        );

        for &index in &model.bits {
            assert!(bitfield.get(index), "set bit {index}");
        }
        for _ in 0..2000 {
            let index = rng.gen_range(0..WINDOW + 2 * BITS_PER_SEGMENT);
            assert_eq!(
                bitfield.get(index),
                model.bits.contains(&index),
                "get({index})"
            );
        }

        for _ in 0..200 {
            let position = rng.gen_range(0..WINDOW + 2 * BITS_PER_SEGMENT);
            for val in [true, false] {
                assert_eq!(
                    bitfield.find_first(val, position),
                    model.find_first(val, position),
                    "find_first({val}, {position})"
                );
                assert_eq!(
                    bitfield.find_last(val, position),
                    model.find_last(val, position),
                    "find_last({val}, {position})"
                );
            }
        }
    }
}
