//! The Hypercore merkle tree: appends, proof generation and verification, and
//! reorg (fork) detection. A line-by-line port of `hypercore/lib/merkle-tree.js`
//! with synchronous node reads: local storage answers without awaiting.

use std::collections::HashMap;
use std::fmt;

use compact_encoding::Bytes;
use compact_encoding::hypercore::{
    Data, DataBlock, DataHash, DataSeek, DataUpgrade, Node, Prologue, RequestBlock, RequestSeek,
    RequestUpgrade,
};

use crate::crypto::{block_node, parent_node, tree_hash, tree_signable, tree_signable_compat};
use crate::flat_tree::{self, Iter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    InvalidProof(String),
    InvalidChecksum(u64),
    InvalidOperation(String),
    BadArgument(String),
    /// A node the tree must have is missing from storage.
    MissingNode(u64),
    Storage(String),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof(m) => write!(f, "INVALID_PROOF: {m}"),
            Self::InvalidChecksum(i) => write!(f, "INVALID_CHECKSUM: Invalid checksum at node {i}"),
            Self::InvalidOperation(m) => write!(f, "INVALID_OPERATION: {m}"),
            Self::BadArgument(m) => write!(f, "BAD_ARGUMENT: {m}"),
            Self::MissingNode(i) => write!(
                f,
                "INVALID_OPERATION: Expected tree node {i} from storage, got (nil)"
            ),
            Self::Storage(m) => write!(f, "storage: {m}"),
        }
    }
}

impl std::error::Error for MerkleError {}

pub type Result<T, E = MerkleError> = std::result::Result<T, E>;

fn invalid(m: impl Into<String>) -> MerkleError {
    MerkleError::InvalidOperation(m.into())
}

/// Read access to persisted tree nodes.
pub trait NodeStore {
    fn node(&self, index: u64) -> Result<Option<Node>>;

    fn has_node(&self, index: u64) -> Result<bool> {
        Ok(self.node(index)?.is_some())
    }

    fn node_or_error(&self, index: u64) -> Result<Node> {
        self.node(index)?.ok_or(MerkleError::MissingNode(index))
    }
}

impl NodeStore for HashMap<u64, Node> {
    fn node(&self, index: u64) -> Result<Option<Node>> {
        Ok(self.get(&index).copied())
    }
}

/// The committed shape of a core's tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeState {
    pub fork: u64,
    pub length: u64,
    pub byte_length: u64,
    pub roots: Vec<Node>,
    pub signature: Option<Bytes>,
    pub prologue: Option<Prologue>,
}

impl TreeState {
    pub fn hash(&self) -> [u8; 32] {
        tree_hash(&self.roots)
    }

    pub fn signable(&self, ctx: &[u8; 32]) -> [u8; 112] {
        tree_signable(ctx, &self.hash(), self.length, self.fork)
    }
}

/// Roots of the tree at `length`, read from storage.
pub fn roots_at(store: &impl NodeStore, length: u64) -> Result<Vec<Node>> {
    flat_tree::full_roots(2 * length)
        .into_iter()
        .map(|i| store.node_or_error(i))
        .collect()
}

/// Whether every root for `length` is stored locally.
pub fn upgradeable(store: &impl NodeStore, length: u64) -> Result<bool> {
    for i in flat_tree::full_roots(2 * length) {
        if !store.has_node(i)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn total_size(nodes: &[Node]) -> u64 {
    nodes.iter().map(|n| n.size).sum()
}

pub fn total_span(nodes: &[Node]) -> u64 {
    nodes.iter().fold(0, |s, n| s + 2 * (n.index - s + 1))
}

struct NodeQueue<'a> {
    nodes: &'a [Node],
    i: usize,
    root: Option<Node>,
}

impl<'a> NodeQueue<'a> {
    fn new(nodes: &'a [Node], root: Option<Node>) -> Self {
        Self { nodes, i: 0, root }
    }

    fn len(&self) -> usize {
        self.nodes.len() - self.i + self.root.is_some() as usize
    }

    fn peek(&self, index: u64) -> bool {
        self.root.is_some_and(|r| r.index == index)
            || self.nodes.get(self.i).is_some_and(|n| n.index == index)
    }

    fn shift(&mut self, index: u64) -> Result<Node> {
        if let Some(root) = self.root.filter(|e| e.index == index) {
            self.root = None;
            return Ok(root);
        }
        let Some(node) = self.nodes.get(self.i) else {
            return Err(invalid(format!("Expected node {index}, got (nil)")));
        };
        if node.index != index {
            return Err(invalid(format!(
                "Expected node {index}, got node {}",
                node.index
            )));
        }
        self.i += 1;
        Ok(*node)
    }
}

/// Reorg bookkeeping: which subtree still differs from the local tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgWant {
    pub nodes: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone)]
pub struct Reorg {
    pub diff: Option<Node>,
    /// `None` once the fork point is known.
    pub want: Option<ReorgWant>,
}

/// A pending change to a tree (`MerkleTreeBatch`, and `ReorgBatch` when
/// `reorg` is set).
#[derive(Debug, Clone)]
pub struct Batch {
    pub fork: u64,
    pub roots: Vec<Node>,
    pub length: u64,
    pub signature: Option<Bytes>,
    pub ancestors: u64,
    pub byte_length: u64,
    pub prologue: Option<Prologue>,
    pub tree_length: u64,
    pub tree_fork: u64,
    pub nodes: Vec<Node>,
    pub upgraded: bool,
    pub truncated: bool,
    pub reorg: Option<Reorg>,
}

impl Batch {
    pub fn new(state: &TreeState) -> Self {
        Self {
            fork: state.fork,
            roots: state.roots.clone(),
            length: state.length,
            signature: state.signature.clone(),
            ancestors: state.length,
            byte_length: state.byte_length,
            prologue: state.prologue.clone(),
            tree_length: state.length,
            tree_fork: state.fork,
            nodes: vec![],
            upgraded: false,
            truncated: false,
            reorg: None,
        }
    }

    /// An empty batch that rebuilds the tree from a fork proof.
    pub fn new_reorg(state: &TreeState) -> Self {
        Self {
            roots: vec![],
            length: 0,
            byte_length: 0,
            ancestors: 0,
            upgraded: true,
            reorg: Some(Reorg {
                diff: None,
                want: Some(ReorgWant {
                    nodes: 0,
                    start: 0,
                    end: 0,
                }),
            }),
            ..Self::new(state)
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        tree_hash(&self.roots)
    }

    pub fn signable(&self, ctx: &[u8; 32]) -> [u8; 112] {
        tree_signable(ctx, &self.hash(), self.length, self.fork)
    }

    pub fn signable_compat(&self, no_header: bool) -> Vec<u8> {
        tree_signable_compat(&self.hash(), self.length, self.fork, no_header)
    }

    /// The tree state this batch would commit.
    pub fn state(&self) -> TreeState {
        TreeState {
            fork: self.fork,
            length: self.length,
            byte_length: self.byte_length,
            roots: self.roots.clone(),
            signature: self.signature.clone(),
            prologue: self.prologue.clone(),
        }
    }

    pub fn get(&self, store: &impl NodeStore, index: u64) -> Result<Option<Node>> {
        if index >= self.length * 2 {
            return Ok(None);
        }
        if let Some(n) = self.nodes.iter().find(|n| n.index == index) {
            return Ok(Some(*n));
        }
        store.node(index)
    }

    pub fn append(&mut self, data: &[u8]) {
        let head = self.length * 2;
        let mut ite = Iter::new(head);
        self.append_root(block_node(head, data), &mut ite);
    }

    fn append_root(&mut self, node: Node, ite: &mut Iter) {
        self.upgraded = true;
        self.length += ite.factor / 2;
        self.byte_length += node.size;
        self.roots.push(node);
        self.nodes.push(node);
        while self.roots.len() > 1 {
            let a = self.roots[self.roots.len() - 1];
            let b = self.roots[self.roots.len() - 2];
            if ite.sibling() != b.index {
                ite.sibling(); // undo, so it keeps pointing at the last root
                break;
            }
            let node = parent_node(ite.parent(), &a, &b);
            self.nodes.push(node);
            self.roots.truncate(self.roots.len() - 2);
            self.roots.push(node);
        }
    }

    /// Moves the batch to an earlier `length` using roots it already has.
    pub fn checkout(&mut self, length: u64, additional_roots: &[Node]) -> Result<()> {
        let head = (2 * length).wrapping_sub(2);
        let mut all: HashMap<u64, Node> = additional_roots.iter().map(|n| (n.index, *n)).collect();
        all.extend(self.nodes.iter().map(|n| (n.index, *n)));
        let mut gaps = vec![];
        let mut roots = vec![];
        let mut r = 0;
        for index in flat_tree::full_roots(2 * length) {
            let left = flat_tree::left_span(index);
            if left != 0 {
                gaps.push(left - 1);
            }
            if r < self.roots.len() && self.roots[r].index == index {
                roots.push(self.roots[r]);
                r += 1;
                continue;
            }
            roots.push(
                *all.get(&index).ok_or_else(|| {
                    MerkleError::BadArgument("root missing for given length".into())
                })?,
            );
        }
        self.byte_length = total_size(&roots);
        self.roots = roots;
        self.length = length;
        self.signature = None;
        self.nodes
            .retain(|n| length > 0 && n.index <= head && !gaps.contains(&n.index));
        Ok(())
    }

    /// Drops batch nodes not needed below `length` (JS `prune`).
    pub fn prune(&mut self, length: u64) {
        if length == 0 {
            return;
        }
        let head = 2 * length - 2;
        let gaps: Vec<u64> = flat_tree::full_roots(head + 2)
            .into_iter()
            .map(flat_tree::left_span)
            .filter(|&l| l != 0)
            .map(|l| l - 1)
            .collect();
        self.nodes
            .retain(|n| n.index > head || gaps.contains(&n.index));
    }

    pub fn verify_upgrade(&mut self, proof: &Data) -> Result<bool> {
        let unverified = verify_tree(proof, &mut self.nodes)?;
        if proof.upgrade.is_none() {
            return Err(invalid("Expected upgrade proof"));
        }
        verify_upgrade(proof, unverified, self)
    }

    /// Whether `state` is still the tree this batch was made from.
    pub fn commitable(&self, state: &TreeState) -> bool {
        self.tree_fork == state.fork
            && if self.upgraded {
                self.tree_length == state.length
            } else {
                self.tree_length <= state.length
            }
    }

    /// Tree-node writes (and truncation deletes) for this batch.
    pub fn commit_ops(&mut self) -> CommitOps {
        let mut ops = CommitOps::default();
        if self.upgraded && self.ancestors < self.tree_length {
            ops.delete_range = Some((self.ancestors * 2, self.tree_length * 2));
            if self.ancestors > 0 {
                let head = self.ancestors * 2;
                let mut ite = Iter::new(head - 2);
                loop {
                    if ite.contains(head) && ite.index < head {
                        ops.delete.push(ite.index);
                    }
                    if ite.offset == 0 {
                        break;
                    }
                    ite.parent();
                }
                self.truncated = true;
            }
        }
        ops.put = self.nodes.clone();
        ops
    }

    /// Byte offset of the node at `index` in this batch's tree.
    pub fn byte_offset(&self, store: &impl NodeStore, index: u64) -> Result<u64> {
        if index == 2 * self.length {
            return Ok(self.byte_length);
        }
        byte_offset_in(&self.roots, index, &|i| {
            self.get(store, i)?.ok_or(MerkleError::MissingNode(i))
        })
    }

    // ReorgBatch

    /// `ReorgBatch.update`: feeds a proof answering `reorg.want`.
    pub fn reorg_update(&mut self, store: &impl NodeStore, proof: &Data) -> Result<bool> {
        let Some(reorg) = &self.reorg else {
            return Err(invalid("not a reorg batch"));
        };
        if reorg.want.is_none() {
            return Ok(true);
        }
        let diff_hash = reorg.diff.map(|d| d.hash);
        let mut nodes = vec![];
        let root = verify_tree(proof, &mut nodes)?;
        if root.is_none() || root.map(|r| r.hash) != diff_hash {
            return Ok(false);
        }
        self.nodes.extend_from_slice(&nodes);
        self.reorg_descend(store, &nodes)
    }

    pub fn reorg_finished(&self) -> bool {
        self.reorg.as_ref().is_some_and(|r| r.want.is_none())
    }

    fn reorg_descend(&mut self, store: &impl NodeStore, nodes: &[Node]) -> Result<bool> {
        let n: HashMap<u64, Node> = nodes.iter().map(|x| (x.index, *x)).collect();
        let current = self
            .reorg
            .as_ref()
            .and_then(|r| r.diff)
            .expect("reorg diff set");
        let mut diff = None;
        let mut ite = Iter::new(current.index);
        while ite.index & 1 != 0 {
            let Some(left) = n.get(&ite.left_child()).copied() else {
                break;
            };
            let existing = store.node(left.index)?;
            if existing.is_none_or(|e| e.hash != left.hash) {
                diff = Some(left);
            } else {
                diff = n.get(&ite.sibling()).copied();
            }
        }
        if current.index & 1 == 0 {
            return Ok(true);
        }
        match diff {
            None => Ok(false),
            Some(d) => Ok(self.update_diff_root(d)),
        }
    }

    fn update_diff_root(&mut self, diff: Node) -> bool {
        let tree_length = self.tree_length;
        let reorg = self.reorg.as_mut().expect("reorg batch");
        let Some(want) = reorg.want.as_mut() else {
            return true;
        };
        let (s0, s1) = flat_tree::spans(diff.index);
        let start = s0 / 2;
        let end = tree_length.min(s1 / 2 + 1);
        self.ancestors = start;
        reorg.diff = Some(diff);
        if diff.index & 1 == 0 || want.start >= tree_length || end <= start {
            reorg.want = None;
            return true;
        }
        want.start = start;
        want.end = end;
        want.nodes = log2(s1 - s0 + 2) - 1;
        false
    }
}

/// Storage writes produced by committing a batch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CommitOps {
    pub put: Vec<Node>,
    pub delete: Vec<u64>,
    /// `[start, end)` of tree indexes to delete.
    pub delete_range: Option<(u64, u64)>,
}

/// JS `log2`: `n` is always a power of two here.
fn log2(mut n: u64) -> u64 {
    let mut res = 1;
    while n > 2 {
        n /= 2;
        res += 1;
    }
    res
}

fn unpadded_size(node: &Node, padding: u64, ite: Option<&Iter>) -> u64 {
    if padding == 0 {
        return node.size;
    }
    let leaves = ite.map_or_else(|| flat_tree::count_leaves(node.index), Iter::count_leaves);
    node.size - padding * leaves
}

fn byte_offset_in(roots: &[Node], index: u64, get: &dyn Fn(u64) -> Result<Node>) -> Result<u64> {
    let index = if index & 1 == 1 {
        flat_tree::left_span(index)
    } else {
        index
    };
    let mut head = 0;
    let mut offset = 0;
    for node in roots {
        head += 2 * (node.index - head + 1);
        if index >= head {
            offset += node.size;
            continue;
        }
        let mut ite = Iter::new(node.index);
        let mut cnt = 0;
        while ite.index != index {
            cnt += 1;
            if cnt >= 1024 {
                return Err(invalid(format!("Bad getByteOffsetSession index={index}")));
            }
            if index < ite.index {
                ite.left_child();
            } else {
                offset += get(ite.left_child())?.size;
                ite.sibling();
            }
        }
        return Ok(offset);
    }
    Err(invalid("Failed to find offset"))
}

/// Byte offset of tree node `index` (a block is `2 * block`).
pub fn byte_offset(state: &TreeState, store: &impl NodeStore, index: u64) -> Result<u64> {
    if index == 2 * state.length {
        return Ok(state.byte_length);
    }
    byte_offset_in(&state.roots, index, &|i| store.node_or_error(i))
}

/// `(byte offset, byte size)` of tree node `index`.
pub fn byte_range(state: &TreeState, store: &impl NodeStore, index: u64) -> Result<(u64, u64)> {
    let last = if index & 1 == 0 {
        index
    } else {
        flat_tree::right_span(index)
    };
    if last >= 2 * state.length {
        return Err(MerkleError::BadArgument("Index is out of bounds".into()));
    }
    Ok((
        byte_offset(state, store, index)?,
        store.node_or_error(index)?.size,
    ))
}

/// Result of seeking a byte offset in the locally known tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seek {
    /// Block index and the offset into it.
    Found(u64, u64),
    /// Blocks `[start, end)` must be downloaded to resolve the seek.
    Need { start: u64, end: u64 },
}

/// `MerkleTree.seek(session, bytes, padding).update()`.
pub fn seek(
    state: &TreeState,
    store: &impl NodeStore,
    bytes: u64,
    padding: u64,
) -> Result<Option<Seek>> {
    let (start, end) = seek_window(state, bytes, padding);
    let Some((index, rem)) = seek_local(state, store, bytes, padding)? else {
        return Ok(if start < end {
            Some(Seek::Need { start, end })
        } else {
            None
        });
    };
    if index & 1 == 0 {
        return Ok(Some(Seek::Found(index / 2, rem)));
    }
    let (s0, s1) = flat_tree::spans(index);
    Ok(Some(Seek::Need {
        start: s0 / 2,
        end: s1 / 2 + 1,
    }))
}

/// `ByteSeeker`'s `start`/`end`: the local block span a peer is asked about for `bytes`.
/// At or past the local length it is `(length, 0)` — the JS replicator still sends the seek.
pub fn seek_window(state: &TreeState, bytes: u64, padding: u64) -> (u64, u64) {
    let size = state.byte_length - state.length * padding;
    if bytes >= size {
        (state.length, 0)
    } else {
        (0, state.length)
    }
}

fn seek_local(
    state: &TreeState,
    store: &impl NodeStore,
    mut bytes: u64,
    padding: u64,
) -> Result<Option<(u64, u64)>> {
    if bytes == 0 {
        return Ok(Some((0, 0)));
    }
    for node in &state.roots {
        let size = unpadded_size(node, padding, None);
        if bytes == size {
            return Ok(Some((flat_tree::right_span(node.index) + 2, 0)));
        }
        if bytes > size {
            bytes -= size;
            continue;
        }
        let mut ite = Iter::new(node.index);
        while ite.index & 1 != 0 {
            match store.node(ite.left_child())? {
                Some(l) => {
                    let size = unpadded_size(&l, padding, Some(&ite));
                    if size == bytes {
                        return Ok(Some((ite.right_span() + 2, 0)));
                    }
                    if size > bytes {
                        continue;
                    }
                    bytes -= size;
                    ite.sibling();
                }
                None => {
                    ite.parent();
                    return Ok(Some((ite.index, bytes)));
                }
            }
        }
        return Ok(Some((ite.index, bytes)));
    }
    Ok(None)
}

/// Rebuilds `batch` as a truncation of the tree to `length`.
pub fn truncate(store: &impl NodeStore, length: u64, batch: &mut Batch, fork: u64) -> Result<()> {
    let full = flat_tree::full_roots(length * 2);
    for (i, &root) in full.iter().enumerate() {
        if i < batch.roots.len() && batch.roots[i].index == root {
            continue;
        }
        batch.roots.truncate(i);
        batch.roots.push(store.node_or_error(root)?);
    }
    batch.roots.truncate(full.len());
    batch.fork = fork;
    batch.length = length;
    batch.ancestors = length;
    batch.byte_length = total_size(&batch.roots);
    batch.upgraded = true;
    Ok(())
}

/// `MerkleTree.verify`: checks a remote proof against the local tree and
/// returns the batch that applying it would commit.
pub fn verify(state: &TreeState, store: &impl NodeStore, proof: &Data) -> Result<Batch> {
    let mut batch = Batch::new(state);
    let mut unverified = verify_tree(proof, &mut batch.nodes)?;
    if proof.upgrade.is_some() && verify_upgrade(proof, unverified, &mut batch)? {
        unverified = None;
    }
    if let Some(u) = unverified {
        let verified = store.node_or_error(u.index)?;
        if verified.hash != u.hash {
            return Err(MerkleError::InvalidChecksum(u.index));
        }
    }
    Ok(batch)
}

/// `MerkleTree.verifyFullyRemote`: verifies a proof without local nodes.
pub fn verify_fully_remote(state: &TreeState, proof: &Data) -> Result<Batch> {
    let mut batch = Batch::new(state);
    batch.fork = proof.fork;
    batch.roots.clear();
    batch.length = 0;
    batch.ancestors = 0;
    batch.byte_length = 0;
    let mut unverified = verify_tree(proof, &mut batch.nodes)?;
    if proof.upgrade.is_some() && verify_upgrade(proof, unverified, &mut batch)? {
        unverified = None;
    }
    if unverified.is_some() {
        return Err(MerkleError::InvalidProof(
            "Proof not covered by the upgrade".into(),
        ));
    }
    Ok(batch)
}

/// `MerkleTree.reorg`: starts resolving a fork from a signed upgrade.
pub fn reorg(store: &impl NodeStore, proof: &Data, batch: &mut Batch) -> Result<()> {
    let unverified = if proof.block.is_some() || proof.hash.is_some() || proof.seek.is_some() {
        verify_tree(proof, &mut batch.nodes)?
    } else {
        None
    };
    if !verify_upgrade(proof, unverified, batch)? {
        return Err(MerkleError::InvalidProof(
            "Fork proof not verifiable".into(),
        ));
    }
    for root in batch.roots.clone() {
        if store.node(root.index)?.is_some_and(|e| e.hash == root.hash) {
            continue;
        }
        batch.update_diff_root(root);
        break;
    }
    if batch.reorg.as_ref().is_some_and(|r| r.diff.is_some()) {
        let nodes = batch.nodes.clone();
        batch.reorg_descend(store, &nodes)?;
    } else {
        batch.reorg.as_mut().expect("reorg batch").want = None;
        batch.ancestors = batch.length;
    }
    Ok(())
}

fn verify_tree(proof: &Data, nodes: &mut Vec<Node>) -> Result<Option<Node>> {
    let untrusted = match (&proof.block, &proof.hash) {
        (Some(b), _) => Some((2 * b.index, Some(&b.value), &b.nodes[..])),
        (None, Some(h)) => Some((h.index, None, &h.nodes[..])),
        _ => None,
    };
    let seek_nodes = proof
        .seek
        .as_ref()
        .map(|s| &s.nodes[..])
        .filter(|n| !n.is_empty());
    if untrusted.is_none() && seek_nodes.is_none() {
        return Ok(None);
    }

    let mut root = None;
    if let Some(seek_nodes) = seek_nodes {
        let mut ite = Iter::new(seek_nodes[0].index);
        let mut q = NodeQueue::new(seek_nodes, None);
        let mut r = q.shift(ite.index)?;
        nodes.push(r);
        while q.len() > 0 {
            let node = q.shift(ite.sibling())?;
            r = parent_node(ite.parent(), &r, &node);
            nodes.push(node);
            nodes.push(r);
        }
        root = Some(r);
    }

    let Some((index, value, untrusted_nodes)) = untrusted else {
        return Ok(root);
    };
    let mut ite = Iter::new(index);
    let mut q = NodeQueue::new(untrusted_nodes, root);
    let mut r = match value {
        Some(v) => block_node(ite.index, v),
        None => q.shift(ite.index)?,
    };
    nodes.push(r);
    while q.len() > 0 {
        let node = q.shift(ite.sibling())?;
        r = parent_node(ite.parent(), &r, &node);
        nodes.push(node);
        nodes.push(r);
    }
    Ok(Some(r))
}

fn verify_upgrade(proof: &Data, block_root: Option<Node>, batch: &mut Batch) -> Result<bool> {
    let upgrade = proof
        .upgrade
        .as_ref()
        .ok_or_else(|| invalid("Expected upgrade proof"))?;
    if upgrade.length == 0 {
        return Err(invalid("Invalid upgrade"));
    }
    if let Some(p) = &batch.prologue
        && upgrade.start < p.length
        && (upgrade.start != 0 || upgrade.length < p.length)
    {
        return Err(MerkleError::InvalidProof(
            "Upgrade does not satisfy prologue".into(),
        ));
    }

    let mut q = NodeQueue::new(&upgrade.nodes, block_root);
    let mut grow = !batch.roots.is_empty();
    let mut i = 0;
    let to = 2 * (upgrade.start + upgrade.length);
    let mut ite = Iter::new(0);

    while ite.full_root(to) {
        if i < batch.roots.len() && batch.roots[i].index == ite.index {
            i += 1;
            ite.next_tree();
            continue;
        }
        if grow {
            grow = false;
            let root = ite.index;
            if i < batch.roots.len() {
                ite.seek(batch.roots[batch.roots.len() - 1].index);
                while ite.index != root {
                    let node = q.shift(ite.sibling())?;
                    batch.append_root(node, &mut ite);
                }
                ite.next_tree();
                continue;
            }
        }
        let node = q.shift(ite.index)?;
        batch.append_root(node, &mut ite);
        ite.next_tree();
    }

    if let Some(p) = &batch.prologue
        && batch.length == p.length
        && p.hash != batch.hash()
    {
        return Err(MerkleError::InvalidProof("Invalid hash".into()));
    }

    // A block past the upgrade is proven by the additional nodes (hypercore 11.40).
    let past = q.root.filter(|r| r.index >= to);
    if past.is_some() {
        q.root = None;
    }
    let mut additional = NodeQueue::new(&upgrade.additional_nodes, past);
    let last = batch
        .roots
        .last()
        .ok_or_else(|| MerkleError::InvalidProof("empty upgrade".into()))?;
    ite.seek(last.index);
    while additional.len() > 0 && additional.peek(ite.sibling()) {
        let node = additional.shift(ite.index)?;
        batch.append_root(node, &mut ite);
    }
    while additional.len() > 0 {
        while !additional.peek(ite.index) {
            if ite.factor == 2 {
                return Err(invalid("Unexpected additional node"));
            }
            ite.left_child();
        }
        let node = additional.shift(ite.index)?;
        batch.append_root(node, &mut ite);
        ite.sibling();
    }

    batch.signature = upgrade.signature.clone();
    batch.fork = proof.fork;
    Ok(q.root.is_none())
}

/// What the remote asked to be proven.
#[derive(Debug, Clone, Default)]
pub struct ProofRequest {
    pub block: Option<RequestBlock>,
    pub hash: Option<RequestBlock>,
    pub seek: Option<RequestSeek>,
    pub upgrade: Option<RequestUpgrade>,
}

struct Indexed {
    value: bool,
    index: u64,
    nodes: u64,
    last_index: u64,
}

#[derive(Default)]
struct Pending {
    node: Option<Vec<Node>>,
    seek: Option<Vec<Node>>,
    upgrade: Option<Vec<Node>>,
    additional: Option<Vec<Node>>,
}

/// `MerkleTree.proof(...).settle()`. The returned `Data` has `request = 0`,
/// an empty block value and no manifest; the caller fills those in.
pub fn proof(state: &TreeState, store: &impl NodeStore, req: &ProofRequest) -> Result<Data> {
    let mut upgrade = req.upgrade;
    if let (Some(p), Some(u)) = (&state.prologue, upgrade.as_mut())
        && u.start < p.length
    {
        u.start = 0;
        u.length = p.length;
    }
    let head = 2 * state.length;
    let from = upgrade.map_or(0, |u| u.start * 2);
    let to = upgrade.map_or(head, |u| from + u.length * 2);
    let node = match (&req.block, &req.hash) {
        (Some(b), _) => Some(Indexed {
            value: true,
            index: b.index * 2,
            nodes: b.nodes,
            last_index: b.index,
        }),
        (None, Some(h)) => Some(Indexed {
            value: false,
            index: h.index,
            nodes: h.nodes,
            last_index: flat_tree::right_span(h.index) / 2,
        }),
        _ => None,
    };

    let mut out = Data {
        fork: state.fork,
        ..Default::default()
    };
    if head == 0 {
        return Ok(out);
    }
    if from >= to || to > head {
        return Err(invalid("Invalid upgrade"));
    }
    if req.seek.is_some()
        && node
            .as_ref()
            .zip(upgrade)
            .is_some_and(|(n, u)| n.last_index >= u.start)
    {
        return Err(invalid(
            "Cannot both do a seek and block/hash request when upgrading",
        ));
    }

    let mut sub_tree = head;
    let mut p = Pending::default();
    let seek = req.seek;

    if let Some(n) = node
        .as_ref()
        .filter(|n| upgrade.is_none_or(|u| n.last_index < u.start))
    {
        sub_tree = nodes_to_root(n.index, n.nodes, to)?;
        let seek_root = match seek {
            Some(s) => seek_untrusted_tree(state, store, sub_tree, s.bytes, s.padding)?,
            None => head,
        };
        block_and_seek_proof(
            store,
            node.as_ref(),
            seek.is_some(),
            seek_root,
            sub_tree,
            &mut p,
        )?;
    } else if (node.is_some() || seek.is_some()) && upgrade.is_some() {
        sub_tree = match seek {
            Some(s) => seek_from_head(store, to, s.bytes, s.padding)?,
            None => node.as_ref().expect("node or seek").index,
        };
    }

    if upgrade.is_some() {
        let mut nodes = vec![];
        upgrade_proof(
            store,
            node.as_ref(),
            seek.is_some(),
            from,
            to,
            sub_tree,
            &mut p,
            &mut nodes,
        )?;
        p.upgrade = Some(nodes);
        if head > to {
            let mut nodes = vec![];
            let sub = if seek.is_some() { head } else { sub_tree };
            upgrade_proof(
                store,
                node.as_ref(),
                seek.is_some(),
                to,
                head,
                sub,
                &mut p,
                &mut nodes,
            )?;
            p.additional = Some(nodes);
        }
    }

    if let Some(b) = &req.block {
        let nodes = p.node.ok_or_else(|| invalid("Invalid block request"))?;
        out.block = Some(DataBlock {
            index: b.index,
            value: Bytes::new(),
            nodes,
        });
    } else if let Some(h) = &req.hash {
        let nodes = p.node.ok_or_else(|| invalid("Invalid block request"))?;
        out.hash = Some(DataHash {
            index: h.index,
            nodes,
        });
    }
    if let (Some(s), Some(nodes)) = (seek, p.seek) {
        out.seek = Some(DataSeek {
            bytes: s.bytes,
            nodes,
        });
    }
    if let Some(u) = upgrade {
        out.upgrade = Some(DataUpgrade {
            start: u.start,
            length: u.length,
            nodes: p.upgrade.unwrap_or_default(),
            additional_nodes: p.additional.unwrap_or_default(),
            signature: state.signature.clone(),
        });
    }
    Ok(out)
}

fn nodes_to_root(index: u64, nodes: u64, head: u64) -> Result<u64> {
    let mut ite = Iter::new(index);
    for _ in 0..nodes {
        ite.parent();
        if ite.contains(head) {
            return Err(invalid("Nodes is out of bounds"));
        }
    }
    Ok(ite.index)
}

fn seek_proof(store: &impl NodeStore, seek_root: u64, root: u64, p: &mut Pending) -> Result<()> {
    let mut ite = Iter::new(seek_root);
    let mut seek = vec![store.node_or_error(ite.index)?];
    let mut cnt = 0;
    while ite.index != root {
        cnt += 1;
        if cnt >= 1024 {
            return Err(invalid(format!(
                "Bad seekProof seekRoot={seek_root}, root={root}"
            )));
        }
        ite.sibling();
        seek.push(store.node_or_error(ite.index)?);
        ite.parent();
    }
    p.seek = Some(seek);
    Ok(())
}

fn block_and_seek_proof(
    store: &impl NodeStore,
    node: Option<&Indexed>,
    seek: bool,
    seek_root: u64,
    root: u64,
    p: &mut Pending,
) -> Result<()> {
    let Some(node) = node else {
        return seek_proof(store, seek_root, root, p);
    };
    let mut ite = Iter::new(node.index);
    let mut out = vec![];
    if !node.value {
        out.push(store.node_or_error(ite.index)?);
    }
    let mut cnt = 0;
    while ite.index != root {
        cnt += 1;
        if cnt >= 1024 {
            return Err(invalid(format!(
                "Bad blockAndSeekProof seekRoot={seek_root}, root={root}"
            )));
        }
        ite.sibling();
        if seek && ite.contains(seek_root) && ite.index != seek_root {
            seek_proof(store, seek_root, ite.index, p)?;
        } else {
            out.push(store.node_or_error(ite.index)?);
        }
        ite.parent();
    }
    p.node = Some(out);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upgrade_proof(
    store: &impl NodeStore,
    node: Option<&Indexed>,
    seek: bool,
    from: u64,
    to: u64,
    sub_tree: u64,
    p: &mut Pending,
    nodes: &mut Vec<Node>,
) -> Result<()> {
    let mut connected = from == 0;
    let mut ite = Iter::new(0);
    while ite.full_root(to) {
        if ite.index + ite.factor / 2 < from {
            ite.next_tree();
            continue;
        }
        // connect to the tree the remote already has
        if !connected && from >= 2 && ite.contains(from - 2) {
            connected = true;
            let root = ite.index;
            let target = from - 2;
            ite.seek(target);
            let mut cnt = 0;
            while ite.index != root {
                cnt += 1;
                if cnt >= 1024 {
                    return Err(invalid(format!(
                        "Bad upgradeProof target={target}, root={root}"
                    )));
                }
                ite.sibling();
                if ite.index > target {
                    if p.node.is_none() && p.seek.is_none() && ite.contains(sub_tree) {
                        block_and_seek_proof(store, node, seek, sub_tree, ite.index, p)?;
                    } else {
                        nodes.push(store.node_or_error(ite.index)?);
                    }
                }
                ite.parent();
            }
            ite.next_tree();
            continue;
        }
        connected = true;
        // a requested subtree inside this root replaces the root itself
        if p.node.is_none() && p.seek.is_none() && ite.contains(sub_tree) {
            block_and_seek_proof(store, node, seek, sub_tree, ite.index, p)?;
            ite.next_tree();
            continue;
        }
        nodes.push(store.node_or_error(ite.index)?);
        ite.next_tree();
    }
    Ok(())
}

fn seek_from_head(store: &impl NodeStore, head: u64, mut bytes: u64, padding: u64) -> Result<u64> {
    for root in flat_tree::full_roots(head) {
        let node = store.node_or_error(root)?;
        let size = unpadded_size(&node, padding, None);
        if bytes == size {
            return Ok(root);
        }
        if bytes > size {
            bytes -= size;
            continue;
        }
        return seek_trusted_tree(store, root, bytes, padding);
    }
    Ok(head)
}

fn seek_trusted_tree(
    store: &impl NodeStore,
    root: u64,
    mut bytes: u64,
    padding: u64,
) -> Result<u64> {
    if bytes == 0 {
        return Ok(root);
    }
    let mut ite = Iter::new(root);
    let mut cnt = 0;
    while ite.index & 1 != 0 {
        cnt += 1;
        if cnt >= 1024 {
            return Err(invalid(format!(
                "Bad seekTrusted bytes={bytes}, paddding={padding}"
            )));
        }
        match store.node(ite.left_child())? {
            Some(l) => {
                let size = unpadded_size(&l, padding, Some(&ite));
                if size == bytes {
                    return Ok(ite.index);
                }
                if size > bytes {
                    continue;
                }
                bytes -= size;
                ite.sibling();
            }
            None => {
                ite.parent();
                return Ok(ite.index);
            }
        }
    }
    Ok(ite.index)
}

fn seek_untrusted_tree(
    state: &TreeState,
    store: &impl NodeStore,
    root: u64,
    bytes: u64,
    padding: u64,
) -> Result<u64> {
    let offset = byte_offset(state, store, root)?
        .checked_sub(if padding > 0 {
            padding * flat_tree::left_span(root) / 2
        } else {
            0
        })
        .ok_or_else(|| invalid("Invalid seek"))?;
    if offset > bytes {
        return Err(invalid("Invalid seek"));
    }
    if offset == bytes {
        return Ok(root);
    }
    let bytes = bytes - offset;
    let node = store.node_or_error(root)?;
    if unpadded_size(&node, padding, None) <= bytes {
        return Err(invalid("Invalid seek"));
    }
    seek_trusted_tree(store, root, bytes, padding)
}

/// `MerkleTree.missingNodes`: how many parents of `index` are absent locally.
pub fn missing_nodes(store: &impl NodeStore, index: u64, length: u64) -> Result<u64> {
    let head = 2 * length;
    let mut ite = Iter::new(index);
    if ite.peek_right_span() >= head {
        return Ok(0);
    }
    let mut cnt = 0;
    while !ite.contains(head) && !store.has_node(ite.index)? {
        cnt += 1;
        if cnt >= 1024 {
            return Err(MerkleError::InvalidOperation(format!(
                "Bad arguments to missingNodes index={index} at length={length}"
            )));
        }
        ite.parent();
    }
    Ok(cnt)
}

/// `MerkleTree.maxMissingNodes`.
pub fn max_missing_nodes(index: u64, length: u64) -> u64 {
    let head = 2 * length;
    let mut ite = Iter::new(index);
    if ite.peek_right_span() >= head || flat_tree::full_roots(head).contains(&index) {
        return 0;
    }
    ite.parent();
    let mut cnt = 0;
    while !ite.contains(head) {
        cnt += 1;
        ite.parent();
    }
    cnt
}

/// The largest length JS can represent (`2 ** 52`).
const MAX_LENGTH: u64 = 1 << 52;
/// A proof needs at most two nodes per level of a 64-level tree.
const MAX_NODES: usize = 2 * 64;

/// Serves only the nodes a proof carries, noting any lookup it cannot answer.
struct ProofNodes {
    nodes: HashMap<u64, Node>,
    insufficient: std::cell::Cell<bool>,
}

impl NodeStore for ProofNodes {
    fn node(&self, index: u64) -> Result<Option<Node>> {
        let n = self.nodes.get(&index).copied();
        if n.is_none() {
            self.insufficient.set(true);
        }
        Ok(n)
    }
}

/// `MerkleTree.refit` (hypercore 11.40): rewrites an upgrade proof made for
/// another length as if requested from ours, using only the nodes it carries.
/// `Ok(None)`: those nodes cannot bridge our length.
pub fn refit(state: &TreeState, store: &impl NodeStore, proof: &Data) -> Result<Option<Data>> {
    let Some(upgrade) = proof
        .upgrade
        .as_ref()
        .filter(|u| proof.seek.is_none() && u.start != state.length)
    else {
        return Ok(Some(proof.clone()));
    };
    let too_many = |n: &[Node]| n.len() > MAX_NODES;
    if proof.block.as_ref().is_some_and(|b| too_many(&b.nodes))
        || proof.hash.as_ref().is_some_and(|h| too_many(&h.nodes))
        || too_many(&upgrade.nodes)
        || too_many(&upgrade.additional_nodes)
    {
        return Err(invalid("Too many nodes"));
    }
    let mut carried = vec![];
    verify_tree(proof, &mut carried)?;
    carried.extend_from_slice(&upgrade.nodes);
    carried.extend_from_slice(&upgrade.additional_nodes);
    let length = carried
        .iter()
        .map(|n| flat_tree::right_span(n.index) / 2 + 1)
        .max()
        .unwrap_or(0);
    if length > MAX_LENGTH {
        return Err(invalid("Upgrade is out of bounds"));
    }
    let nodes = ProofNodes {
        nodes: carried.into_iter().map(|n| (n.index, n)).collect(),
        insufficient: false.into(),
    };

    let mut tree = TreeState {
        roots: vec![],
        byte_length: 0,
        ..state.clone()
    };
    let mut req = ProofRequest {
        block: proof.block.as_ref().map(|b| RequestBlock {
            index: b.index,
            nodes: 0,
        }),
        hash: proof.hash.as_ref().map(|h| RequestBlock {
            index: h.index,
            nodes: 0,
        }),
        ..Default::default()
    };
    if let Some(b) = req.block.as_mut() {
        b.nodes = missing_nodes(store, 2 * b.index, state.length)?;
    }
    if let Some(h) = req.hash.as_mut() {
        h.nodes = missing_nodes(store, h.index, state.length)?;
    }
    if length > state.length {
        req.upgrade = Some(RequestUpgrade {
            start: state.length,
            length: length - state.length,
        });
        tree.length = length;
        tree.signature = upgrade.signature.clone();
    }
    match self::proof(&tree, &nodes, &req) {
        Ok(mut out) => {
            if let (Some(b), Some(src)) = (out.block.as_mut(), proof.block.as_ref()) {
                b.value = src.value.clone();
            }
            out.manifest = proof.manifest.clone();
            Ok(Some(out))
        }
        Err(_) if nodes.insufficient.get() => Ok(None),
        Err(e) => Err(e),
    }
}
