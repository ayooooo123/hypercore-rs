//! Private on-disk storage for many hypercore instances in one directory.
//!
//! Layout: one redb database for all metadata plus append-only segment files for
//! blocks at or above [`SEGMENT_MIN`] bytes. The format is private; no JS code reads it.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use compact_encoding::{Bytes, hypercore::Node};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

pub type Result<T, E = StorageError> = std::result::Result<T, E>;

/// Blocks at or above this size live in segment files, smaller ones inline in redb.
pub const SEGMENT_MIN: usize = 16 * 1024;
/// Blocks per segment file.
pub const BLOCKS_PER_SEGMENT: u64 = 128;

/// Open segment handles kept per store; writes always open their own handle.
const HANDLE_CACHE: usize = 32;

const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nodes");
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const BITFIELD: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bitfield");
const USER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("user");
const SEGMENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("segments");
const META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta");

const TAG_INLINE: u8 = 0;
const TAG_SEGMENT: u8 = 1;

/// Storage failure.
#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Db(String),
    Corrupt(String),
    Closed,
    ReadOnly,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "io: {e}"),
            StorageError::Db(e) => write!(f, "database: {e}"),
            StorageError::Corrupt(e) => write!(f, "corrupt storage: {e}"),
            StorageError::Closed => f.write_str("storage closed"),
            StorageError::ReadOnly => f.write_str("storage is read-only"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        StorageError::Io(e)
    }
}

fn db_err<E: fmt::Display>(e: E) -> StorageError {
    StorageError::Db(e.to_string())
}

fn corrupt(what: &str) -> StorageError {
    StorageError::Corrupt(what.to_string())
}

/// A directory of cores: one redb database plus one segment tree per core.
#[derive(Clone)]
pub struct Store {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    db: RwLock<Option<Database>>,
    read_only: bool,
    closed: tokio::sync::watch::Sender<bool>,
    dir: PathBuf,
    handles: Mutex<HandleCache>,
    // Writers hold this across commit and the unlinks that follow it: releasing the redb
    // writer lock first would let another batch recreate a path before we delete it.
    // Block reads hold it so a record and the file bytes it points at come from the
    // same generation.
    gate: RwLock<()>,
}

#[derive(Default)]
struct HandleCache {
    files: HashMap<PathBuf, File>,
    order: VecDeque<PathBuf>,
}

impl Store {
    /// Open (or create) the store in `dir`.
    pub fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir.join("blocks"))?;
        let db = Database::create(dir.join("db.redb")).map_err(db_err)?;
        let txn = db.begin_write().map_err(db_err)?;
        // Create every table up front so read transactions never see a missing table.
        for def in [HEADERS, NODES, BLOCKS, BITFIELD, USER, SEGMENTS, META] {
            txn.open_table(def).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(Store {
            inner: Arc::new(StoreInner {
                db: RwLock::new(Some(db)),
                read_only: false,
                closed: tokio::sync::watch::channel(false).0,
                dir: dir.to_path_buf(),
                handles: Mutex::new(HandleCache::default()),
                gate: RwLock::new(()),
            }),
        })
    }

    pub fn open_read_only(dir: &Path) -> Result<Store> {
        let db = Database::open(dir.join("db.redb")).map_err(db_err)?;
        Ok(Store {
            inner: Arc::new(StoreInner {
                db: RwLock::new(Some(db)),
                read_only: true,
                closed: tokio::sync::watch::channel(false).0,
                dir: dir.to_path_buf(),
                handles: Mutex::new(HandleCache::default()),
                gate: RwLock::new(()),
            }),
        })
    }

    pub fn read_only(&self) -> bool {
        self.inner.read_only
    }

    pub fn is_closed(&self) -> bool {
        self.inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    }

    pub(crate) fn closed(&self) -> tokio::sync::watch::Receiver<bool> {
        self.inner.closed.subscribe()
    }

    pub fn close(&self) {
        self.inner.closed.send_replace(true);
        let _gate = self.inner.gate.write().unwrap_or_else(|p| p.into_inner());
        self.inner
            .handles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .files
            .clear();
        self.inner
            .db
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }

    /// Handle for one core; writes nothing until a [`Batch`] is committed.
    pub fn core(&self, discovery_key: &[u8; 32]) -> CoreStorage {
        CoreStorage {
            store: self.clone(),
            dk: *discovery_key,
        }
    }

    /// Discovery keys of every core that has a header.
    pub fn cores(&self) -> Result<Vec<[u8; 32]>> {
        let db = self.inner.db.read().unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(HEADERS).map_err(db_err)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(db_err)? {
            let (k, _) = entry.map_err(db_err)?;
            let key = k.value();
            if key.len() != 32 {
                return Err(corrupt("header key is not a discovery key"));
            }
            let mut dk = [0u8; 32];
            dk.copy_from_slice(key);
            out.push(dk);
        }
        Ok(out)
    }

    /// Remove every record and segment file belonging to one core.
    pub fn delete_core(&self, discovery_key: &[u8; 32]) -> Result<()> {
        if self.is_closed() {
            return Err(StorageError::Closed);
        }
        if self.inner.read_only {
            return Err(StorageError::ReadOnly);
        }
        let _gate = self.inner.gate.write().unwrap_or_else(|p| p.into_inner());
        let db = self.inner.db.read().unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_write()
            .map_err(db_err)?;
        {
            let mut headers = txn.open_table(HEADERS).map_err(db_err)?;
            headers.remove(&discovery_key[..]).map_err(db_err)?;
        }
        for def in [NODES, BLOCKS, BITFIELD, USER, SEGMENTS] {
            let mut table = txn.open_table(def).map_err(db_err)?;
            delete_prefix(&mut table, discovery_key)?;
        }
        txn.commit().map_err(db_err)?;
        let dir = self.inner.core_dir(discovery_key);
        self.inner.evict(&dir);
        let removed = match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        };
        self.inner.evict(&dir);
        removed
    }

    /// Store-level metadata, e.g. the corestore primary key.
    pub fn get_meta(&self, key: &str) -> Result<Option<Bytes>> {
        let db = self.inner.db.read().unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(META).map_err(db_err)?;
        let value = table.get(key.as_bytes()).map_err(db_err)?;
        Ok(value.map(|v| Bytes::copy_from_slice(v.value())))
    }

    /// Store-level metadata; `None` deletes the key.
    pub fn put_meta(&self, key: &str, value: Option<&[u8]>) -> Result<()> {
        if self.is_closed() {
            return Err(StorageError::Closed);
        }
        if self.inner.read_only {
            return Err(StorageError::ReadOnly);
        }
        let db = self.inner.db.read().unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_write()
            .map_err(db_err)?;
        {
            let mut table = txn.open_table(META).map_err(db_err)?;
            match value {
                Some(value) => {
                    table.insert(key.as_bytes(), value).map_err(db_err)?;
                }
                None => {
                    table.remove(key.as_bytes()).map_err(db_err)?;
                }
            }
        }
        txn.commit().map_err(db_err)
    }
}

impl StoreInner {
    fn core_dir(&self, dk: &[u8; 32]) -> PathBuf {
        let hex = hex(dk);
        self.dir.join("blocks").join(&hex[..2]).join(hex)
    }

    fn segment_path(&self, dk: &[u8; 32], segment: u64) -> PathBuf {
        self.core_dir(dk).join(format!("{segment}.seg"))
    }

    /// Drop cached handles at or under `prefix`, so a later file at the same path
    /// is never read through a handle to an unlinked inode.
    fn evict(&self, prefix: &Path) {
        let mut cache = self.handles.lock().unwrap_or_else(|p| p.into_inner());
        let stale: Vec<PathBuf> = cache
            .files
            .keys()
            .filter(|path| path.starts_with(prefix))
            .cloned()
            .collect();
        for path in stale {
            cache.files.remove(&path);
        }
        cache.order.retain(|path| !path.starts_with(prefix));
    }

    /// Cached read handle for an existing segment file.
    fn segment_file(&self, path: &Path) -> Result<File> {
        let mut cache = self.handles.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(file) = cache.files.get(path) {
            return file.try_clone().map_err(StorageError::Io);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => corrupt("missing segment file"),
                _ => StorageError::Io(e),
            })?;
        let handle = file.try_clone()?;
        if cache.order.len() >= HANDLE_CACHE
            && let Some(old) = cache.order.pop_front()
        {
            cache.files.remove(&old);
        }
        cache.order.push_back(path.to_path_buf());
        cache.files.insert(path.to_path_buf(), file);
        Ok(handle)
    }
}

/// One core inside a [`Store`].
#[derive(Clone)]
pub struct CoreStorage {
    store: Store,
    dk: [u8; 32],
}

impl CoreStorage {
    /// Discovery key this handle addresses.
    pub fn discovery_key(&self) -> &[u8; 32] {
        &self.dk
    }

    /// Opaque core header (the signed manifest) if it was stored.
    pub fn header(&self) -> Result<Option<Bytes>> {
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(HEADERS).map_err(db_err)?;
        let value = table.get(&self.dk[..]).map_err(db_err)?;
        Ok(value.map(|v| Bytes::copy_from_slice(v.value())))
    }

    /// Merkle tree node at `index`.
    pub fn tree_node(&self, index: u64) -> Result<Option<Node>> {
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(NODES).map_err(db_err)?;
        let value = table.get(&core_key(&self.dk, index)[..]).map_err(db_err)?;
        match value {
            None => Ok(None),
            Some(v) => Ok(Some(decode_node(index, v.value())?)),
        }
    }

    /// Whether a merkle tree node exists at `index`.
    pub fn has_tree_node(&self, index: u64) -> Result<bool> {
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(NODES).map_err(db_err)?;
        Ok(table
            .get(&core_key(&self.dk, index)[..])
            .map_err(db_err)?
            .is_some())
    }

    /// Block `index`, inline or from its segment file.
    pub fn block(&self, index: u64) -> Result<Option<Bytes>> {
        // The pointer and the bytes it addresses must come from the same generation.
        let _gate = self
            .store
            .inner
            .gate
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(BLOCKS).map_err(db_err)?;
        let value = table.get(&core_key(&self.dk, index)[..]).map_err(db_err)?;
        let raw = match value {
            None => return Ok(None),
            Some(v) => v.value().to_vec(),
        };
        match raw.first() {
            Some(&TAG_INLINE) => Ok(Some(Bytes::copy_from_slice(&raw[1..]))),
            Some(&TAG_SEGMENT) => {
                let (segment, offset, len) = decode_segment_entry(&raw)?;
                let path = self.store.inner.segment_path(&self.dk, segment);
                let file = self.store.inner.segment_file(&path)?;
                let mut buf =
                    vec![0u8; usize::try_from(len).map_err(|_| corrupt("block too large"))?];
                // Reads stay inside bytes a committed record referenced; a short read is damage.
                file.read_exact_at(&mut buf, offset)
                    .map_err(|e| match e.kind() {
                        io::ErrorKind::UnexpectedEof => {
                            corrupt("segment shorter than its block record")
                        }
                        _ => StorageError::Io(e),
                    })?;
                Ok(Some(Bytes::from(buf)))
            }
            _ => Err(corrupt("unknown block record tag")),
        }
    }

    /// Every stored bitfield page, ascending.
    pub fn bitfield_pages(&self) -> Result<Vec<(u64, Bytes)>> {
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(BITFIELD).map_err(db_err)?;
        let mut out = Vec::new();
        for (key, value) in prefix_entries(&table, &self.dk)? {
            let page = decode_index(&key, "bitfield key")?;
            out.push((page, Bytes::from(value)));
        }
        Ok(out)
    }

    /// One user-data value.
    pub fn user_data(&self, key: &str) -> Result<Option<Bytes>> {
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(USER).map_err(db_err)?;
        let value = table.get(&user_key(&self.dk, key)[..]).map_err(db_err)?;
        Ok(value.map(|v| Bytes::copy_from_slice(v.value())))
    }

    /// All user-data values, by key.
    pub fn user_data_all(&self) -> Result<Vec<(String, Bytes)>> {
        let db = self
            .store
            .inner
            .db
            .read()
            .unwrap_or_else(|p| p.into_inner());
        let txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_read()
            .map_err(db_err)?;
        let table = txn.open_table(USER).map_err(db_err)?;
        let mut out = Vec::new();
        for (key, value) in prefix_entries(&table, &self.dk)? {
            if key.len() < 32 {
                return Err(corrupt("user data key is too short"));
            }
            let name = std::str::from_utf8(&key[32..])
                .map_err(|_| corrupt("user data key is not utf-8"))?;
            out.push((name.to_string(), Bytes::from(value)));
        }
        Ok(out)
    }

    /// Apply a batch atomically and durably.
    pub fn write(&self, batch: Batch) -> Result<()> {
        if self.store.is_closed() {
            return Err(StorageError::Closed);
        }
        if self.store.inner.read_only {
            return Err(StorageError::ReadOnly);
        }
        if batch.is_empty() {
            return Ok(());
        }
        let _gate = self
            .store
            .inner
            .gate
            .write()
            .unwrap_or_else(|p| p.into_inner());
        let inner = &*self.store.inner;
        let dk = &self.dk;
        let db = inner.db.read().unwrap_or_else(|p| p.into_inner());
        let mut txn = db
            .as_ref()
            .ok_or(StorageError::Closed)?
            .begin_write()
            .map_err(db_err)?;
        txn.set_durability(Durability::Immediate).map_err(db_err)?;

        // Declared outside the table scope: segment bytes are synced before the commit.
        let mut stats: HashMap<u64, SegStat> = HashMap::new();
        let mut files: HashMap<u64, File> = HashMap::new();
        let mut new_dirs: HashSet<PathBuf> = HashSet::new();
        let mut dead: Vec<PathBuf> = Vec::new();

        {
            let mut headers = txn.open_table(HEADERS).map_err(db_err)?;
            let mut nodes = txn.open_table(NODES).map_err(db_err)?;
            let mut blocks = txn.open_table(BLOCKS).map_err(db_err)?;
            let mut bitfield = txn.open_table(BITFIELD).map_err(db_err)?;
            let mut user = txn.open_table(USER).map_err(db_err)?;
            let mut segments = txn.open_table(SEGMENTS).map_err(db_err)?;

            for op in batch.ops {
                match op {
                    Op::Header(value) => {
                        headers.insert(&dk[..], &value[..]).map_err(db_err)?;
                    }
                    Op::PutNode(node) => {
                        let value = node_value(&node);
                        nodes
                            .insert(&core_key(dk, node.index)[..], &value[..])
                            .map_err(db_err)?;
                    }
                    Op::DeleteNode(index) => {
                        nodes.remove(&core_key(dk, index)[..]).map_err(db_err)?;
                    }
                    Op::DeleteNodeRange(start, end) => {
                        let entries =
                            range_entries(&nodes, &core_key(dk, start), &core_key(dk, end))?;
                        for (key, _) in entries {
                            nodes.remove(key.as_slice()).map_err(db_err)?;
                        }
                    }
                    Op::PutBlock(index, data) => {
                        let key = core_key(dk, index);
                        let old = blocks
                            .get(&key[..])
                            .map_err(db_err)?
                            .map(|v| v.value().to_vec());
                        if let Some(old) = old {
                            free_old_block(&mut stats, &segments, dk, &old)?;
                        }
                        if data.len() < SEGMENT_MIN {
                            let mut value = Vec::with_capacity(data.len() + 1);
                            value.push(TAG_INLINE);
                            value.extend_from_slice(&data);
                            blocks.insert(&key[..], value.as_slice()).map_err(db_err)?;
                        } else {
                            let segment = index / BLOCKS_PER_SEGMENT;
                            let stat = seg_stat(&mut stats, &segments, dk, segment)?;
                            let offset = stat.size;
                            let len = data.len() as u64;
                            put_segment_bytes(
                                inner,
                                dk,
                                segment,
                                &mut files,
                                &mut new_dirs,
                                offset,
                                &data,
                            )?;
                            stat.size += len;
                            stat.live += len;
                            let value = segment_entry(segment, offset, len);
                            blocks.insert(&key[..], &value[..]).map_err(db_err)?;
                        }
                    }
                    Op::DeleteBlockRange(start, end) => {
                        let entries =
                            range_entries(&blocks, &core_key(dk, start), &core_key(dk, end))?;
                        for (key, value) in entries {
                            free_old_block(&mut stats, &segments, dk, &value)?;
                            blocks.remove(key.as_slice()).map_err(db_err)?;
                        }
                    }
                    Op::PutBitfieldPage(page, Some(value)) => {
                        bitfield
                            .insert(&core_key(dk, page)[..], &value[..])
                            .map_err(db_err)?;
                    }
                    Op::PutBitfieldPage(page, None) => {
                        bitfield.remove(&core_key(dk, page)[..]).map_err(db_err)?;
                    }
                    Op::PutUserData(key, Some(value)) => {
                        user.insert(&user_key(dk, &key)[..], &value[..])
                            .map_err(db_err)?;
                    }
                    Op::PutUserData(key, None) => {
                        user.remove(&user_key(dk, &key)[..]).map_err(db_err)?;
                    }
                }
            }

            // Segments that lost their last live byte are dropped once the commit lands.
            for (segment, stat) in &stats {
                let key = core_key(dk, *segment);
                if stat.live == 0 {
                    segments.remove(&key[..]).map_err(db_err)?;
                    dead.push(inner.segment_path(dk, *segment));
                } else {
                    segments
                        .insert(&key[..], &seg_record(stat)[..])
                        .map_err(db_err)?;
                }
            }

            // Crash ordering: segment bytes and the directory entries of new segment files
            // reach disk before the redb commit. A file fsync does not persist its directory
            // entry on Linux, so new files also sync their directories.
            for file in files.values() {
                file.sync_data()?;
            }
            for dir in &new_dirs {
                sync_dir_chain(inner, dir)?;
            }
        }

        drop(files);
        txn.commit().map_err(db_err)?;
        for path in dead {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            // Evict after the unlink: a reader that reopened the old inode between the
            // previous eviction and this unlink must not serve a future record.
            inner.evict(&path);
        }
        Ok(())
    }
}

/// Ordered operations for one atomic [`CoreStorage::write`].
#[derive(Default)]
pub struct Batch {
    ops: Vec<Op>,
}

enum Op {
    Header(Bytes),
    PutNode(Node),
    DeleteNode(u64),
    DeleteNodeRange(u64, u64),
    PutBlock(u64, Bytes),
    DeleteBlockRange(u64, u64),
    PutBitfieldPage(u64, Option<Bytes>),
    PutUserData(String, Option<Bytes>),
}

impl Batch {
    /// Store the core header.
    pub fn set_header(&mut self, header: Bytes) {
        self.ops.push(Op::Header(header));
    }

    /// Write or replace a tree node.
    pub fn put_tree_node(&mut self, node: Node) {
        self.ops.push(Op::PutNode(node));
    }

    /// Delete one tree node.
    pub fn delete_tree_node(&mut self, index: u64) {
        self.ops.push(Op::DeleteNode(index));
    }

    /// Delete tree nodes in `[start, end)`.
    pub fn delete_tree_range(&mut self, start: u64, end: u64) {
        self.ops.push(Op::DeleteNodeRange(start, end));
    }

    /// Write or replace a block.
    pub fn put_block(&mut self, index: u64, data: Bytes) {
        self.ops.push(Op::PutBlock(index, data));
    }

    /// Delete blocks in `[start, end)`.
    pub fn delete_block_range(&mut self, start: u64, end: u64) {
        self.ops.push(Op::DeleteBlockRange(start, end));
    }

    /// Write or delete a bitfield page.
    pub fn put_bitfield_page(&mut self, page: u64, data: Option<Bytes>) {
        self.ops.push(Op::PutBitfieldPage(page, data));
    }

    /// Write or delete a user-data value.
    pub fn put_user_data(&mut self, key: &str, value: Option<Bytes>) {
        self.ops.push(Op::PutUserData(key.to_string(), value));
    }

    /// Whether the batch holds no operations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

#[derive(Clone, Copy)]
struct SegStat {
    size: u64,
    live: u64,
}

/// Segment state for `segment`, loading it into `stats` on first use.
fn seg_stat<'a>(
    stats: &'a mut HashMap<u64, SegStat>,
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    dk: &[u8; 32],
    segment: u64,
) -> Result<&'a mut SegStat> {
    let stat = match stats.entry(segment) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let value = table.get(&core_key(dk, segment)[..]).map_err(db_err)?;
            let stat = match value {
                Some(v) => decode_seg_record(v.value())?,
                None => SegStat { size: 0, live: 0 },
            };
            entry.insert(stat)
        }
    };
    Ok(stat)
}

/// Drop the live-byte accounting of an existing block entry.
fn free_old_block(
    stats: &mut HashMap<u64, SegStat>,
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    dk: &[u8; 32],
    entry: &[u8],
) -> Result<()> {
    if entry.first() != Some(&TAG_SEGMENT) {
        return Ok(());
    }
    let (segment, _, len) = decode_segment_entry(entry)?;
    let stat = seg_stat(stats, table, dk, segment)?;
    stat.live = stat.live.saturating_sub(len);
    Ok(())
}

/// Append bytes to a segment file at a recorded offset; never at the end of the file,
/// so bytes left by a crash before commit are overwritten.
fn put_segment_bytes(
    inner: &StoreInner,
    dk: &[u8; 32],
    segment: u64,
    files: &mut HashMap<u64, File>,
    new_dirs: &mut HashSet<PathBuf>,
    offset: u64,
    data: &[u8],
) -> Result<()> {
    let file = match files.entry(segment) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let path = inner.segment_path(dk, segment);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            let file = match options.open(&path) {
                Ok(file) => {
                    if let Some(parent) = path.parent() {
                        new_dirs.insert(parent.to_path_buf());
                    }
                    file
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    OpenOptions::new().read(true).write(true).open(&path)?
                }
                Err(e) => return Err(e.into()),
            };
            entry.insert(file)
        }
    };
    // write_all_at: a short write must never leave a record pointing past EOF.
    file.write_all_at(data, offset)?;
    Ok(())
}

/// Persist the directories that hold a new segment file's directory entry.
fn sync_dir_chain(inner: &StoreInner, dir: &Path) -> Result<()> {
    let mut current = Some(dir);
    while let Some(path) = current {
        if !path.starts_with(&inner.dir) {
            break;
        }
        File::open(path)?.sync_all()?;
        if path == inner.dir {
            break;
        }
        current = path.parent();
    }
    Ok(())
}

fn delete_prefix(
    table: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    dk: &[u8; 32],
) -> Result<()> {
    let entries = prefix_entries(&*table, dk)?;
    for (key, _) in entries {
        table.remove(key.as_slice()).map_err(db_err)?;
    }
    Ok(())
}

fn range_entries<T>(table: &T, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut out = Vec::new();
    for entry in table.range(start..end).map_err(db_err)? {
        let (key, value) = entry.map_err(db_err)?;
        out.push((key.value().to_vec(), value.value().to_vec()));
    }
    Ok(out)
}

fn prefix_entries<T>(table: &T, dk: &[u8; 32]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    match next_prefix(dk) {
        Some(end) => range_entries(table, &dk[..], &end),
        // A discovery key of all 0xff has no successor byte string.
        None => {
            let mut out = Vec::new();
            for entry in table.iter().map_err(db_err)? {
                let (key, value) = entry.map_err(db_err)?;
                if key.value().starts_with(dk) {
                    out.push((key.value().to_vec(), value.value().to_vec()));
                }
            }
            Ok(out)
        }
    }
}

/// Smallest byte string greater than every string starting with `dk`.
fn next_prefix(dk: &[u8; 32]) -> Option<Vec<u8>> {
    for i in (0..dk.len()).rev() {
        if dk[i] != 0xff {
            let mut end = dk[..=i].to_vec();
            end[i] += 1;
            return Some(end);
        }
    }
    None
}

fn core_key(dk: &[u8; 32], n: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(dk);
    key[32..].copy_from_slice(&n.to_be_bytes());
    key
}

fn user_key(dk: &[u8; 32], name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + name.len());
    key.extend_from_slice(dk);
    key.extend_from_slice(name.as_bytes());
    key
}

fn node_value(node: &Node) -> [u8; 40] {
    let mut value = [0u8; 40];
    value[..8].copy_from_slice(&node.size.to_le_bytes());
    value[8..].copy_from_slice(&node.hash);
    value
}

fn decode_node(index: u64, value: &[u8]) -> Result<Node> {
    if value.len() != 40 {
        return Err(corrupt("tree node record has the wrong length"));
    }
    let mut size = [0u8; 8];
    size.copy_from_slice(&value[..8]);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&value[8..]);
    Ok(Node {
        index,
        size: u64::from_le_bytes(size),
        hash,
    })
}

fn segment_entry(segment: u64, offset: u64, len: u64) -> [u8; 25] {
    let mut value = [0u8; 25];
    value[0] = TAG_SEGMENT;
    value[1..9].copy_from_slice(&segment.to_le_bytes());
    value[9..17].copy_from_slice(&offset.to_le_bytes());
    value[17..25].copy_from_slice(&len.to_le_bytes());
    value
}

fn decode_segment_entry(value: &[u8]) -> Result<(u64, u64, u64)> {
    if value.len() != 25 {
        return Err(corrupt("segment block record has the wrong length"));
    }
    let mut segment = [0u8; 8];
    segment.copy_from_slice(&value[1..9]);
    let mut offset = [0u8; 8];
    offset.copy_from_slice(&value[9..17]);
    let mut len = [0u8; 8];
    len.copy_from_slice(&value[17..25]);
    Ok((
        u64::from_le_bytes(segment),
        u64::from_le_bytes(offset),
        u64::from_le_bytes(len),
    ))
}

fn seg_record(stat: &SegStat) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&stat.size.to_le_bytes());
    value[8..].copy_from_slice(&stat.live.to_le_bytes());
    value
}

fn decode_seg_record(value: &[u8]) -> Result<SegStat> {
    if value.len() != 16 {
        return Err(corrupt("segment record has the wrong length"));
    }
    let mut size = [0u8; 8];
    size.copy_from_slice(&value[..8]);
    let mut live = [0u8; 8];
    live.copy_from_slice(&value[8..]);
    Ok(SegStat {
        size: u64::from_le_bytes(size),
        live: u64::from_le_bytes(live),
    })
}

fn decode_index(key: &[u8], what: &str) -> Result<u64> {
    if key.len() != 40 {
        return Err(corrupt(what));
    }
    let mut n = [0u8; 8];
    n.copy_from_slice(&key[32..]);
    Ok(u64::from_be_bytes(n))
}

fn hex(dk: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in dk {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    use std::time::Instant;
    use tempfile::TempDir;

    fn dk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn block_data(len: usize, seed: u8) -> Bytes {
        Bytes::from(
            (0..len)
                .map(|i| seed.wrapping_add(i as u8))
                .collect::<Vec<u8>>(),
        )
    }

    fn segment_record(store: &Store, key: &[u8; 32], segment: u64) -> Option<(u64, u64)> {
        let db = store.inner.db.read().unwrap();
        let txn = db.as_ref().unwrap().begin_read().unwrap();
        let table = txn.open_table(SEGMENTS).unwrap();
        let value = table.get(&core_key(key, segment)[..]).unwrap()?;
        let stat = decode_seg_record(value.value()).unwrap();
        Some((stat.size, stat.live))
    }

    fn raw_block(store: &Store, key: &[u8; 32], index: u64) -> Option<Vec<u8>> {
        let db = store.inner.db.read().unwrap();
        let txn = db.as_ref().unwrap().begin_read().unwrap();
        let table = txn.open_table(BLOCKS).unwrap();
        let value = table.get(&core_key(key, index)[..]).unwrap()?;
        Some(value.value().to_vec())
    }

    fn node(index: u64, size: u64, byte: u8) -> Node {
        Node {
            index,
            size,
            hash: [byte; 32],
        }
    }

    #[test]
    fn round_trip_every_record() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(1);
        let core = store.core(&key);

        let mut batch = Batch::default();
        assert!(batch.is_empty());
        batch.set_header(Bytes::from_static(b"header"));
        batch.put_tree_node(node(3, 7, 9));
        batch.put_tree_node(node(5, 1, 1));
        batch.put_tree_node(node(6, 2, 2));
        batch.put_tree_node(node(7, 3, 3));
        batch.put_block(0, block_data(100, 1));
        batch.put_block(200, block_data(40_000, 2));
        batch.put_bitfield_page(2, Some(Bytes::from_static(b"bits")));
        batch.put_user_data("name", Some(Bytes::from_static(b"value")));
        assert!(!batch.is_empty());
        core.write(batch).unwrap();

        assert_eq!(
            core.header().unwrap().unwrap(),
            Bytes::from_static(b"header")
        );
        assert_eq!(core.tree_node(3).unwrap().unwrap(), node(3, 7, 9));
        assert!(core.has_tree_node(3).unwrap());
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(100, 1));
        assert_eq!(core.block(200).unwrap().unwrap(), block_data(40_000, 2));
        assert_eq!(
            core.bitfield_pages().unwrap(),
            vec![(2, Bytes::from_static(b"bits"))]
        );
        assert_eq!(
            core.user_data("name").unwrap().unwrap(),
            Bytes::from_static(b"value")
        );
        assert_eq!(
            core.user_data_all().unwrap(),
            vec![("name".to_string(), Bytes::from_static(b"value"))]
        );

        let mut batch = Batch::default();
        batch.delete_tree_node(3);
        batch.delete_tree_range(5, 7);
        batch.put_bitfield_page(2, None);
        batch.put_user_data("name", None);
        core.write(batch).unwrap();

        assert!(core.tree_node(3).unwrap().is_none());
        assert!(!core.has_tree_node(3).unwrap());
        assert!(core.tree_node(5).unwrap().is_none());
        assert!(core.tree_node(6).unwrap().is_none());
        assert!(core.tree_node(7).unwrap().is_some());
        assert!(core.bitfield_pages().unwrap().is_empty());
        assert!(core.user_data("name").unwrap().is_none());
        assert!(core.user_data_all().unwrap().is_empty());

        store.put_meta("primary", Some(b"key")).unwrap();
        assert_eq!(
            store.get_meta("primary").unwrap().unwrap(),
            Bytes::from_static(b"key")
        );
        store.put_meta("primary", None).unwrap();
        assert!(store.get_meta("primary").unwrap().is_none());
    }

    #[test]
    fn reopen_persists() {
        let dir = TempDir::new().unwrap();
        let key = dk(2);
        {
            let store = Store::open(dir.path()).unwrap();
            let core = store.core(&key);
            let mut batch = Batch::default();
            batch.set_header(Bytes::from_static(b"h"));
            batch.put_tree_node(node(0, 4, 4));
            batch.put_block(128, block_data(30_000, 5));
            batch.put_user_data("k", Some(Bytes::from_static(b"v")));
            core.write(batch).unwrap();
            store.put_meta("primary", Some(&[7u8; 32][..])).unwrap();
        }
        let store = Store::open(dir.path()).unwrap();
        let core = store.core(&key);
        assert_eq!(core.header().unwrap().unwrap(), Bytes::from_static(b"h"));
        assert_eq!(core.tree_node(0).unwrap().unwrap(), node(0, 4, 4));
        assert_eq!(core.block(128).unwrap().unwrap(), block_data(30_000, 5));
        assert_eq!(
            core.user_data("k").unwrap().unwrap(),
            Bytes::from_static(b"v")
        );
        assert_eq!(
            store.get_meta("primary").unwrap().unwrap(),
            Bytes::copy_from_slice(&[7u8; 32])
        );
        assert_eq!(store.cores().unwrap(), vec![key]);
    }

    #[test]
    fn inline_and_segment_threshold() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(3);
        let core = store.core(&key);

        let mut batch = Batch::default();
        batch.put_block(0, block_data(SEGMENT_MIN - 1, 9));
        core.write(batch).unwrap();
        assert_eq!(raw_block(&store, &key, 0).unwrap()[0], TAG_INLINE);
        assert!(segment_record(&store, &key, 0).is_none());
        assert!(!store.inner.segment_path(&key, 0).exists());

        let mut batch = Batch::default();
        batch.put_block(1, block_data(SEGMENT_MIN, 9));
        core.write(batch).unwrap();
        assert_eq!(raw_block(&store, &key, 1).unwrap()[0], TAG_SEGMENT);
        assert_eq!(
            segment_record(&store, &key, 0),
            Some((SEGMENT_MIN as u64, SEGMENT_MIN as u64))
        );
        assert!(store.inner.segment_path(&key, 0).exists());
        assert_eq!(core.block(1).unwrap().unwrap(), block_data(SEGMENT_MIN, 9));
    }

    #[test]
    fn segment_delete_semantics() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(4);
        let core = store.core(&key);
        let size = 20_000u64;
        let path = store.inner.segment_path(&key, 0);

        let mut batch = Batch::default();
        for index in 0..3 {
            batch.put_block(index, block_data(size as usize, index as u8));
        }
        core.write(batch).unwrap();
        assert_eq!(segment_record(&store, &key, 0), Some((3 * size, 3 * size)));
        assert!(path.exists());

        let mut batch = Batch::default();
        batch.delete_block_range(0, 2);
        core.write(batch).unwrap();
        assert_eq!(segment_record(&store, &key, 0), Some((3 * size, size)));
        assert!(path.exists());
        assert!(core.block(0).unwrap().is_none());
        assert!(core.block(1).unwrap().is_none());
        assert_eq!(
            core.block(2).unwrap().unwrap(),
            block_data(size as usize, 2)
        );

        let mut batch = Batch::default();
        batch.delete_block_range(2, 3);
        core.write(batch).unwrap();
        assert!(segment_record(&store, &key, 0).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn overwrite_accounting() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(5);
        let core = store.core(&key);
        let path = store.inner.segment_path(&key, 0);

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 1));
        core.write(batch).unwrap();
        assert_eq!(segment_record(&store, &key, 0), Some((20_000, 20_000)));

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 2));
        core.write(batch).unwrap();
        assert_eq!(segment_record(&store, &key, 0), Some((40_000, 20_000)));
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(20_000, 2));

        let mut batch = Batch::default();
        batch.put_block(0, block_data(100, 3));
        core.write(batch).unwrap();
        assert!(segment_record(&store, &key, 0).is_none());
        assert!(!path.exists());
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(100, 3));

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 4));
        core.write(batch).unwrap();
        assert_eq!(segment_record(&store, &key, 0), Some((20_000, 20_000)));
        let mut batch = Batch::default();
        batch.delete_block_range(0, 1);
        core.write(batch).unwrap();
        assert!(segment_record(&store, &key, 0).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn same_batch_overwrite_keeps_accounting() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(15);
        let core = store.core(&key);

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 1));
        batch.put_block(0, block_data(20_000, 2));
        batch.put_block(1, block_data(100, 3));
        batch.put_block(1, block_data(40_000, 4));
        core.write(batch).unwrap();

        assert_eq!(segment_record(&store, &key, 0), Some((80_000, 60_000)));
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(20_000, 2));
        assert_eq!(core.block(1).unwrap().unwrap(), block_data(40_000, 4));
    }

    #[test]
    fn block_accounting_matches_files() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(16);
        let core = store.core(&key);

        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };
        let mut model: HashMap<u64, Vec<u8>> = HashMap::new();

        for _ in 0..150 {
            let mut batch = Batch::default();
            match next() % 3 {
                0 | 2 => {
                    let index = next() % 300;
                    let len = [50usize, 20_000, 60_000][(next() % 3) as usize];
                    let data: Vec<u8> = (0..len)
                        .map(|i| (index as u8).wrapping_add(i as u8))
                        .collect();
                    batch.put_block(index, Bytes::copy_from_slice(&data));
                    model.insert(index, data);
                }
                _ => {
                    let start = next() % 300;
                    let end = start + next() % 6;
                    batch.delete_block_range(start, end);
                    for index in start..end {
                        model.remove(&index);
                    }
                }
            }
            core.write(batch).unwrap();
        }

        for (index, data) in &model {
            let got = core.block(*index).unwrap().unwrap();
            assert_eq!(&got, data);
        }
        for index in 0..300 {
            if !model.contains_key(&index) {
                assert!(core.block(index).unwrap().is_none());
            }
        }

        let db = store.inner.db.read().unwrap();
        let txn = db.as_ref().unwrap().begin_read().unwrap();
        let blocks = txn.open_table(BLOCKS).unwrap();
        let mut live: HashMap<u64, u64> = HashMap::new();
        assert_eq!(prefix_entries(&blocks, &key).unwrap().len(), model.len());
        for (_, value) in prefix_entries(&blocks, &key).unwrap() {
            if value[0] == TAG_SEGMENT {
                let (segment, _, len) = decode_segment_entry(&value).unwrap();
                *live.entry(segment).or_default() += len;
            }
        }
        let segments = txn.open_table(SEGMENTS).unwrap();
        for (record_key, value) in prefix_entries(&segments, &key).unwrap() {
            let segment = u64::from_be_bytes(record_key[32..].try_into().unwrap());
            let stat = decode_seg_record(&value).unwrap();
            assert!(stat.live > 0);
            assert_eq!(stat.live, live.remove(&segment).unwrap_or(0));
            let path = store.inner.segment_path(&key, segment);
            assert_eq!(std::fs::metadata(path).unwrap().len(), stat.size);
        }
        assert!(live.is_empty());
    }

    #[test]
    fn concurrent_writers() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut handles = Vec::new();
        for t in 0..4u8 {
            let core = store.core(&dk(20 + t));
            handles.push(std::thread::spawn(move || {
                for index in 0..25u64 {
                    let seed = t.wrapping_mul(31).wrapping_add(index as u8);
                    let mut batch = Batch::default();
                    batch.put_block(index, block_data(20_000, seed));
                    core.write(batch).unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        for t in 0..4u8 {
            let core = store.core(&dk(20 + t));
            for index in 0..25u64 {
                let seed = t.wrapping_mul(31).wrapping_add(index as u8);
                assert_eq!(
                    core.block(index).unwrap().unwrap(),
                    block_data(20_000, seed)
                );
            }
        }
    }

    #[test]
    fn delete_core_removes_everything() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(6);
        let other = dk(7);
        let core = store.core(&key);

        let mut batch = Batch::default();
        batch.set_header(Bytes::from_static(b"h"));
        batch.put_tree_node(node(0, 1, 1));
        batch.put_block(0, block_data(30_000, 1));
        batch.put_bitfield_page(0, Some(Bytes::from_static(b"b")));
        batch.put_user_data("u", Some(Bytes::from_static(b"d")));
        core.write(batch).unwrap();
        store.put_meta("primary", Some(b"p")).unwrap();

        let mut batch = Batch::default();
        batch.set_header(Bytes::from_static(b"other"));
        batch.put_block(0, block_data(30_000, 2));
        store.core(&other).write(batch).unwrap();

        assert!(store.inner.core_dir(&key).exists());
        store.delete_core(&key).unwrap();

        assert!(core.header().unwrap().is_none());
        assert!(core.tree_node(0).unwrap().is_none());
        assert!(core.block(0).unwrap().is_none());
        assert!(core.bitfield_pages().unwrap().is_empty());
        assert!(core.user_data_all().unwrap().is_empty());
        assert!(!store.inner.core_dir(&key).exists());
        assert_eq!(store.cores().unwrap(), vec![other]);
        assert_eq!(
            store.get_meta("primary").unwrap().unwrap(),
            Bytes::from_static(b"p")
        );

        let other_core = store.core(&other);
        assert!(other_core.header().unwrap().is_some());
        assert_eq!(other_core.block(0).unwrap().unwrap(), block_data(30_000, 2));
        store.delete_core(&other).unwrap();
        assert!(store.cores().unwrap().is_empty());
    }

    #[test]
    fn cores_lists_headers_only() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(8);
        let empty = dk(9);

        let mut batch = Batch::default();
        batch.set_header(Bytes::from_static(b"h"));
        store.core(&key).write(batch).unwrap();

        let mut batch = Batch::default();
        batch.put_block(0, block_data(100, 1));
        store.core(&empty).write(batch).unwrap();

        assert_eq!(store.cores().unwrap(), vec![key]);
        assert!(store.core(&dk(10)).header().unwrap().is_none());
    }

    #[test]
    fn garbage_past_recorded_size_is_overwritten() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(11);
        let core = store.core(&key);
        let size = 20_000u64;
        let path = store.inner.segment_path(&key, 0);

        let mut batch = Batch::default();
        batch.put_block(0, block_data(size as usize, 1));
        core.write(batch).unwrap();

        // Bytes a crash could have left after a write that never committed.
        let file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all_at(&[0xaa; 4096], size).unwrap();
        assert_eq!(file.metadata().unwrap().len(), size + 4096);

        let mut batch = Batch::default();
        batch.put_block(1, block_data(size as usize, 2));
        core.write(batch).unwrap();

        assert_eq!(
            core.block(0).unwrap().unwrap(),
            block_data(size as usize, 1)
        );
        assert_eq!(
            core.block(1).unwrap().unwrap(),
            block_data(size as usize, 2)
        );
        assert_eq!(segment_record(&store, &key, 0), Some((2 * size, 2 * size)));
        assert_eq!(file.metadata().unwrap().len(), 2 * size);
    }

    #[test]
    fn deleted_segment_is_not_read_through_a_cached_handle() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(13);
        let core = store.core(&key);

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 1));
        core.write(batch).unwrap();
        // Populate the handle cache before the segment file is unlinked.
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(20_000, 1));

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 2));
        core.write(batch).unwrap();
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(20_000, 2));

        let mut batch = Batch::default();
        batch.delete_block_range(0, 1);
        core.write(batch).unwrap();
        assert!(!store.inner.segment_path(&key, 0).exists());

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 3));
        core.write(batch).unwrap();
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(20_000, 3));
    }

    #[test]
    fn recreated_core_does_not_read_deleted_segments() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(14);

        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 1));
        store.core(&key).write(batch).unwrap();
        assert!(store.core(&key).block(0).unwrap().is_some());

        store.delete_core(&key).unwrap();
        assert!(!store.inner.core_dir(&key).exists());

        let core = store.core(&key);
        let mut batch = Batch::default();
        batch.put_block(0, block_data(20_000, 2));
        batch.set_header(Bytes::from_static(b"h"));
        core.write(batch).unwrap();
        assert_eq!(core.block(0).unwrap().unwrap(), block_data(20_000, 2));
        assert_eq!(core.header().unwrap().unwrap(), Bytes::from_static(b"h"));
    }

    #[test]
    fn large_blocks_throughput() {
        let dir = TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = dk(12);
        let core = store.core(&key);
        const BLOCK: usize = 512 * 1024;
        const COUNT: u64 = 300;
        let blocks: Vec<Bytes> = (0..COUNT)
            .map(|i| Bytes::from(vec![i as u8; BLOCK]))
            .collect();
        let total = COUNT as f64 * BLOCK as f64 / (1024.0 * 1024.0);

        let mut batch = Batch::default();
        for (index, block) in blocks.iter().enumerate() {
            batch.put_block(index as u64, block.clone());
        }
        let start = Instant::now();
        core.write(batch).unwrap();
        let write_secs = start.elapsed().as_secs_f64();

        let start = Instant::now();
        for (index, block) in blocks.iter().enumerate() {
            let got = core.block(index as u64).unwrap().unwrap();
            assert_eq!(&got, block);
        }
        let read_secs = start.elapsed().as_secs_f64();

        println!(
            "512 KiB x {COUNT}: write {:.1} MiB/s, read {:.1} MiB/s ({total:.0} MiB)",
            total / write_secs,
            total / read_secs
        );
        for segment in 0..3 {
            assert!(store.inner.segment_path(&key, segment).exists());
        }
    }
}
