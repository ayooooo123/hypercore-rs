//! One Hypercore: its persisted header, merkle tree, bitfield and blocks, and
//! the local operations on them. Replication drives `verify_*` and `reorg`.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;

use compact_encoding::Bytes;
use compact_encoding::hypercore::{Data, Manifest, Node};
use tokio::sync::{broadcast, watch};

use crate::bitfield::Bitfield;
use crate::crypto::{self, KeyPair};
use crate::encryption::{BlockEncryption, EncryptionOptions, PADDING};
use crate::flat_tree::{self, Iter};
use crate::merkle::{self, Batch, MerkleError, NodeStore, ProofRequest, TreeState};
use crate::replicator::Replicator;
use crate::storage::{self, CoreStorage, StorageError, Store};
use crate::verifier::{self, Verifier};

#[derive(Debug)]
pub enum CoreError {
    Storage(StorageError),
    Merkle(MerkleError),
    NotWritable,
    BadArgument(String),
    InvalidSignature,
    InvalidManifest,
    NotFound,
    Timeout,
    Cancelled,
    CancelledWithReason(String),
    /// The block was truncated away while being requested.
    SnapshotNotAvailable,
    Closed,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::Merkle(e) => write!(f, "{e}"),
            Self::NotWritable => f.write_str("SESSION_NOT_WRITABLE"),
            Self::BadArgument(m) => write!(f, "BAD_ARGUMENT: {m}"),
            Self::InvalidSignature => {
                f.write_str("INVALID_SIGNATURE: Proof contains an invalid signature")
            }
            Self::InvalidManifest => {
                f.write_str("INVALID_SIGNATURE: Proof contains an invalid manifest")
            }
            Self::NotFound => f.write_str("core not found in storage"),
            Self::Timeout => f.write_str("REQUEST_TIMEOUT"),
            Self::Cancelled => f.write_str("REQUEST_CANCELLED"),
            Self::CancelledWithReason(reason) => write!(f, "REQUEST_CANCELLED: {reason}"),
            Self::SnapshotNotAvailable => f.write_str("SNAPSHOT_NOT_AVAILABLE"),
            Self::Closed => f.write_str("SESSION_CLOSED"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<StorageError> for CoreError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Closed => Self::Closed,
            other => Self::Storage(other),
        }
    }
}

impl From<MerkleError> for CoreError {
    fn from(e: MerkleError) -> Self {
        Self::Merkle(e)
    }
}

pub type Result<T, E = CoreError> = std::result::Result<T, E>;
/// A shared, sticky cancellation scope for block and range requests.
#[derive(Debug, Clone)]
pub struct RequestBag {
    reason: watch::Sender<Option<String>>,
}

impl Default for RequestBag {
    fn default() -> Self {
        Self {
            reason: watch::channel(None).0,
        }
    }
}

impl RequestBag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn destroy(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.reason.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(reason);
                true
            }
        });
    }

    fn error(&self) -> Option<CoreError> {
        self.reason
            .borrow()
            .clone()
            .map(CoreError::CancelledWithReason)
    }

    async fn cancelled(&self) -> CoreError {
        let mut receiver = self.reason.subscribe();
        loop {
            if let Some(reason) = receiver.borrow_and_update().clone() {
                return CoreError::CancelledWithReason(reason);
            }
            let _ = receiver.changed().await;
        }
    }
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl NodeStore for CoreStorage {
    fn node(&self, index: u64) -> merkle::Result<Option<compact_encoding::hypercore::Node>> {
        self.get_tree_node(index)
            .map_err(|e| MerkleError::Storage(e.to_string()))
    }

    fn nodes(&self, indices: &[u64]) -> merkle::Result<Vec<Option<Node>>> {
        self.get_tree_nodes(indices)
            .map_err(|e| MerkleError::Storage(e.to_string()))
    }

    fn missing_prefix(&self, indices: impl Iterator<Item = u64>) -> merkle::Result<u64> {
        self.missing_tree_nodes(indices)
            .map_err(|e| MerkleError::Storage(e.to_string()))
    }
}

/// How to open (or create) a core.
#[derive(Clone)]
pub struct CoreOptions {
    pub key: Option<[u8; 32]>,
    pub key_pair: Option<KeyPair>,
    pub manifest: Option<Manifest>,
    pub encryption_key: Option<[u8; 32]>,
    pub encryption: EncryptionOptions,
    pub manifest_version: u64,
    pub inflight_range: Option<(u32, u32)>,
    /// Join this topic's group (`core.setGroup` on open).
    pub group: Option<[u8; 32]>,
    /// Fail with `NotFound` instead of creating the core.
    pub no_create: bool,
}

impl Default for CoreOptions {
    fn default() -> Self {
        Self {
            key: None,
            key_pair: None,
            manifest: None,
            encryption_key: None,
            encryption: EncryptionOptions::default(),
            manifest_version: 1,
            inflight_range: None,
            group: None,
            no_create: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreEvent {
    Append {
        start: u64,
        length: u64,
    },
    /// A block was received and stored. `from` is the public key of the peer that sent it
    /// (JS `core.on('download', (index, byteLength, from))`'s `from.remotePublicKey`), when
    /// the transport identifies the remote.
    Download {
        index: u64,
        byte_length: u64,
        from: Option<[u8; 32]>,
    },
    Truncate {
        fork: u64,
        length: u64,
    },
    PeerAdd,
    PeerRemove,
    Close,
}

/// One member's head, as `core.ongroupupdate(topic, update)` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupUpdate {
    pub key: [u8; 32],
    pub length: u64,
    pub fork: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AppendOptions {
    pub writable: bool,
    pub max_length: Option<u64>,
}

/// Length, fork and byte length at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Head {
    pub fork: u64,
    pub length: u64,
    pub byte_length: u64,
}

/// The per-core metadata hypercore keeps in memory: the auth row, the head row
/// and the hints row of the current data pointer.
#[derive(Debug, Clone, Default)]
pub(crate) struct Header {
    pub key: [u8; 32],
    pub manifest: Option<Manifest>,
    pub secret_key: Option<[u8; 64]>,
    pub fork: u64,
    pub length: u64,
    pub signature: Option<Bytes>,
    /// Epoch milliseconds of the head row this header stands for
    /// (JS `core.header.tree.timestamp`); a group update row is keyed by it.
    pub timestamp: u64,
    pub contiguous_length: u64,
    pub remote_contiguous_length: u64,
    pub frozen: bool,
    pub group: Option<storage::CoreGroup>,
    pub encryption_key: Option<Bytes>,
}

impl Header {
    /// Reads a core's rows; `None` when the core has no auth row.
    pub(crate) fn load(storage: &CoreStorage) -> Result<Option<Self>> {
        let Some(auth) = storage.get_auth()? else {
            return Ok(None);
        };
        let head = storage.get_head()?.unwrap_or_default();
        let hints = storage.get_hints()?.unwrap_or_default();
        Ok(Some(Self {
            key: auth.key,
            manifest: auth.manifest,
            secret_key: auth.key_pair.as_ref().and_then(|pair| pair.secret_key),
            fork: head.fork,
            length: head.length,
            signature: head.signature,
            timestamp: head.timestamp,
            contiguous_length: hints.contiguous_length,
            remote_contiguous_length: hints.remote_contiguous_length,
            frozen: hints.recovering != 0,
            group: storage.get_group()?,
            encryption_key: auth.encryption_key,
        }))
    }

    /// The `@core/auth` row this header stands for.
    pub(crate) fn auth(&self) -> storage::Auth {
        let key_pair = self.secret_key.map(|secret| {
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&secret[32..]);
            storage::KeyPair {
                public_key,
                secret_key: Some(secret),
            }
        });
        storage::Auth {
            key: self.key,
            discovery_key: crypto::discovery_key(&self.key),
            manifest: self.manifest.clone(),
            key_pair,
            encryption_key: self.encryption_key.clone(),
        }
    }

    /// The `@core/head` row for a tree with `roots`, stamped `timestamp`.
    fn head_row_at(&self, roots: &[Node], timestamp: u64) -> storage::CoreHead {
        storage::CoreHead {
            fork: self.fork,
            length: self.length,
            root_hash: crypto::tree_hash(roots),
            signature: self.signature.clone(),
            timestamp,
        }
    }

    pub(crate) fn hints_row(&self) -> storage::HeaderHints {
        storage::HeaderHints {
            contiguous_length: self.contiguous_length,
            remote_contiguous_length: self.remote_contiguous_length,
            recovering: self.frozen as u64,
        }
    }

    /// Queues the auth row (and the group row) when they changed.
    pub(crate) fn write_auth(&self, tx: &mut storage::Batch) {
        tx.set_auth(&self.auth());
        if self.group.is_some() {
            tx.set_group(self.group);
        }
    }

    /// Queues the head and hints rows for a tree with `roots`, at the head
    /// timestamp this core already has (JS writes no head row for a plain
    /// download, a clear or a freeze).
    pub(crate) fn write_head(&self, tx: &mut storage::Batch, roots: &[Node]) {
        tx.set_head(&self.head_row_at(roots, self.timestamp));
        tx.set_hints(&self.hints_row());
    }

    /// Queues the head and hints rows for a new head, and moves this core's
    /// group update to it (`updateGroupIndex` + `setHead`).
    pub(crate) fn write_new_head(&mut self, tx: &mut storage::Batch, roots: &[Node]) {
        let previous = std::mem::replace(&mut self.timestamp, now_millis());
        tx.set_head(&self.head_row_at(roots, self.timestamp));
        tx.set_hints(&self.hints_row());
        if let Some(group) = &self.group {
            tx.delete_group_update(group.pointer, previous);
            tx.put_group_update(group.pointer, self.timestamp, &self.key);
        }
    }

    fn key_pair(&self) -> Option<KeyPair> {
        self.secret_key.map(|s| {
            let seed: [u8; 32] = s[..32].try_into().expect("seed");
            KeyPair::from_seed(&seed)
        })
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) struct State {
    pub header: Header,
    pub tree: TreeState,
    pub bitfield: Bitfield,
    pub verifier: Option<Verifier>,
    pub encryption: Option<BlockEncryption>,
    encryption_key: Option<([u8; 32], EncryptionOptions)>,
}

impl State {
    pub fn head(&self) -> Head {
        Head {
            fork: self.tree.fork,
            length: self.tree.length,
            byte_length: self.tree.byte_length,
        }
    }

    pub fn compat(&self) -> bool {
        self.verifier.as_ref().is_some_and(|v| v.compat)
    }

    /// JS `updateContigBatch`: the contiguous hint after `[start, start+len)` changed.
    fn contiguous_after(&self, start: u64, length: u64, drop: bool) -> u64 {
        let c = self.header.contiguous_length;
        let end = start + length;
        if drop {
            return c.min(start);
        }
        if c <= end && c >= start {
            let mut c = end;
            while self.bitfield.get(c) {
                c += 1;
            }
            return c;
        }
        c
    }

    fn set_bits(&mut self, start: u64, end: u64, value: bool) {
        self.bitfield.set_range(start, end, value);
        self.bitfield.clear_dirty();
    }

    fn set_manifest(&mut self, manifest: Manifest) {
        let verifier = Verifier::new(self.header.key, &manifest, false);
        self.tree.prologue = verifier.prologue.clone();
        if let Some((k, opts)) = self.encryption_key {
            let opts = EncryptionOptions {
                compat: verifier.compat || opts.compat,
                ..opts
            };
            self.encryption = Some(BlockEncryption::new(&k, &self.header.key, opts));
        }
        self.verifier = Some(verifier);
        self.header.manifest = Some(manifest);
    }

    /// `core._verifyBatchUpgrade`. Returns the manifest to persist, if new.
    fn verify_batch_upgrade(
        &self,
        batch: &Batch,
        manifest: Option<&Manifest>,
    ) -> Result<Option<Manifest>> {
        let key = self.header.key;
        let mut learned = None;
        let verifier = match &self.verifier {
            Some(v) => v.clone(),
            None => {
                let m = manifest
                    .cloned()
                    .unwrap_or_else(|| verifier::default_signer_manifest(key));
                let compat = m.signers.len() == 1 && m.signers[0].public_key == key;
                if !verifier::is_valid_manifest(&key, &m) && !compat {
                    return Err(CoreError::InvalidManifest);
                }
                learned = manifest
                    .cloned()
                    .filter(|m| verifier::is_valid_manifest(&key, m));
                Verifier::new(key, &m, false)
            }
        };
        if !verifier.verify(batch, batch.signature.as_deref()) {
            return Err(CoreError::InvalidSignature);
        }
        Ok(learned)
    }
}

/// Bitfield pages for storage after setting `[start, end)` to `value`.
fn bitfield_pages(
    bitfield: &Bitfield,
    start: u64,
    end: u64,
    value: bool,
    batch: &mut storage::Batch,
) {
    for (page, bytes) in bitfield.preview_range(start, end, value) {
        match bytes {
            Some(bytes) => batch.put_bitfield_page(page, Bytes::from(bytes)),
            None => batch.delete_bitfield_page(page),
        }
    }
}

type IdleHook = Box<dyn Fn(&Core) + Send + Sync>;
type GroupHook = Box<dyn Fn([u8; 32], GroupUpdate) + Send + Sync>;

pub(crate) struct Inner {
    pub storage: CoreStorage,
    pub store: Store,
    pub key: [u8; 32],
    pub discovery_key: [u8; 32],
    state: Mutex<State>,
    write: tokio::sync::Mutex<()>,
    exclusive: Arc<tokio::sync::Mutex<()>>,
    head: watch::Sender<Head>,
    events: OnceLock<broadcast::Sender<CoreEvent>>,
    closed: AtomicBool,
    pub(crate) inflight_range: Mutex<Option<(u32, u32)>>,
    pub replicator: OnceLock<Replicator>,
    sessions: AtomicUsize,
    session_lifecycle: Mutex<()>,
    leases: AtomicUsize,
    active_sessions: AtomicUsize,
    manually_active: AtomicBool,
    peers: AtomicUsize,
    idle_hook: OnceLock<IdleHook>,
    group_hook: OnceLock<GroupHook>,
}

/// A shared handle to one open core.
#[derive(Clone)]
pub struct Core {
    pub(crate) inner: Arc<Inner>,
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("storage task panicked")
}

impl Core {
    /// Opens (or creates) the core described by `opts` in `store`.
    pub fn open(store: &Store, opts: CoreOptions) -> Result<Core> {
        let manifest = opts.manifest.clone().or_else(|| {
            opts.key_pair.as_ref().map(|kp| {
                let mut manifest = verifier::default_signer_manifest(kp.public_key);
                manifest.version = opts.manifest_version;
                manifest
            })
        });
        let key = match (opts.key, &manifest) {
            (Some(k), _) => k,
            (None, Some(m)) => crypto::manifest_hash(m),
            (None, None) => {
                return Err(CoreError::BadArgument(
                    "a key, key pair or manifest is required".into(),
                ));
            }
        };
        let discovery_key = crypto::discovery_key(&key);
        let (storage, header) = match store.resume_core(&discovery_key)? {
            Some(storage) => {
                let mut header = Header::load(&storage)?.ok_or(CoreError::NotFound)?;
                if header.key != key {
                    return Err(CoreError::BadArgument(
                        "stored core has a different key".into(),
                    ));
                }
                if header.secret_key.is_none()
                    && let Some(pair) = &opts.key_pair
                {
                    header.secret_key = Some(pair.secret_key);
                    let mut tx = storage.write();
                    header.write_auth(&mut tx);
                    storage.flush(tx)?;
                }
                (storage, header)
            }
            None if opts.no_create => return Err(CoreError::NotFound),
            None => {
                let manifest = manifest.filter(|m| {
                    verifier::is_valid_manifest(&key, m)
                        || (m.signers.len() == 1 && m.signers[0].public_key == key)
                });
                let header = Header {
                    key,
                    manifest: manifest.clone(),
                    secret_key: opts.key_pair.as_ref().map(|kp| kp.secret_key),
                    encryption_key: opts.encryption_key.map(|key| Bytes::copy_from_slice(&key)),
                    ..Default::default()
                };
                let storage = store.create_core(storage::CreateCore {
                    key,
                    discovery_key,
                    manifest,
                    key_pair: header.auth().key_pair,
                    encryption_key: header.encryption_key.clone(),
                    ..Default::default()
                })?;
                (storage, header)
            }
        };
        Self::from_header(store.clone(), storage, header, &opts)
    }

    /// Opens a stored core knowing only its discovery key (a remote asked for it).
    pub fn open_by_discovery_key(
        store: &Store,
        discovery_key: &[u8; 32],
        opts: CoreOptions,
    ) -> Result<Core> {
        let storage = store
            .resume_core(discovery_key)?
            .ok_or(CoreError::NotFound)?;
        let header = Header::load(&storage)?.ok_or(CoreError::NotFound)?;
        Self::from_header(store.clone(), storage, header, &opts)
    }

    fn from_header(
        store: Store,
        storage: CoreStorage,
        header: Header,
        opts: &CoreOptions,
    ) -> Result<Core> {
        let roots = merkle::roots_at(&storage, header.length)?;
        let tree = TreeState {
            fork: header.fork,
            length: header.length,
            byte_length: merkle::total_size(&roots),
            roots,
            signature: header.signature.clone(),
            prologue: None,
        };
        let pages = storage.bitfield_pages()?;
        let key = header.key;
        let mut state = State {
            bitfield: Bitfield::from_pages(pages.iter().map(|(i, b)| (*i, b.as_ref()))),
            tree,
            verifier: None,
            encryption: None,
            encryption_key: opts.encryption_key.map(|k| (k, opts.encryption)),
            header,
        };
        match state.header.manifest.clone() {
            Some(m) => state.set_manifest(m),
            None => {
                if let Some((k, o)) = state.encryption_key {
                    state.encryption = Some(BlockEncryption::new(&k, &key, o));
                }
            }
        }
        // `opts.group`: `core._open` joins the group and rewrites the row.
        if let Some(topic) = opts.group {
            let group = match state.header.group {
                Some(group) if group.key == Some(topic) => group,
                Some(_) => {
                    return Err(CoreError::BadArgument(
                        "core is already registered to another group".into(),
                    ));
                }
                None => storage::CoreGroup {
                    key: Some(topic),
                    pointer: store.create_group(&topic)?,
                },
            };
            state.header.group = Some(group);
            let mut tx = storage.write();
            tx.set_group(Some(group));
            storage.flush(tx)?;
        }
        let head = state.head();
        let core = Core {
            inner: Arc::new(Inner {
                discovery_key: crypto::discovery_key(&key),
                key,
                storage,
                store,
                state: Mutex::new(state),
                write: tokio::sync::Mutex::new(()),
                exclusive: Arc::new(tokio::sync::Mutex::new(())),
                head: watch::channel(head).0,
                events: OnceLock::new(),
                closed: AtomicBool::new(false),
                inflight_range: Mutex::new(opts.inflight_range),
                replicator: OnceLock::new(),
                sessions: AtomicUsize::new(0),
                session_lifecycle: Mutex::new(()),
                leases: AtomicUsize::new(0),
                active_sessions: AtomicUsize::new(0),
                manually_active: AtomicBool::new(false),
                peers: AtomicUsize::new(0),
                idle_hook: OnceLock::new(),
                group_hook: OnceLock::new(),
            }),
        };
        Ok(core)
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn stored_head(store: &Store, discovery_key: &[u8; 32]) -> Result<Option<Head>> {
        let Some(storage) = store.resume_core(discovery_key)? else {
            return Ok(None);
        };
        let Some(header) = Header::load(&storage)? else {
            return Ok(None);
        };
        let roots = merkle::roots_at(&storage, header.length)?;
        Ok(Some(Head {
            fork: header.fork,
            length: header.length,
            byte_length: merkle::total_size(&roots),
        }))
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.inner.key
    }

    pub fn discovery_key(&self) -> &[u8; 32] {
        &self.inner.discovery_key
    }

    /// Whether both handles refer to the same physical core.
    pub fn same_instance(&self, other: &Core) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn head(&self) -> Head {
        self.state().head()
    }

    pub fn length(&self) -> u64 {
        self.head().length
    }

    pub fn byte_length(&self) -> u64 {
        self.head().byte_length
    }

    pub fn fork(&self) -> u64 {
        self.head().fork
    }

    pub fn contiguous_length(&self) -> u64 {
        let st = self.state();
        st.header.contiguous_length.min(st.tree.length)
    }

    pub fn remote_contiguous_length(&self) -> u64 {
        let st = self.state();
        st.header.remote_contiguous_length.min(st.tree.length)
    }

    pub fn user_data(&self, key: &str) -> Result<Option<Bytes>> {
        self.ensure_open()?;
        Ok(self.inner.storage.get_user_data(key)?)
    }

    pub async fn set_user_data(&self, key: &str, value: Option<&[u8]>) -> Result<()> {
        let _w = self.inner.write.lock().await;
        self.ensure_open()?;
        if self.inner.storage.get_user_data(key)?.as_deref() == value {
            return Ok(());
        }
        let mut batch = self.inner.storage.write();
        batch.put_user_data(key, value.map(Bytes::copy_from_slice));
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(batch)).await?;
        Ok(())
    }

    pub async fn tree_hash(&self, length: u64) -> Result<[u8; 32]> {
        self.ensure_open()?;
        if length > 0 && !self.has(length - 1) {
            self.get(length - 1, GetOptions::default()).await?;
        }
        Ok(crypto::tree_hash(&merkle::roots_at(
            &self.inner.storage,
            length,
        )?))
    }

    pub fn writable(&self) -> bool {
        let st = self.state();
        !self.inner.store.read_only() && st.header.secret_key.is_some() && st.verifier.is_some()
    }

    pub fn manifest(&self) -> Option<Manifest> {
        self.state().header.manifest.clone()
    }

    /// Bytes of padding each stored block carries (encrypted cores only).
    pub fn padding(&self) -> usize {
        let st = self.state();
        if st.encryption.is_some() && st.header.manifest.is_some() {
            PADDING
        } else {
            0
        }
    }

    pub fn storage(&self) -> &CoreStorage {
        &self.inner.storage
    }

    /// Changes the replication window for current and future peers.
    pub fn set_inflight_range(&self, range: (u32, u32)) {
        *self
            .inner
            .inflight_range
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(range);
        if let Some(replicator) = self.inner.replicator.get() {
            replicator.set_inflight_range(range);
        }
    }

    pub fn inflight_range(&self) -> Option<(u32, u32)> {
        *self
            .inner
            .inflight_range
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Watches the head; changes on append, download upgrades and truncation.
    pub fn subscribe(&self) -> watch::Receiver<Head> {
        self.inner.head.subscribe()
    }

    pub fn events(&self) -> broadcast::Receiver<CoreEvent> {
        self.inner
            .events
            .get_or_init(|| broadcast::channel(256).0)
            .subscribe()
    }

    fn emit(&self, event: CoreEvent) {
        if let Some(events) = self.inner.events.get() {
            let _ = events.send(event);
        }
    }

    fn ensure_open(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) || self.inner.store.is_closed() {
            Err(CoreError::Closed)
        } else {
            Ok(())
        }
    }

    /// Replicates this core over a Protomux connection (one call per connection).
    pub fn replicate(&self, mux: &protomux::Mux) {
        if !self.is_closed() {
            self.replicator().attach(mux, None);
        }
    }

    /// Replicates over `mux` in answer to the remote open behind `pairing`
    /// (a Protomux pair request for this core's discovery key).
    pub fn replicate_paired(&self, mux: &protomux::Mux, pairing: protomux::PairRequest) {
        if !self.is_closed() {
            self.replicator().attach(mux, Some(pairing));
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || self.inner.store.is_closed()
    }

    /// Stops replicating: closes every channel of this core.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.emit(CoreEvent::Close);
        if let Some(r) = self.inner.replicator.get() {
            r.destroy();
        }
    }

    /// Waits for an existing replication actor to release its channels after `close`.
    pub async fn replication_closed(&self) {
        if let Some(replicator) = self.inner.replicator.get() {
            replicator.closed().await;
        }
    }

    pub(crate) fn replicator(&self) -> &Replicator {
        self.inner.replicator.get_or_init(|| Replicator::new(self))
    }

    /// `core.findingPeers()`: hold the guard while this core's update is still looking for
    /// peers, so it does not conclude that no update is available. Releasing it concludes.
    pub fn finding_peers(&self) -> crate::replicator::FindingPeers {
        self.replicator().finding_peers()
    }

    /// Whether block `index` is stored locally.
    pub fn has(&self, index: u64) -> bool {
        self.state().bitfield.get(index)
    }

    /// Whether every block of `[start, end)` is stored locally.
    pub fn has_range(&self, start: u64, end: u64) -> bool {
        start >= end || !self.state().bitfield.has_unset(start, end - start)
    }

    /// How many blocks of `[start, end)` are stored locally (`core.count()`), under one lock.
    pub fn count_local(&self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        self.state().bitfield.count(start, end - start, true)
    }

    fn publish(&self, st: &State) {
        self.inner.head.send_replace(st.head());
    }

    fn decrypt(&self, index: u64, block: Bytes) -> Bytes {
        let st = self.state();
        let Some(e) = st.encryption.as_ref() else {
            return block;
        };
        let mut buf = block.to_vec();
        e.decrypt(index, &mut buf);
        Bytes::from(buf).slice(PADDING..)
    }

    /// The raw stored block (still encrypted, if the core is).
    pub fn get_raw_local(&self, index: u64) -> Result<Option<Bytes>> {
        self.ensure_open()?;
        if !self.has(index) {
            return Ok(None);
        }
        Ok(self.inner.storage.get_block(index)?)
    }

    /// A block if stored locally, decrypted.
    pub fn get_local(&self, index: u64) -> Result<Option<Bytes>> {
        Ok(self.get_raw_local(index)?.map(|b| self.decrypt(index, b)))
    }

    /// A block, downloading it from peers if `wait` (the default).
    pub async fn get(&self, index: u64, opts: GetOptions) -> Result<Option<Bytes>> {
        if let Some(error) = opts.bag.as_ref().and_then(RequestBag::error) {
            return Err(error);
        }
        let local = if opts.raw {
            self.get_raw_local(index)?
        } else {
            self.get_local(index)?
        };
        if let Some(b) = local {
            return Ok(Some(b));
        }
        if !opts.wait {
            return Ok(None);
        }
        let req = self.replicator().request_block(index, opts.force);
        let request = async {
            match opts.timeout {
                Some(t) => tokio::time::timeout(t, req)
                    .await
                    .map_err(|_| CoreError::Timeout)?,
                None => req.await,
            }
        };
        let raw = if let Some(bag) = &opts.bag {
            tokio::select! {
                biased;
                error = bag.cancelled() => return Err(error),
                result = request => result?,
            }
        } else {
            request.await?
        };
        Ok(Some(if opts.raw {
            raw
        } else {
            self.decrypt(index, raw)
        }))
    }

    /// Asks peers for a longer signed length. True if the core grew.
    pub async fn update(&self, timeout: Option<Duration>) -> Result<bool> {
        let req = self.replicator().request_upgrade();
        match timeout {
            Some(t) => tokio::time::timeout(t, req)
                .await
                .map_err(|_| CoreError::Timeout)?,
            None => req.await,
        }
    }

    /// Downloads `[start, end)` (`end = None`: to the end, following appends).
    /// The range is registered at call time and cancelled when the returned
    /// future drops, so holding it unpolled keeps a prefetch window open.
    pub fn download(
        &self,
        start: u64,
        end: Option<u64>,
        linear: bool,
    ) -> impl Future<Output = Result<bool>> + Send + use<> {
        self.replicator().request_range(start, end, linear)
    }

    /// Downloads a range until completion or cancellation of its request bag.
    pub fn download_with_bag(
        &self,
        start: u64,
        end: Option<u64>,
        linear: bool,
        bag: RequestBag,
    ) -> impl Future<Output = Result<bool>> + Send + use<> {
        let request = self.replicator().request_range(start, end, linear);
        let mut task = AbortOnDrop(tokio::spawn(async move {
            tokio::select! {
                biased;
                error = bag.cancelled() => Err(error),
                result = request => result,
            }
        }));
        async move { (&mut task.0).await.unwrap_or(Err(CoreError::Closed)) }
    }

    /// Finds the block holding byte `bytes` (of plaintext).
    ///
    /// `wait` matches the JS session's: a seek past the local tree is answered by a peer (the
    /// replicator's seek request), so an empty core asked for a middle offset still resolves
    /// instead of reporting nothing.
    pub async fn seek(&self, bytes: u64, wait: bool) -> Result<Option<(u64, u64)>> {
        let padding = self.padding() as u64;
        loop {
            let (found, window) = {
                let st = self.state();
                (
                    merkle::seek(&st.tree, &self.inner.storage, bytes, padding)?,
                    merkle::seek_window(&st.tree, bytes, padding),
                )
            };
            match found {
                Some(merkle::Seek::Found(i, off)) => return Ok(Some((i, off))),
                None if !wait => return Ok(None),
                // At or past the local byte length: the position comes from a peer's tree.
                None => {
                    let (start, end) = window;
                    if !self
                        .replicator()
                        .request_seek(bytes, padding, start, end)
                        .await?
                    {
                        return Ok(None);
                    }
                }
                Some(merkle::Seek::Need { .. }) if !wait => return Ok(None),
                Some(merkle::Seek::Need { start, end }) => {
                    self.replicator()
                        .request_seek(bytes, padding, start, end)
                        .await?;
                }
            }
        }
    }

    /// `(byte offset, byte length)` of block `index`, without padding.
    pub fn byte_range(&self, index: u64) -> Result<(u64, u64)> {
        let padding = self.padding() as u64;
        let st = self.state();
        let (off, len) = merkle::byte_range(&st.tree, &self.inner.storage, 2 * index)?;
        Ok((off - padding * index, len - padding))
    }

    /// Appends blocks; returns the new head. The core must be writable.
    pub async fn append<B: AsRef<[u8]>>(&self, blocks: &[B]) -> Result<Head> {
        self.append_with(blocks, AppendOptions::default()).await
    }

    pub async fn append_with<B: AsRef<[u8]>>(
        &self,
        blocks: &[B],
        opts: AppendOptions,
    ) -> Result<Head> {
        let _w = self.inner.write.lock().await;
        self.ensure_open()?;
        let (batch, sb, start, end, contig, stamp) = {
            let st = self.state();
            let kp = st.header.key_pair();
            let verifier = st.verifier.as_ref().ok_or(CoreError::NotWritable)?;
            if st.header.frozen {
                return Err(CoreError::NotWritable);
            }
            if kp.is_none() && !(opts.writable && verifier.quorum == 0) {
                return Err(CoreError::NotWritable);
            }
            let start = st.tree.length;
            if opts
                .max_length
                .is_some_and(|max| start.saturating_add(blocks.len() as u64) > max)
            {
                return Ok(st.head());
            }
            let mut batch = Batch::new(&st.tree);
            let mut sb = self.inner.storage.write();
            for (i, b) in blocks.iter().enumerate() {
                let index = start + i as u64;
                let data = match &st.encryption {
                    Some(e) => {
                        let mut buf = vec![0u8; PADDING + b.as_ref().len()];
                        buf[PADDING..].copy_from_slice(b.as_ref());
                        e.encrypt(index, &mut buf, st.tree.fork);
                        buf
                    }
                    None => b.as_ref().to_vec(),
                };
                batch.append(&data);
                sb.put_block(index, Bytes::from(data));
            }
            batch.signature = if let Some(kp) = kp {
                Some(verifier.sign(&batch, &kp).ok_or(CoreError::NotWritable)?)
            } else {
                if verifier
                    .prologue
                    .as_ref()
                    .is_some_and(|p| batch.length < p.length)
                {
                    return Err(CoreError::BadArgument(
                        "Append is not consistent with prologue".into(),
                    ));
                }
                None
            };
            let end = batch.length;
            write_tree_ops(&mut batch, &mut sb);
            bitfield_pages(&st.bitfield, start, end, true, &mut sb);
            let contig = st.contiguous_after(start, end - start, false);
            let mut header = st.header.clone();
            header.fork = batch.fork;
            header.length = batch.length;
            header.signature = batch.signature.clone();
            header.contiguous_length = contig;
            header.write_new_head(&mut sb, &batch.roots);
            (batch, sb, start, end, contig, header.timestamp)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(sb)).await?;
        let head = {
            let mut st = self.state();
            st.tree = batch.state();
            st.header.length = batch.length;
            st.header.fork = batch.fork;
            st.header.timestamp = stamp;
            st.header.signature = batch.signature.clone();
            st.header.contiguous_length = contig;
            st.set_bits(start, end, true);
            self.publish(&st);
            st.head()
        };
        self.flush_hooks();
        self.emit(CoreEvent::Append {
            start,
            length: end - start,
        });
        if let Some(r) = self.inner.replicator.get() {
            r.on_append(start, end - start);
        }
        Ok(head)
    }

    /// Truncates to `length`, moving to `fork` (default: current fork + 1).
    pub async fn truncate(&self, length: u64, fork: Option<u64>) -> Result<()> {
        let _w = self.inner.write.lock().await;
        let (batch, sb, old, stamp) = {
            let st = self.state();
            let kp = st.header.key_pair().ok_or(CoreError::NotWritable)?;
            let verifier = st.verifier.as_ref().ok_or(CoreError::NotWritable)?;
            if let Some(p) = &st.tree.prologue
                && length < p.length
            {
                return Err(CoreError::BadArgument("Truncation breaks prologue".into()));
            }
            if length > st.tree.length {
                return Err(CoreError::BadArgument(format!(
                    "Not a truncation, {length} must be less or equal to {}",
                    st.tree.length
                )));
            }
            let mut batch = Batch::new(&st.tree);
            merkle::truncate(
                &self.inner.storage,
                length,
                &mut batch,
                fork.unwrap_or(st.tree.fork + 1),
            )?;
            batch.signature = Some(verifier.sign(&batch, &kp).ok_or(CoreError::NotWritable)?);
            let (sb, stamp) = self.truncate_batch(&st, &mut batch);
            (batch, sb, st.tree.length, stamp)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(sb)).await?;
        self.after_truncate(&batch, old, stamp);
        Ok(())
    }

    /// Storage writes for a truncation or reorg batch (`_truncate`).
    fn truncate_batch(&self, st: &State, batch: &mut Batch) -> (storage::Batch, u64) {
        let mut sb = self.inner.storage.write();
        sb.delete_block_range(batch.ancestors, batch.tree_length);
        write_tree_ops(batch, &mut sb);
        bitfield_pages(
            &st.bitfield,
            batch.ancestors,
            batch.tree_length,
            false,
            &mut sb,
        );
        let mut header = st.header.clone();
        header.fork = batch.fork;
        header.length = batch.length;
        header.signature = batch.signature.clone();
        if batch.ancestors < header.contiguous_length {
            header.contiguous_length = batch.ancestors;
            header.remote_contiguous_length = batch.length.min(header.remote_contiguous_length);
        }
        header.write_new_head(&mut sb, &batch.roots);
        (sb, header.timestamp)
    }

    fn after_truncate(&self, batch: &Batch, old_length: u64, stamp: u64) {
        let start = batch.ancestors;
        {
            let mut st = self.state();
            st.tree = batch.state();
            st.header.fork = batch.fork;
            st.header.length = batch.length;
            st.header.timestamp = stamp;
            st.header.signature = batch.signature.clone();
            if start < st.header.contiguous_length {
                st.header.contiguous_length = start;
                st.header.remote_contiguous_length =
                    batch.length.min(st.header.remote_contiguous_length);
            }
            st.set_bits(start, old_length.max(start), false);
            self.publish(&st);
        }
        self.emit(CoreEvent::Truncate {
            fork: batch.fork,
            length: batch.length,
        });
        if let Some(r) = self.inner.replicator.get() {
            r.on_truncate(start, old_length.saturating_sub(start));
        }
        self.flush_hooks();
    }

    /// Deletes local copies of blocks `[start, end)` (they stay in the log).
    pub async fn clear(&self, start: u64, end: u64) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let _w = self.inner.write.lock().await;
        let (sb, contig, stamp) = {
            let st = self.state();
            let mut sb = self.inner.storage.write();
            let mut ite = Iter::new(start * 2);
            while !st.tree.roots.iter().any(|r| r.index == ite.index)
                && ite.index < 2 * st.tree.length
            {
                let a = ite.index;
                let b = ite.sibling();
                ite.parent();
                let (l, r) = flat_tree::spans(b);
                let (s, e) = (l / 2, r / 2 + 1);
                let has = if s >= start && e <= end {
                    false
                } else {
                    st.bitfield.has_set(s, e - s)
                };
                if has {
                    break;
                }
                sb.delete_tree_node(a);
                // the whole sibling subtree is unused (hypercore 11.40)
                sb.delete_tree_range(l, r + 1);
            }
            bitfield_pages(&st.bitfield, start, end, false, &mut sb);
            let contig = st.header.contiguous_length.min(start);
            let mut header = st.header.clone();
            header.contiguous_length = contig;
            header.write_head(&mut sb, &st.tree.roots);
            sb.delete_block_range(start, end);
            (sb, contig, header.timestamp)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(sb)).await?;
        {
            let mut st = self.state();
            st.header.contiguous_length = contig;
            st.header.timestamp = stamp;
            st.set_bits(start, end, false);
        }
        if let Some(r) = self.inner.replicator.get() {
            r.on_clear(start, end - start);
        }
        Ok(())
    }

    /// Deletes the core and all its data from storage. Consumes the handle;
    /// other handles to the same core must not be used afterwards.
    pub async fn purge(self) -> Result<()> {
        let _w = self.inner.write.lock().await;
        if let Some(r) = self.inner.replicator.get() {
            r.destroy();
        }
        let store = self.inner.store.clone();
        let dk = self.inner.discovery_key;
        blocking(move || store.delete_core(&dk)).await?;
        Ok(())
    }

    // Sessions
    pub fn set_active(&self, active: bool) {
        self.inner.manually_active.store(active, Ordering::Release);
        self.replicator().sync_active();
    }

    pub(crate) fn effective_active(&self) -> bool {
        self.inner.manually_active.load(Ordering::Acquire) || self.active_session_count() > 0
    }

    /// Opens a session; `active: false` sessions don't keep the core downloading.
    pub fn session(&self, active: bool) -> Session {
        let _lifecycle = self
            .inner
            .session_lifecycle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.inner.sessions.fetch_add(1, Ordering::AcqRel);
        if active {
            self.inner.active_sessions.fetch_add(1, Ordering::AcqRel);
            self.replicator().sync_active();
        }
        Session {
            core: self.clone(),
            state: Arc::new(SessionState {
                core: self.clone(),
                active: Mutex::new(Some(active)),
                lease: Mutex::new(None),
                closed: watch::channel(false).0,
            }),
        }
    }

    pub fn session_count(&self) -> usize {
        self.inner.sessions.load(Ordering::Acquire)
    }

    pub fn active_session_count(&self) -> usize {
        self.inner.active_sessions.load(Ordering::Acquire)
    }

    /// Peers currently replicating this core.
    pub fn peer_count(&self) -> usize {
        self.inner.peers.load(Ordering::Acquire)
    }

    /// No sessions and no peers (JS `checkIfIdle`).
    pub fn is_idle(&self) -> bool {
        self.session_count() == 0 && self.peer_count() == 0
    }

    /// Block gets, seeks and download ranges still waiting on peers.
    pub async fn pending_requests(&self) -> usize {
        self.replicator().pending_requests().await
    }

    /// Wire requests outstanding across this core's peers (JS `sum(peer.inflight)`).
    pub async fn inflight_requests(&self) -> usize {
        match self.inner.replicator.get() {
            Some(replicator) => replicator.inflight_requests().await,
            None => 0,
        }
    }

    /// Called (once set) whenever the core may have become idle. Corestore
    /// uses it to garbage collect cores.
    pub fn set_idle_hook(&self, hook: impl Fn(&Core) + Send + Sync + 'static) {
        let _ = self.inner.idle_hook.set(Box::new(hook));
    }

    /// `core.ongroupupdate`: called with the group's topic and this core's head
    /// after every commit that moves it, once the write is flushed.
    pub fn set_group_update_hook(
        &self,
        hook: impl Fn([u8; 32], GroupUpdate) + Send + Sync + 'static,
    ) {
        let _ = self.inner.group_hook.set(Box::new(hook));
    }

    /// `_flushHooks`: tell the group this core's head moved.
    fn flush_hooks(&self) {
        let Some(hook) = self.inner.group_hook.get() else {
            return;
        };
        let (topic, update) = {
            let st = self.state();
            let Some(topic) = st.header.group.and_then(|group| group.key) else {
                return;
            };
            (
                topic,
                GroupUpdate {
                    key: st.header.key,
                    length: st.tree.length,
                    fork: st.tree.fork,
                },
            )
        };
        hook(topic, update);
    }

    /// `core.setGroup(topic)`: joins the topic's group, refusing a second one.
    pub async fn set_group(&self, topic: [u8; 32]) -> Result<()> {
        let _w = self.inner.write.lock().await;
        self.ensure_open()?;
        if let Some(group) = self.state().header.group {
            return if group.key == Some(topic) {
                Ok(())
            } else {
                Err(CoreError::BadArgument(
                    "core is already registered to another group".into(),
                ))
            };
        }
        let group = storage::CoreGroup {
            key: Some(topic),
            pointer: self.inner.store.create_group(&topic)?,
        };
        let tx = {
            let mut st = self.state();
            st.header.group = Some(group);
            let mut tx = self.inner.storage.write();
            tx.set_group(Some(group));
            tx
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(tx)).await?;
        Ok(())
    }

    pub(crate) fn set_peer_count(&self, n: usize) {
        let old = self.inner.peers.swap(n, Ordering::AcqRel);
        let event = if n > old {
            CoreEvent::PeerAdd
        } else {
            CoreEvent::PeerRemove
        };
        for _ in 0..old.abs_diff(n) {
            self.emit(event.clone());
        }
    }

    pub(crate) fn check_if_idle(&self) {
        if self.is_idle()
            && let Some(hook) = self.inner.idle_hook.get()
        {
            hook(self);
        }
    }

    // Replication

    /// Generates the proof (with block value and manifest) answering `req`.
    pub(crate) fn proof_for(&self, req: &ProofRequest, with_manifest: bool) -> Result<Data> {
        let (tree, manifest) = {
            let st = self.state();
            (
                st.tree.clone(),
                (with_manifest && !st.compat())
                    .then(|| st.header.manifest.clone())
                    .flatten(),
            )
        };
        let mut data = merkle::proof(&tree, &self.inner.storage, req)?;
        if let Some(b) = data.block.as_mut() {
            b.value = self
                .inner
                .storage
                .get_block(b.index)?
                .ok_or(CoreError::NotFound)?;
        }
        data.manifest = manifest;
        Ok(data)
    }

    /// `core.verify`: checks a remote proof and stores what it carries.
    /// `Ok(None)` if it no longer applies; `Ok(Some(upgraded))` once stored. `from` is the
    /// peer that sent the proof, reported with the stored block (JS `core.verify(proof, from)`).
    pub(crate) async fn verify(&self, proof: Data, from: Option<[u8; 32]>) -> Result<Option<bool>> {
        let _w = self.inner.write.lock().await;
        let prepared = {
            let st = self.state();
            if proof.fork != st.tree.fork {
                return Ok(None);
            }
            // hypercore 11.40: an upgrade made for another length is refitted to ours.
            let Some(proof) = merkle::refit(&st.tree, &self.inner.storage, &proof)? else {
                return Ok(None);
            };
            let mut batch = merkle::verify(&st.tree, &self.inner.storage, &proof)?;
            if batch.upgraded && batch.length <= st.tree.length {
                downgrade(&mut batch, &self.inner.storage)?;
            }
            if !batch.commitable(&st.tree) {
                return Ok(None);
            }
            let learned = if batch.upgraded {
                st.verify_batch_upgrade(&batch, proof.manifest.as_ref())?
            } else {
                None
            };
            let learned = learned.or_else(|| {
                proof.manifest.clone().filter(|m| {
                    st.header.manifest.is_none() && verifier::is_valid_manifest(&st.header.key, m)
                })
            });

            let mut sb = self.inner.storage.write();
            let block = proof.block.as_ref().map(|b| (b.index, b.value.clone()));
            let mut contig = st.header.contiguous_length;
            if let Some((index, value)) = &block {
                sb.put_block(*index, value.clone());
                bitfield_pages(&st.bitfield, *index, index + 1, true, &mut sb);
                contig = st.contiguous_after(*index, 1, false);
            }
            write_tree_ops(&mut batch, &mut sb);
            let mut header = st.header.clone();
            if let Some(m) = &learned {
                header.manifest = Some(m.clone());
                header.write_auth(&mut sb);
            }
            if batch.upgraded {
                header.fork = batch.fork;
                header.length = batch.length;
                header.signature = batch.signature.clone();
            }
            header.contiguous_length = contig;
            let roots = if batch.upgraded {
                batch.roots.clone()
            } else {
                st.tree.roots.clone()
            };
            if batch.upgraded {
                header.write_new_head(&mut sb, &roots);
            } else {
                header.write_head(&mut sb, &roots);
            }
            (
                batch,
                sb,
                block.map(|b| b.0),
                contig,
                learned,
                header.timestamp,
            )
        };
        let (batch, sb, block, contig, learned, stamp) = prepared;
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(sb)).await?;
        let upgraded = batch.upgraded;
        {
            let mut st = self.state();
            if let Some(m) = learned {
                st.set_manifest(m);
            }
            if upgraded {
                st.tree = batch.state();
                st.header.fork = batch.fork;
                st.header.length = batch.length;
                st.header.signature = batch.signature.clone();
            }
            st.header.timestamp = stamp;
            st.header.contiguous_length = contig;
            if let Some(i) = block {
                st.set_bits(i, i + 1, true);
            }
            self.publish(&st);
        }
        if upgraded {
            self.flush_hooks();
        }
        if let Some(block) = proof.block.as_ref() {
            self.emit(CoreEvent::Download {
                index: block.index,
                byte_length: block.value.len() as u64,
                from,
            });
        }
        Ok(Some(upgraded))
    }

    /// Verifies plain block proofs (no upgrade) and stores them in one commit,
    /// as JS batches concurrent verifies in `_verifyShared`.
    pub(crate) async fn verify_blocks(
        &self,
        proofs: &[Data],
        from: Option<[u8; 32]>,
    ) -> Vec<Result<Option<bool>>> {
        let _w = self.inner.write.lock().await;
        let mut results = Vec::with_capacity(proofs.len());
        let mut indices = vec![];
        let mut sb = self.inner.storage.write();
        let contig = {
            let st = self.state();
            let mut known = std::collections::HashMap::new();
            for proof in proofs {
                let r = (|| {
                    if proof.fork != st.tree.fork {
                        return Ok(None);
                    }
                    let mut batch =
                        merkle::verify_cached(&st.tree, &self.inner.storage, proof, &known)?;
                    if batch.upgraded || !batch.commitable(&st.tree) {
                        return Ok(None);
                    }
                    if proofs.len() > 1 {
                        batch
                            .nodes
                            .retain(|node| known.insert(node.index, *node) != Some(*node));
                    }
                    write_tree_ops(&mut batch, &mut sb);
                    if let Some(b) = &proof.block {
                        sb.put_block(b.index, b.value.clone());
                        indices.push(b.index);
                    }
                    Ok(Some(false))
                })();
                results.push(r);
            }
            let mut pages: std::collections::BTreeMap<u64, Vec<u32>> = Default::default();
            for &i in &indices {
                let page = i / crate::bitfield::BITS_PER_PAGE;
                let words = pages.entry(page).or_insert_with(|| {
                    st.bitfield
                        .page_words(i)
                        .map_or_else(|| vec![0; 1024], <[u32]>::to_vec)
                });
                let bit = i % crate::bitfield::BITS_PER_PAGE;
                words[(bit / 32) as usize] |= 1 << (bit % 32);
            }
            for (page, words) in pages {
                sb.put_bitfield_page(
                    page,
                    Bytes::from(
                        words
                            .iter()
                            .flat_map(|w| w.to_le_bytes())
                            .collect::<Vec<u8>>(),
                    ),
                );
            }
            let mut c = st.header.contiguous_length;
            while st.bitfield.get(c) || indices.contains(&c) {
                c += 1;
            }
            let mut header = st.header.clone();
            header.contiguous_length = c;
            header.write_head(&mut sb, &st.tree.roots);
            c
        };
        if indices.is_empty() {
            return results;
        }
        let storage = self.inner.storage.clone();
        if let Err(e) = blocking(move || storage.flush(sb)).await {
            let msg = e.to_string();
            return results
                .into_iter()
                .map(|r| match r {
                    Ok(Some(_)) => Err(CoreError::Storage(StorageError::Rocks(msg.clone()))),
                    other => other,
                })
                .collect();
        }
        let mut st = self.state();
        st.header.contiguous_length = contig;
        for i in indices {
            st.set_bits(i, i + 1, true);
        }
        for (proof, result) in proofs.iter().zip(&results) {
            if matches!(result, Ok(Some(_)))
                && let Some(block) = &proof.block
            {
                self.emit(CoreEvent::Download {
                    index: block.index,
                    byte_length: block.value.len() as u64,
                    from,
                });
            }
        }
        results
    }

    /// `core.verifyReorg`: validates a fork proof and returns its batch.
    pub(crate) fn verify_reorg(&self, proof: &Data) -> Result<Batch> {
        let st = self.state();
        let mut batch = Batch::new_reorg(&st.tree);
        merkle::reorg(&self.inner.storage, proof, &mut batch)?;
        st.verify_batch_upgrade(&batch, proof.manifest.as_ref())?;
        Ok(batch)
    }

    pub(crate) fn reorg_update(&self, batch: &mut Batch, proof: &Data) -> Result<bool> {
        Ok(batch.reorg_update(&self.inner.storage, proof)?)
    }

    /// Applies a finished reorg batch: truncates to the fork point and adopts
    /// the remote tree.
    pub(crate) async fn apply_reorg(&self, mut batch: Batch) -> Result<bool> {
        let _w = self.inner.write.lock().await;
        let (sb, old, stamp) = {
            let st = self.state();
            if !batch.commitable(&st.tree) {
                return Ok(false);
            }
            let (sb, stamp) = self.truncate_batch(&st, &mut batch);
            (sb, st.tree.length, stamp)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(sb)).await?;
        self.after_truncate(&batch, old, stamp);
        Ok(true)
    }

    /// `core.checkConflict`: true if `proof` proves two signed trees exist for
    /// the same length and fork (the core is frozen), or is itself invalid.
    pub(crate) async fn check_conflict(&self, proof: &Data) -> Result<bool> {
        let Some(upgrade) = proof.upgrade.as_ref() else {
            return Ok(false);
        };
        let local = {
            let st = self.state();
            if st.tree.length < upgrade.length
                || proof.fork != st.tree.fork
                || st.header.manifest.is_none()
            {
                return Ok(false);
            }
            let batch = merkle::verify_fully_remote(&st.tree, proof)?;
            if st
                .verify_batch_upgrade(&batch, proof.manifest.as_ref())
                .is_err()
            {
                return Ok(true);
            }
            let roots = merkle::roots_at(&self.inner.storage, upgrade.length).unwrap_or_default();
            crypto::tree_hash(&roots)
        };
        if crypto::tree_hash(&upgrade.nodes) == local {
            return Ok(false);
        }
        let _w = self.inner.write.lock().await;
        let sb = {
            let mut st = self.state();
            st.header.frozen = true;
            let mut sb = self.inner.storage.write();
            st.header.write_head(&mut sb, &st.tree.roots);
            sb
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.flush(sb)).await?;
        Ok(true)
    }

    pub(crate) fn set_remote_contiguous_length(&self, length: u64) {
        let mut st = self.state();
        if length > st.header.remote_contiguous_length {
            st.header.remote_contiguous_length = length;
        }
    }
}

/// `batch.downgrade()`: an "upgrade" to a length we already have is only a
/// block proof if its roots match ours.
fn downgrade(batch: &mut Batch, store: &CoreStorage) -> Result<()> {
    for root in &batch.roots {
        match store.node(root.index)? {
            Some(n) if n.hash == root.hash => {}
            _ => return Ok(()),
        }
    }
    batch.upgraded = false;
    Ok(())
}

fn write_tree_ops(batch: &mut Batch, sb: &mut storage::Batch) {
    let ops = batch.commit_ops();
    if let Some((s, e)) = ops.delete_range {
        sb.delete_tree_range(s, e);
    }
    for i in ops.delete {
        sb.delete_tree_node(i);
    }
    for n in ops.put {
        sb.put_tree_node(n);
    }
}

#[derive(Debug, Clone)]
pub struct GetOptions {
    pub wait: bool,
    pub timeout: Option<Duration>,
    /// Request even if the remote has not signalled it can upgrade us.
    pub force: bool,
    pub raw: bool,
    pub bag: Option<RequestBag>,
}

impl Default for GetOptions {
    fn default() -> Self {
        Self {
            wait: true,
            timeout: None,
            force: false,
            raw: false,
            bag: None,
        }
    }
}

/// An exclusive permit tied to one physical core.
pub struct ExclusiveLease {
    core: Core,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for ExclusiveLease {
    fn drop(&mut self) {
        let inner = &self.core.inner;
        let _lifecycle = inner
            .session_lifecycle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if inner.leases.fetch_sub(1, Ordering::AcqRel) == 1
            && inner.sessions.load(Ordering::Acquire) == 0
        {
            self.core.close();
        }
    }
}

struct SessionState {
    core: Core,
    active: Mutex<Option<bool>>,
    lease: Mutex<Option<ExclusiveLease>>,
    closed: watch::Sender<bool>,
}

/// A weak session registration, used by store scopes.
pub struct WeakSession(Weak<SessionState>);

impl WeakSession {
    pub fn is_alive(&self) -> bool {
        self.0.strong_count() != 0
    }

    /// The core's discovery key while the session is still open.
    pub fn discovery_key(&self) -> Option<[u8; 32]> {
        self.0.upgrade().map(|state| *state.core.discovery_key())
    }

    /// A `findingPeers` guard on the session's core (see [`Core::finding_peers`]).
    pub fn finding_peers(&self) -> Option<crate::replicator::FindingPeers> {
        self.0.upgrade().map(|state| state.core.finding_peers())
    }

    pub fn close(&self) {
        if let Some(state) = self.0.upgrade() {
            state.close();
        }
    }
}

impl SessionState {
    fn close(&self) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let Some(was_active) = active.take() else {
            return;
        };
        self.closed.send_replace(true);
        self.lease.lock().unwrap_or_else(|e| e.into_inner()).take();
        let inner = &self.core.inner;
        let _lifecycle = inner
            .session_lifecycle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        inner.sessions.fetch_sub(1, Ordering::AcqRel);
        if was_active {
            inner.active_sessions.fetch_sub(1, Ordering::AcqRel);
            if let Some(r) = inner.replicator.get() {
                r.sync_active();
            }
        }
        if inner.sessions.load(Ordering::Acquire) == 0 && inner.leases.load(Ordering::Acquire) == 0
        {
            self.core.close();
        }
        self.core.check_if_idle();
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.close();
    }
}

/// A session on a physical core.
pub struct Session {
    core: Core,
    state: Arc<SessionState>,
}

impl Session {
    pub fn core(&self) -> &Core {
        &self.core
    }

    pub fn key(&self) -> &[u8; 32] {
        self.core.key()
    }
    pub fn discovery_key(&self) -> &[u8; 32] {
        self.core.discovery_key()
    }
    pub fn head(&self) -> Head {
        self.core.head()
    }
    pub fn length(&self) -> u64 {
        self.core.length()
    }
    pub fn byte_length(&self) -> u64 {
        self.core.byte_length()
    }
    pub fn fork(&self) -> u64 {
        self.core.fork()
    }
    pub fn contiguous_length(&self) -> u64 {
        self.core.contiguous_length()
    }
    pub fn remote_contiguous_length(&self) -> u64 {
        self.core.remote_contiguous_length()
    }
    pub fn writable(&self) -> bool {
        self.core.writable()
    }
    pub fn manifest(&self) -> Option<Manifest> {
        self.core.manifest()
    }
    pub fn padding(&self) -> usize {
        self.core.padding()
    }
    pub fn inflight_range(&self) -> Option<(u32, u32)> {
        self.core.inflight_range()
    }
    pub fn subscribe(&self) -> watch::Receiver<Head> {
        self.core.subscribe()
    }
    pub fn events(&self) -> broadcast::Receiver<CoreEvent> {
        self.core.events()
    }
    pub fn has(&self, index: u64) -> bool {
        self.core.has(index)
    }
    pub fn has_range(&self, start: u64, end: u64) -> bool {
        self.core.has_range(start, end)
    }
    pub fn count_local(&self, start: u64, end: u64) -> u64 {
        self.core.count_local(start, end)
    }
    pub fn byte_range(&self, index: u64) -> Result<(u64, u64)> {
        self.ensure_open()?;
        self.core.byte_range(index)
    }
    pub async fn tree_hash(&self, length: u64) -> Result<[u8; 32]> {
        self.ensure_open()?;
        self.core.tree_hash(length).await
    }
    pub fn download(
        &self,
        start: u64,
        end: Option<u64>,
        linear: bool,
    ) -> impl Future<Output = Result<bool>> + Send + use<> {
        let mut closed = self.state.closed.subscribe();
        let request = self
            .ensure_open()
            .map(|()| self.core.download(start, end, linear));
        async move {
            let request = request?;
            if *closed.borrow() {
                return Err(CoreError::Closed);
            }
            tokio::select! {
                result = request => result,
                _ = closed.changed() => Err(CoreError::Closed),
            }
        }
    }
    pub fn download_with_bag(
        &self,
        start: u64,
        end: Option<u64>,
        linear: bool,
        bag: RequestBag,
    ) -> impl Future<Output = Result<bool>> + Send + use<> {
        let mut closed = self.state.closed.subscribe();
        let request = self
            .ensure_open()
            .map(|()| self.core.download_with_bag(start, end, linear, bag));
        async move {
            let request = request?;
            if *closed.borrow() {
                return Err(CoreError::Closed);
            }
            tokio::select! {
                result = request => result,
                _ = closed.changed() => Err(CoreError::Closed),
            }
        }
    }

    pub fn downgrade(&self) -> WeakSession {
        WeakSession(Arc::downgrade(&self.state))
    }

    pub fn close(&self) {
        self.state.close();
    }

    pub fn is_closed(&self) -> bool {
        self.core.is_closed()
            || self
                .state
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
    }

    fn ensure_open(&self) -> Result<()> {
        if self.is_closed() {
            Err(CoreError::Closed)
        } else {
            self.core.ensure_open()
        }
    }

    pub async fn get(&self, index: u64, opts: GetOptions) -> Result<Option<Bytes>> {
        let mut closed = self.state.closed.subscribe();
        self.ensure_open()?;
        if *closed.borrow() {
            return Err(CoreError::Closed);
        }
        tokio::select! {
            result = self.core.get(index, opts) => result,
            _ = closed.changed() => Err(CoreError::Closed),
        }
    }

    pub async fn append<B: AsRef<[u8]>>(&self, blocks: &[B]) -> Result<Head> {
        self.ensure_open()?;
        self.core.append(blocks).await
    }

    pub async fn append_with<B: AsRef<[u8]>>(
        &self,
        blocks: &[B],
        opts: AppendOptions,
    ) -> Result<Head> {
        self.ensure_open()?;
        self.core.append_with(blocks, opts).await
    }

    pub async fn set_group(&self, topic: [u8; 32]) -> Result<()> {
        self.ensure_open()?;
        self.core.set_group(topic).await
    }

    pub fn get_local(&self, index: u64) -> Result<Option<Bytes>> {
        self.ensure_open()?;
        self.core.get_local(index)
    }

    pub fn get_raw_local(&self, index: u64) -> Result<Option<Bytes>> {
        self.ensure_open()?;
        self.core.get_raw_local(index)
    }

    pub async fn update(&self, timeout: Option<Duration>) -> Result<bool> {
        self.ensure_open()?;
        self.core.update(timeout).await
    }

    /// `session.findingPeers()`: the same guard [`Core::finding_peers`] returns.
    pub fn finding_peers(&self) -> crate::replicator::FindingPeers {
        self.core.finding_peers()
    }

    pub async fn seek(&self, bytes: u64, wait: bool) -> Result<Option<(u64, u64)>> {
        self.ensure_open()?;
        self.core.seek(bytes, wait).await
    }

    pub async fn truncate(&self, length: u64, fork: Option<u64>) -> Result<()> {
        self.ensure_open()?;
        self.core.truncate(length, fork).await
    }

    pub async fn clear(&self, start: u64, end: u64) -> Result<()> {
        self.ensure_open()?;
        self.core.clear(start, end).await
    }

    pub fn user_data(&self, key: &str) -> Result<Option<Bytes>> {
        self.ensure_open()?;
        self.core.user_data(key)
    }

    pub async fn set_user_data(&self, key: &str, value: Option<&[u8]>) -> Result<()> {
        self.ensure_open()?;
        self.core.set_user_data(key, value).await
    }

    pub fn is_active(&self) -> bool {
        self.state
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(false)
    }

    pub fn set_active(&mut self, active: bool) {
        let mut current = self.state.active.lock().unwrap_or_else(|e| e.into_inner());
        let Some(previous) = current.as_mut() else {
            return;
        };
        if *previous == active {
            return;
        }
        *previous = active;
        if active {
            self.core
                .inner
                .active_sessions
                .fetch_add(1, Ordering::AcqRel);
        } else {
            self.core
                .inner
                .active_sessions
                .fetch_sub(1, Ordering::AcqRel);
        }
        self.core.replicator().sync_active();
    }

    pub async fn acquire_exclusive(&self) -> Result<()> {
        let mut closed = self.state.closed.subscribe();
        if *closed.borrow() {
            return Err(CoreError::Closed);
        }
        let guard = tokio::select! {
            guard = self.core.inner.exclusive.clone().lock_owned() => guard,
            _ = closed.changed() => return Err(CoreError::Closed),
        };
        self.core.inner.leases.fetch_add(1, Ordering::AcqRel);
        self.attach_exclusive(ExclusiveLease {
            core: self.core.clone(),
            _guard: guard,
        })
    }

    pub fn take_exclusive(&self) -> Option<ExclusiveLease> {
        self.state
            .lease
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    pub fn attach_exclusive(&self, lease: ExclusiveLease) -> Result<()> {
        let active = self.state.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.is_none() {
            return Err(CoreError::Closed);
        }
        if !Arc::ptr_eq(&lease.core.inner, &self.core.inner) {
            return Err(CoreError::BadArgument(
                "exclusive lease belongs to another core".into(),
            ));
        }
        let mut slot = self.state.lease.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Err(CoreError::BadArgument(
                "session already owns an exclusive lease".into(),
            ));
        }
        *slot = Some(lease);
        Ok(())
    }
}

#[cfg(test)]
mod feature_tests {
    use super::*;

    #[tokio::test]
    async fn rebuildable_cache_loses_only_complete_unflushed_batches() {
        use crate::storage::StoreOptions;
        use compact_encoding::hypercore::{RequestBlock, RequestUpgrade};
        let values = (0..64)
            .map(|i| vec![i as u8; 512 * 1024])
            .collect::<Vec<_>>();
        if let Some(root) = std::env::var_os("WAL_FREE_CRASH_STORE") {
            let root = std::path::PathBuf::from(root);
            let source = Store::open(&root.join("source")).unwrap();
            let writer = Core::open(
                &source,
                CoreOptions {
                    key_pair: Some(KeyPair::from_seed(&[23; 32])),
                    ..Default::default()
                },
            )
            .unwrap();
            std::fs::write(root.join("key"), writer.key()).unwrap();
            writer
                .append(&values.iter().map(Vec::as_slice).collect::<Vec<_>>())
                .await
                .unwrap();
            source.flush().unwrap();
            let cache = Store::open_with_options(
                &root.join("cache"),
                StoreOptions {
                    wal: false,
                    ..Default::default()
                },
            )
            .unwrap();
            let reader = Core::open(
                &cache,
                CoreOptions {
                    key: Some(*writer.key()),
                    ..Default::default()
                },
            )
            .unwrap();
            let upgrade = writer
                .proof_for(
                    &ProofRequest {
                        upgrade: Some(RequestUpgrade {
                            start: 0,
                            length: 64,
                        }),
                        ..Default::default()
                    },
                    true,
                )
                .unwrap();
            reader.verify(upgrade, None).await.unwrap();
            let proof = |index| {
                writer
                    .proof_for(
                        &ProofRequest {
                            block: Some(RequestBlock { index, nodes: 6 }),
                            ..Default::default()
                        },
                        false,
                    )
                    .unwrap()
            };
            let results = reader
                .verify_blocks(&(0..56).map(proof).collect::<Vec<_>>(), None)
                .await;
            assert!(results.into_iter().all(|r| matches!(r, Ok(Some(false)))));
            cache.flush().unwrap();
            let results = reader
                .verify_blocks(&(56..64).map(proof).collect::<Vec<_>>(), None)
                .await;
            assert!(results.into_iter().all(|r| matches!(r, Ok(Some(false)))));
            // No destructors: RocksDB's normal close would flush a WAL-free memtable.
            std::process::exit(0);
        }
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "core::feature_tests::rebuildable_cache_loses_only_complete_unflushed_batches",
            ])
            .env("WAL_FREE_CRASH_STORE", dir.path())
            .status()
            .unwrap();
        assert!(status.success(), "cache writer failed");
        let key = std::fs::read(dir.path().join("key"))
            .unwrap()
            .try_into()
            .unwrap();
        let cache_dir = dir.path().join("cache");
        let cache = Store::open(&cache_dir).unwrap();
        let reader = Core::open(
            &cache,
            CoreOptions {
                key: Some(key),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            reader.has_range(0, 56),
            "the flushed checkpoint must survive"
        );
        assert!(!reader.has(63), "exercise an actually lost WAL-free tail");
        let verifier_store = Store::open(&dir.path().join("verifier")).unwrap();
        let verifier = Core::open(
            &verifier_store,
            CoreOptions {
                key: Some(key),
                ..Default::default()
            },
        )
        .unwrap();
        verifier
            .verify(
                reader
                    .proof_for(
                        &ProofRequest {
                            upgrade: Some(RequestUpgrade {
                                start: 0,
                                length: reader.length(),
                            }),
                            ..Default::default()
                        },
                        true,
                    )
                    .unwrap(),
                None,
            )
            .await
            .unwrap();
        for index in 0..reader.length() {
            if reader.has(index) {
                let proof = reader
                    .proof_for(
                        &ProofRequest {
                            block: Some(RequestBlock { index, nodes: 6 }),
                            ..Default::default()
                        },
                        false,
                    )
                    .unwrap();
                assert_eq!(
                    proof.block.as_ref().unwrap().value.as_ref(),
                    values[index as usize]
                );
                assert_eq!(verifier.verify(proof, None).await.unwrap(), Some(false));
            }
        }
    }

    #[tokio::test]
    async fn remote_contiguous_hint_is_capped_at_local_length() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let core = Core::open(
            &store,
            CoreOptions {
                key_pair: Some(KeyPair::from_seed(&[21; 32])),
                ..Default::default()
            },
        )
        .unwrap();
        core.append(&[b"a", b"b"]).await.unwrap();
        assert!(core.inner.events.get().is_none());
        let mut events = core.events();
        core.set_remote_contiguous_length(10);
        assert_eq!(core.remote_contiguous_length(), 2);
        core.truncate(1, None).await.unwrap();
        assert_eq!(core.remote_contiguous_length(), 1);
        assert_eq!(
            events.try_recv().unwrap(),
            CoreEvent::Truncate { fork: 1, length: 1 }
        );
        core.close();
        assert_eq!(events.try_recv().unwrap(), CoreEvent::Close);
    }

    #[tokio::test]
    async fn shared_proofs_commit_each_node_once_without_trusting_a_failed_proof() {
        use compact_encoding::hypercore::{RequestBlock, RequestUpgrade};
        let dir = tempfile::tempdir().unwrap();
        let source = Store::open(&dir.path().join("source")).unwrap();
        let writer = Core::open(
            &source,
            CoreOptions {
                key_pair: Some(KeyPair::from_seed(&[22; 32])),
                ..Default::default()
            },
        )
        .unwrap();
        writer.append(&[b"a", b"b", b"c", b"d"]).await.unwrap();
        let destination = Store::open(&dir.path().join("destination")).unwrap();
        let reader = Core::open(
            &destination,
            CoreOptions {
                key: Some(*writer.key()),
                ..Default::default()
            },
        )
        .unwrap();
        let upgrade = writer
            .proof_for(
                &ProofRequest {
                    upgrade: Some(RequestUpgrade {
                        start: 0,
                        length: 4,
                    }),
                    ..Default::default()
                },
                true,
            )
            .unwrap();
        assert_eq!(reader.verify(upgrade, None).await.unwrap(), Some(true));
        let proof = |index| {
            writer
                .proof_for(
                    &ProofRequest {
                        block: Some(RequestBlock { index, nodes: 2 }),
                        ..Default::default()
                    },
                    false,
                )
                .unwrap()
        };
        let mut bad = proof(1);
        bad.block.as_mut().unwrap().value = Bytes::from_static(b"bad");
        let results = reader
            .verify_blocks(&[proof(0), bad, proof(1), proof(2)], None)
            .await;
        assert!(matches!(results[0], Ok(Some(false))));
        assert!(matches!(
            results[1],
            Err(CoreError::Merkle(MerkleError::InvalidChecksum(_)))
        ));
        assert!(matches!(results[2], Ok(Some(false))));
        assert!(matches!(results[3], Ok(Some(false))));
        assert_eq!(reader.storage().tree_nodes().unwrap().len(), 7);
        destination.close();
        let destination = Store::open(&dir.path().join("destination")).unwrap();
        let reader = Core::open(
            &destination,
            CoreOptions {
                key: Some(*writer.key()),
                ..Default::default()
            },
        )
        .unwrap();
        for (index, value) in [b"a", b"b", b"c"].iter().enumerate() {
            assert_eq!(
                reader
                    .get_raw_local(index as u64)
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                *value
            );
        }
    }
}
