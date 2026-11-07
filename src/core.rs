//! One Hypercore: its persisted header, merkle tree, bitfield and blocks, and
//! the local operations on them. Replication drives `verify_*` and `reorg`.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;

use compact_encoding::hypercore::{Data, Manifest};
use compact_encoding::{Bytes, Codec, Reader, Writer};
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
        self.tree_node(index)
            .map_err(|e| MerkleError::Storage(e.to_string()))
    }

    fn has_node(&self, index: u64) -> merkle::Result<bool> {
        self.has_tree_node(index)
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
            no_create: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreEvent {
    Append { start: u64, length: u64 },
    Download { index: u64, byte_length: u64 },
    Truncate { fork: u64, length: u64 },
    PeerAdd,
    PeerRemove,
    Close,
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

/// Persisted per-core metadata. Private format: only this crate reads it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Header {
    pub key: [u8; 32],
    pub manifest: Option<Manifest>,
    pub secret_key: Option<[u8; 64]>,
    pub fork: u64,
    pub length: u64,
    pub signature: Option<Bytes>,
    pub contiguous_length: u64,
    pub remote_contiguous_length: u64,
    pub frozen: bool,
}

const HEADER_VERSION: u64 = 1;

impl Header {
    fn encode(&self) -> Bytes {
        let mut w = Writer::new();
        w.uint(HEADER_VERSION);
        let flags = self.manifest.is_some() as u64
            | (self.secret_key.is_some() as u64) << 1
            | (self.signature.is_some() as u64) << 2
            | (self.frozen as u64) << 3;
        w.uint(flags);
        w.raw(&self.key);
        if let Some(m) = &self.manifest {
            m.encode(&mut w);
        }
        if let Some(s) = &self.secret_key {
            w.raw(s);
        }
        w.uint(self.fork);
        w.uint(self.length);
        if let Some(s) = &self.signature {
            w.buffer(s);
        }
        w.uint(self.contiguous_length);
        w.uint(self.remote_contiguous_length);
        w.finish()
    }

    fn decode(b: Bytes) -> Result<Self> {
        let corrupt = |e: compact_encoding::Error| {
            CoreError::Storage(StorageError::Corrupt(format!("header: {e}")))
        };
        let mut r = Reader::new(b);
        if r.uint().map_err(corrupt)? != HEADER_VERSION {
            return Err(CoreError::Storage(StorageError::Corrupt(
                "unknown header version".into(),
            )));
        }
        let flags = r.uint().map_err(corrupt)?;
        let key = r.fixed().map_err(corrupt)?;
        let manifest = if flags & 1 != 0 {
            Some(Manifest::decode(&mut r).map_err(corrupt)?)
        } else {
            None
        };
        let secret_key = if flags & 2 != 0 {
            Some(r.fixed().map_err(corrupt)?)
        } else {
            None
        };
        let fork = r.uint().map_err(corrupt)?;
        let length = r.uint().map_err(corrupt)?;
        let signature = if flags & 4 != 0 {
            Some(r.buffer().map_err(corrupt)?)
        } else {
            None
        };
        Ok(Self {
            key,
            manifest,
            secret_key,
            fork,
            length,
            signature,
            contiguous_length: r.uint().map_err(corrupt)?,
            remote_contiguous_length: r.uint().map_err(corrupt)?,
            frozen: flags & 8 != 0,
        })
    }

    fn key_pair(&self) -> Option<KeyPair> {
        self.secret_key.map(|s| {
            let seed: [u8; 32] = s[..32].try_into().expect("seed");
            KeyPair::from_seed(&seed)
        })
    }
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
        self.bitfield.take_dirty();
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
        batch.put_bitfield_page(page, bytes.map(Bytes::from));
    }
}

type IdleHook = Box<dyn Fn(&Core) + Send + Sync>;

pub(crate) struct Inner {
    pub storage: CoreStorage,
    pub store: Store,
    pub key: [u8; 32],
    pub discovery_key: [u8; 32],
    state: Mutex<State>,
    write: tokio::sync::Mutex<()>,
    exclusive: Arc<tokio::sync::Mutex<()>>,
    head: watch::Sender<Head>,
    events: broadcast::Sender<CoreEvent>,
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
        let storage = store.core(&crypto::discovery_key(&key));
        let header = match storage.header()? {
            Some(h) => {
                let mut header = Header::decode(h)?;
                if header.key != key {
                    return Err(CoreError::BadArgument(
                        "stored core has a different key".into(),
                    ));
                }
                if header.secret_key.is_none() {
                    header.secret_key = opts.key_pair.as_ref().map(|kp| kp.secret_key);
                }
                header
            }
            None if opts.no_create => return Err(CoreError::NotFound),
            None => {
                let manifest = manifest.filter(|m| {
                    verifier::is_valid_manifest(&key, m)
                        || (m.signers.len() == 1 && m.signers[0].public_key == key)
                });
                let header = Header {
                    key,
                    secret_key: opts.key_pair.as_ref().map(|kp| kp.secret_key),
                    manifest,
                    ..Default::default()
                };
                let mut b = storage::Batch::default();
                b.set_header(header.encode());
                storage.write(b)?;
                header
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
        let storage = store.core(discovery_key);
        let header = Header::decode(storage.header()?.ok_or(CoreError::NotFound)?)?;
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
                events: broadcast::channel(256).0,
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
            }),
        };
        Ok(core)
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn stored_head(store: &Store, discovery_key: &[u8; 32]) -> Result<Option<Head>> {
        let storage = store.core(discovery_key);
        let Some(bytes) = storage.header()? else {
            return Ok(None);
        };
        let header = Header::decode(bytes)?;
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
        Ok(self.inner.storage.user_data(key)?)
    }

    pub async fn set_user_data(&self, key: &str, value: Option<&[u8]>) -> Result<()> {
        let _w = self.inner.write.lock().await;
        self.ensure_open()?;
        if self.inner.storage.user_data(key)?.as_deref() == value {
            return Ok(());
        }
        let mut batch = storage::Batch::default();
        batch.put_user_data(key, value.map(Bytes::copy_from_slice));
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(batch)).await?;
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
        self.inner.events.subscribe()
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
        self.replicator().attach(mux, None);
    }

    /// Replicates over `mux` in answer to the remote open behind `pairing`
    /// (a Protomux pair request for this core's discovery key).
    pub fn replicate_paired(&self, mux: &protomux::Mux, pairing: protomux::PairRequest) {
        self.replicator().attach(mux, Some(pairing));
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire) || self.inner.store.is_closed()
    }

    /// Stops replicating: closes every channel of this core.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.inner.events.send(CoreEvent::Close);
        if let Some(r) = self.inner.replicator.get() {
            r.destroy();
        }
    }

    pub(crate) fn replicator(&self) -> &Replicator {
        self.inner.replicator.get_or_init(|| Replicator::new(self))
    }

    /// Whether block `index` is stored locally.
    pub fn has(&self, index: u64) -> bool {
        self.state().bitfield.get(index)
    }

    /// Whether every block of `[start, end)` is stored locally.
    pub fn has_range(&self, start: u64, end: u64) -> bool {
        start >= end || !self.state().bitfield.has_unset(start, end - start)
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
        Ok(self.inner.storage.block(index)?)
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
    pub async fn seek(&self, bytes: u64, wait: bool) -> Result<Option<(u64, u64)>> {
        let padding = self.padding() as u64;
        loop {
            let found = {
                let st = self.state();
                merkle::seek(&st.tree, &self.inner.storage, bytes, padding)?
            };
            match found {
                Some(merkle::Seek::Found(i, off)) => return Ok(Some((i, off))),
                None => return Ok(None),
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
        let (batch, sb, start, end, contig) = {
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
            let mut sb = storage::Batch::default();
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
            sb.set_header(header.encode());
            (batch, sb, start, end, contig)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(sb)).await?;
        let head = {
            let mut st = self.state();
            st.tree = batch.state();
            st.header.length = batch.length;
            st.header.fork = batch.fork;
            st.header.signature = batch.signature.clone();
            st.header.contiguous_length = contig;
            st.set_bits(start, end, true);
            self.publish(&st);
            st.head()
        };
        let _ = self.inner.events.send(CoreEvent::Append {
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
        let (batch, sb, old) = {
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
            let sb = self.truncate_batch(&st, &mut batch);
            (batch, sb, st.tree.length)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(sb)).await?;
        self.after_truncate(&batch, old);
        Ok(())
    }

    /// Storage writes for a truncation or reorg batch (`_truncate`).
    fn truncate_batch(&self, st: &State, batch: &mut Batch) -> storage::Batch {
        let mut sb = storage::Batch::default();
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
        sb.set_header(header.encode());
        sb
    }

    fn after_truncate(&self, batch: &Batch, old_length: u64) {
        let start = batch.ancestors;
        {
            let mut st = self.state();
            st.tree = batch.state();
            st.header.fork = batch.fork;
            st.header.length = batch.length;
            st.header.signature = batch.signature.clone();
            if start < st.header.contiguous_length {
                st.header.contiguous_length = start;
                st.header.remote_contiguous_length =
                    batch.length.min(st.header.remote_contiguous_length);
            }
            st.set_bits(start, old_length.max(start), false);
            self.publish(&st);
        }
        let _ = self.inner.events.send(CoreEvent::Truncate {
            fork: batch.fork,
            length: batch.length,
        });
        if let Some(r) = self.inner.replicator.get() {
            r.on_truncate(start, old_length.saturating_sub(start));
        }
    }

    /// Deletes local copies of blocks `[start, end)` (they stay in the log).
    pub async fn clear(&self, start: u64, end: u64) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let _w = self.inner.write.lock().await;
        let (sb, contig) = {
            let st = self.state();
            let mut sb = storage::Batch::default();
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
            sb.set_header(header.encode());
            sb.delete_block_range(start, end);
            (sb, contig)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(sb)).await?;
        {
            let mut st = self.state();
            st.header.contiguous_length = contig;
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

    /// Called (once set) whenever the core may have become idle. Corestore
    /// uses it to garbage collect cores.
    pub fn set_idle_hook(&self, hook: impl Fn(&Core) + Send + Sync + 'static) {
        let _ = self.inner.idle_hook.set(Box::new(hook));
    }

    pub(crate) fn set_peer_count(&self, n: usize) {
        let old = self.inner.peers.swap(n, Ordering::AcqRel);
        let event = if n > old {
            CoreEvent::PeerAdd
        } else {
            CoreEvent::PeerRemove
        };
        for _ in 0..old.abs_diff(n) {
            let _ = self.inner.events.send(event.clone());
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
                .block(b.index)?
                .ok_or(CoreError::NotFound)?;
        }
        data.manifest = manifest;
        Ok(data)
    }

    /// `core.verify`: checks a remote proof and stores what it carries.
    /// `Ok(None)` if it no longer applies; `Ok(Some(upgraded))` once stored.
    pub(crate) async fn verify(&self, proof: Data) -> Result<Option<bool>> {
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

            let mut sb = storage::Batch::default();
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
            }
            if batch.upgraded {
                header.fork = batch.fork;
                header.length = batch.length;
                header.signature = batch.signature.clone();
            }
            header.contiguous_length = contig;
            sb.set_header(header.encode());
            (batch, sb, block.map(|b| b.0), contig, learned)
        };
        let (batch, sb, block, contig, learned) = prepared;
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(sb)).await?;
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
            st.header.contiguous_length = contig;
            if let Some(i) = block {
                st.set_bits(i, i + 1, true);
            }
            self.publish(&st);
        }
        if let Some(block) = proof.block.as_ref() {
            let _ = self.inner.events.send(CoreEvent::Download {
                index: block.index,
                byte_length: block.value.len() as u64,
            });
        }
        Ok(Some(upgraded))
    }

    /// Verifies plain block proofs (no upgrade) and stores them in one commit,
    /// as JS batches concurrent verifies in `_verifyShared`.
    pub(crate) async fn verify_blocks(&self, proofs: &[Data]) -> Vec<Result<Option<bool>>> {
        let _w = self.inner.write.lock().await;
        let mut results = Vec::with_capacity(proofs.len());
        let mut indices = vec![];
        let mut sb = storage::Batch::default();
        let contig = {
            let st = self.state();
            for proof in proofs {
                let r = (|| {
                    if proof.fork != st.tree.fork {
                        return Ok(None);
                    }
                    let mut batch = merkle::verify(&st.tree, &self.inner.storage, proof)?;
                    if batch.upgraded || !batch.commitable(&st.tree) {
                        return Ok(None);
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
                    Some(Bytes::from(
                        words
                            .iter()
                            .flat_map(|w| w.to_le_bytes())
                            .collect::<Vec<u8>>(),
                    )),
                );
            }
            let mut c = st.header.contiguous_length;
            while st.bitfield.get(c) || indices.contains(&c) {
                c += 1;
            }
            let mut header = st.header.clone();
            header.contiguous_length = c;
            sb.set_header(header.encode());
            c
        };
        if indices.is_empty() {
            return results;
        }
        let storage = self.inner.storage.clone();
        if let Err(e) = blocking(move || storage.write(sb)).await {
            let msg = e.to_string();
            return results
                .into_iter()
                .map(|r| match r {
                    Ok(Some(_)) => Err(CoreError::Storage(StorageError::Db(msg.clone()))),
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
                let _ = self.inner.events.send(CoreEvent::Download {
                    index: block.index,
                    byte_length: block.value.len() as u64,
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
        let (sb, old) = {
            let st = self.state();
            if !batch.commitable(&st.tree) {
                return Ok(false);
            }
            (self.truncate_batch(&st, &mut batch), st.tree.length)
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(sb)).await?;
        self.after_truncate(&batch, old);
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
            let mut sb = storage::Batch::default();
            sb.set_header(st.header.encode());
            sb
        };
        let storage = self.inner.storage.clone();
        blocking(move || storage.write(sb)).await?;
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
        core.set_remote_contiguous_length(10);
        assert_eq!(core.remote_contiguous_length(), 2);
        core.truncate(1, None).await.unwrap();
        assert_eq!(core.remote_contiguous_length(), 1);
    }
}
