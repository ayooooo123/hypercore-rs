//! Replication (`hypercore/lib/replicator.js`): one actor task per core owns
//! every peer's protocol state and every pending download, and handles
//! events one at a time, as JS does on its event loop.
//!
//! Not ported: push mode (`allowPush`), repair mode, extensions, block-list
//! ranges, the 40+ peer update throttle, and RTT-scaled inflight windows
//! (without the UDX RTT the JS non-UDX window is used).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use compact_encoding::hypercore::{
    Bitfield as WireBitfield, Cancel, Data, Extension, Handshake, NoData, Range, Request,
    RequestBlock, RequestSeek, RequestUpgrade, Sync, Want,
};
use compact_encoding::{Bytes, Codec, Reader, decode, encode};
use protomux::{ChannelOptions, ChannelSender, Event, Mux, PairRequest};
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, oneshot};

use crate::core::{Core, CoreError, Inner};
use crate::crypto;
use crate::flat_tree;
use crate::merkle::{self, Batch, ProofRequest};
use crate::remote_bitfield::RemoteBitfield;
use crate::wants::{LocalWants, RemoteWants, WANT_BATCH, WantUpdate};

pub const PROTOCOL: &str = "hypercore/alpha";

const DEFAULT_MAX_INFLIGHT: (usize, usize) = (16, 512);
const HOTSWAP_ROUNDTRIPS: f64 = 3.0;
const MAX_PEERS_UPGRADE: usize = 3;
const LAST_BLOCKS: u64 = 256;
const MAX_RANGES: usize = 64;
const NOT_AVAILABLE: u64 = 1;
const INVALID_REQUEST: u64 = 2;
const MAX_INVALID_REQUESTS: u64 = 64;
const MAX_BACKOFFS: u64 = MAX_INVALID_REQUESTS / 2;
const PAGE_BITS: u64 = 32768;

const PRIORITY_NORMAL: u64 = 0;
const PRIORITY_HIGH: u64 = 1;

// Wire message types, in channel registration order.
const MSG_SYNC: u64 = 0;
const MSG_REQUEST: u64 = 1;
const MSG_CANCEL: u64 = 2;
const MSG_DATA: u64 = 3;
const MSG_NO_DATA: u64 = 4;
const MSG_WANT: u64 = 5;
const MSG_UNWANT: u64 = 6;
const MSG_BITFIELD: u64 = 7;
const MSG_RANGE: u64 = 8;
const MSG_EXTENSION: u64 = 9;

type PeerId = usize;
type ReqId = u64;
type WaiterId = u64;

#[derive(Debug)]
enum Wire {
    Sync(Sync),
    Request(Request),
    Cancel(Cancel),
    Data(Box<Data>),
    NoData(NoData),
    Want(Want),
    Unwant(Want),
    Bitfield(WireBitfield),
    Range(Range),
    #[allow(dead_code)]
    Extension(Extension),
}

fn decode_wire(kind: u64, data: Bytes) -> Result<Option<Wire>, compact_encoding::Error> {
    Ok(Some(match kind {
        MSG_SYNC => Wire::Sync(decode(data)?),
        MSG_REQUEST => Wire::Request(decode(data)?),
        MSG_CANCEL => Wire::Cancel(decode(data)?),
        MSG_DATA => Wire::Data(Box::new(decode(data)?)),
        MSG_NO_DATA => Wire::NoData(decode(data)?),
        MSG_WANT => Wire::Want(decode(data)?),
        MSG_UNWANT => Wire::Unwant(decode(data)?),
        MSG_BITFIELD => Wire::Bitfield(decode(data)?),
        MSG_RANGE => Wire::Range(decode(data)?),
        MSG_EXTENSION => Wire::Extension(Extension::decode(&mut Reader::new(data))?),
        _ => return Ok(None),
    }))
}

enum Cmd {
    Attach(Mux, Option<PairRequest>),
    MakePeer(Mux, Option<PairRequest>),
    Opened {
        peer: PeerId,
        handshake: Bytes,
    },
    Wire {
        peer: PeerId,
        msg: Wire,
    },
    Closed {
        peer: PeerId,
        remote: bool,
    },
    Drained {
        peer: PeerId,
    },
    GetBlock {
        index: u64,
        force: bool,
        waiter: WaiterId,
        reply: oneshot::Sender<Result<Bytes, CoreError>>,
    },
    Upgrade {
        waiter: WaiterId,
        reply: oneshot::Sender<bool>,
    },
    Range {
        start: u64,
        end: Option<u64>,
        linear: bool,
        waiter: WaiterId,
        reply: oneshot::Sender<bool>,
    },
    Seek {
        bytes: u64,
        padding: u64,
        start: u64,
        end: u64,
        waiter: WaiterId,
        reply: oneshot::Sender<bool>,
    },
    Cancel(WaiterId),
    Active(bool),
    LingerDone(u64),
    Appended {
        start: u64,
        length: u64,
    },
    Truncated {
        start: u64,
        length: u64,
    },
    Cleared {
        start: u64,
        length: u64,
    },
    Destroy,
    /// Open block waiters, seeks and ranges: leak checks for range servers.
    Pending(oneshot::Sender<usize>),
}

/// Handle to a core's replication actor.
#[derive(Clone)]
pub struct Replicator {
    tx: mpsc::UnboundedSender<Cmd>,
    next_waiter: Arc<std::sync::atomic::AtomicU64>,
}

/// A pending download. Dropping it cancels the request.
pub struct Pending<T> {
    rx: oneshot::Receiver<T>,
    cancel: Option<(mpsc::UnboundedSender<Cmd>, WaiterId)>,
}

impl<T> Future for Pending<T> {
    type Output = Option<T>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let r = Pin::new(&mut self.rx).poll(cx);
        if r.is_ready() {
            self.cancel = None;
        }
        r.map(|v| v.ok())
    }
}

impl<T> Drop for Pending<T> {
    fn drop(&mut self) {
        if let Some((tx, id)) = self.cancel.take() {
            let _ = tx.send(Cmd::Cancel(id));
        }
    }
}

impl Replicator {
    pub(crate) fn new(core: &Core) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Actor::new(
            Arc::downgrade(&core.inner),
            *core.discovery_key(),
            tx.clone(),
        );
        tokio::spawn(actor.run(rx));
        Self {
            tx,
            next_waiter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }

    fn waiter(&self) -> WaiterId {
        self.next_waiter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn pending<T>(&self, rx: oneshot::Receiver<T>, id: WaiterId) -> Pending<T> {
        Pending {
            rx,
            cancel: Some((self.tx.clone(), id)),
        }
    }

    /// Replicates this core over `mux` (one call per connection). `pairing`
    /// is the remote open that asked for this core, answered by the attach.
    pub fn attach(&self, mux: &Mux, pairing: Option<PairRequest>) {
        self.send(Cmd::Attach(mux.clone(), pairing));
    }

    pub(crate) fn request_block(
        &self,
        index: u64,
        force: bool,
    ) -> impl Future<Output = Result<Bytes, CoreError>> + use<> {
        let (reply, rx) = oneshot::channel();
        let waiter = self.waiter();
        self.send(Cmd::GetBlock {
            index,
            force,
            waiter,
            reply,
        });
        let p = self.pending(rx, waiter);
        async move { p.await.unwrap_or(Err(CoreError::Closed)) }
    }

    pub(crate) fn request_upgrade(&self) -> impl Future<Output = Result<bool, CoreError>> + use<> {
        let (reply, rx) = oneshot::channel();
        let waiter = self.waiter();
        self.send(Cmd::Upgrade { waiter, reply });
        let p = self.pending(rx, waiter);
        async move { p.await.ok_or(CoreError::Closed) }
    }

    pub(crate) fn request_range(
        &self,
        start: u64,
        end: Option<u64>,
        linear: bool,
    ) -> impl Future<Output = Result<bool, CoreError>> + use<> {
        let (reply, rx) = oneshot::channel();
        let waiter = self.waiter();
        self.send(Cmd::Range {
            start,
            end,
            linear,
            waiter,
            reply,
        });
        let p = self.pending(rx, waiter);
        async move { p.await.ok_or(CoreError::Closed) }
    }

    pub(crate) fn request_seek(
        &self,
        bytes: u64,
        padding: u64,
        start: u64,
        end: u64,
    ) -> impl Future<Output = Result<bool, CoreError>> + use<> {
        let (reply, rx) = oneshot::channel();
        let waiter = self.waiter();
        self.send(Cmd::Seek {
            bytes,
            padding,
            start,
            end,
            waiter,
            reply,
        });
        let p = self.pending(rx, waiter);
        async move { p.await.ok_or(CoreError::Closed) }
    }

    pub(crate) async fn pending_requests(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        self.send(Cmd::Pending(reply));
        rx.await.unwrap_or(0)
    }

    pub(crate) fn set_active(&self, active: bool) {
        self.send(Cmd::Active(active));
    }

    pub(crate) fn on_append(&self, start: u64, length: u64) {
        self.send(Cmd::Appended { start, length });
    }

    pub(crate) fn on_truncate(&self, start: u64, length: u64) {
        self.send(Cmd::Truncated { start, length });
    }

    pub(crate) fn on_clear(&self, start: u64, length: u64) {
        self.send(Cmd::Cleared { start, length });
    }

    pub(crate) fn destroy(&self) {
        self.send(Cmd::Destroy);
    }
}

struct Req {
    peer: PeerId,
    rt: u64,
    fork: u64,
    block: Option<RequestBlock>,
    hash: Option<RequestBlock>,
    seek: Option<RequestSeek>,
    upgrade: Option<RequestUpgrade>,
    manifest: bool,
    priority: u64,
    timestamp: Instant,
    cancelled: bool,
}

impl Req {
    fn wire(&self, id: ReqId) -> Request {
        Request {
            id,
            fork: self.fork,
            block: self.block,
            hash: self.hash,
            seek: self.seek,
            upgrade: self.upgrade,
            manifest: self.manifest,
            priority: self.priority,
        }
    }
}

#[derive(Default)]
struct Inflight {
    reqs: Vec<Option<Req>>,
    free: Vec<ReqId>,
    active: usize,
}

impl Inflight {
    fn idle(&self) -> bool {
        self.active == 0
    }

    fn add(&mut self, req: Req) -> ReqId {
        self.active += 1;
        match self.free.pop() {
            Some(id) => {
                self.reqs[id as usize - 1] = Some(req);
                id
            }
            None => {
                self.reqs.push(Some(req));
                self.reqs.len() as ReqId
            }
        }
    }

    fn get(&self, id: ReqId) -> Option<&Req> {
        self.reqs.get((id as usize).wrapping_sub(1))?.as_ref()
    }

    fn get_mut(&mut self, id: ReqId) -> Option<&mut Req> {
        self.reqs.get_mut((id as usize).wrapping_sub(1))?.as_mut()
    }

    /// `roundtrip`: the id may be reused right away (the remote answered).
    fn remove(&mut self, id: ReqId, roundtrip: bool) -> Option<Req> {
        let req = self.reqs.get_mut((id as usize).wrapping_sub(1))?.take();
        if req.is_some() {
            self.active -= 1;
        }
        if roundtrip {
            self.free.push(id);
        }
        req
    }

    fn ids_for(&self, peer: PeerId) -> Vec<ReqId> {
        self.reqs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.as_ref().is_some_and(|r| r.peer == peer))
            .map(|(i, _)| i as ReqId + 1)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Handle {
    Block(u64),
    RangeBatch(u64, u64),
    Range(u64),
    Seek(u64),
    Fork(u64),
}

struct BlockReq {
    priority: u64,
    inflight: Vec<ReqId>,
    queued: bool,
    hotswap: Option<(usize, usize)>,
    force: bool,
    waiters: Vec<(WaiterId, oneshot::Sender<Result<Bytes, CoreError>>)>,
}

struct UpgradeReq {
    fork: u64,
    length: u64,
    inflight: Vec<ReqId>,
    waiters: Vec<(WaiterId, oneshot::Sender<bool>)>,
}

struct SeekReq {
    id: u64,
    bytes: u64,
    padding: u64,
    start: u64,
    end: u64,
    inflight: Vec<ReqId>,
    waiters: Vec<(WaiterId, oneshot::Sender<bool>)>,
}

struct RangeReq {
    id: u64,
    start: u64,
    end: Option<u64>,
    linear: bool,
    user_start: u64,
    user_end: Option<u64>,
    batches: Vec<u64>,
    waiters: Vec<(WaiterId, oneshot::Sender<bool>)>,
}

struct ForkReq {
    fork: u64,
    inflight: Vec<ReqId>,
    batch: Option<Batch>,
}

struct RoundtripQueue {
    queue: VecDeque<(u64, ReqId)>,
    tick: u64,
}

struct Peer {
    tx: ChannelSender,
    mux: Mux,
    remote_supports_seeks: bool,
    inflight: usize,
    paused: bool,
    removed: bool,
    block_roundtrip: f64,
    receiver_queue: VecDeque<Request>,
    roundtrip_queue: Option<RoundtripQueue>,
    can_upgrade: bool,
    last_upgradable_length: u64,
    last_upgradable_fork: u64,
    remote_contiguous: u64,
    remote_opened: bool,
    remote_bitfield: RemoteBitfield,
    missing_blocks: RemoteBitfield,
    remote_fork: u64,
    remote_length: u64,
    remote_can_upgrade: bool,
    remote_uploading: bool,
    remote_downloading: bool,
    remote_synced: bool,
    remote_has_manifest: bool,
    remote_requests: HashMap<u64, Request>,
    wants: LocalWants<Handle>,
    remote_wants: RemoteWants,
    length_acked: u64,
    fully_downloaded_signaled: u64,
    drain_pending: bool,
    not_available_backoffs: u64,
    backoffs: u64,
    invalid_requests: u64,
}

impl Peer {
    fn is_active(&self, frozen: bool) -> bool {
        !(self.paused || self.removed || frozen)
    }

    fn max_inflight(&self) -> usize {
        DEFAULT_MAX_INFLIGHT.1.min(DEFAULT_MAX_INFLIGHT.0 * 3)
    }

    fn max_hotswap_inflight(&self) -> usize {
        16.max(self.max_inflight() / 2)
    }

    fn remote_has_block(&self, index: u64) -> bool {
        index < self.remote_contiguous || self.remote_bitfield.get(index)
    }

    /// JS `remoteContiguousLength`: the first block the remote lacks.
    fn remote_contiguous_length(&self) -> u64 {
        self.remote_bitfield
            .find_first(false, self.remote_contiguous)
            .unwrap_or(self.remote_contiguous)
    }

    fn send<T: Codec>(&mut self, kind: u64, msg: &T) -> bool {
        self.tx.send(kind, msg)
    }
}

struct Actor {
    core: Weak<Inner>,
    dk: [u8; 32],
    tx: mpsc::UnboundedSender<Cmd>,
    peers: Vec<Option<Peer>>,
    order: Vec<PeerId>,
    inflight: Inflight,
    blocks: HashMap<u64, BlockReq>,
    hashes: HashMap<u64, BlockReq>,
    queued: Vec<u64>,
    hotswaps: [Vec<u64>; 3],
    seeks: Vec<SeekReq>,
    upgrade: Option<UpgradeReq>,
    reorgs: Vec<ForkReq>,
    ranges: Vec<RangeReq>,
    next_id: u64,
    downloading: bool,
    active: bool,
    linger: Option<u64>,
    had_peers: bool,
    if_available: i64,
    manifest_peer: Option<PeerId>,
    attached: Vec<Mux>,
    applying_reorg: bool,
    destroyed: bool,
}

/// JS picks the not-downloading linger at random in [20s, 40s).
fn linger() -> Duration {
    Duration::from_millis(rand::thread_rng().gen_range(20_000..40_000))
}

fn backoff(times: u64) -> Duration {
    Duration::from_millis(match times {
        0..2 => 200,
        2..5 => 500,
        5..40 => 1000,
        _ => 5000,
    })
}

fn remove_id(v: &mut Vec<ReqId>, id: ReqId) -> bool {
    match v.iter().position(|&x| x == id) {
        Some(i) => {
            v.swap_remove(i);
            true
        }
        None => false,
    }
}

impl Actor {
    fn new(core: Weak<Inner>, dk: [u8; 32], tx: mpsc::UnboundedSender<Cmd>) -> Self {
        Self {
            core,
            dk,
            tx,
            peers: vec![],
            order: vec![],
            inflight: Inflight::default(),
            blocks: HashMap::new(),
            hashes: HashMap::new(),
            queued: vec![],
            hotswaps: [vec![], vec![], vec![]],
            seeks: vec![],
            upgrade: None,
            reorgs: vec![],
            ranges: vec![],
            next_id: 1,
            downloading: false,
            active: false,
            linger: None,
            had_peers: false,
            if_available: 0,
            manifest_peer: None,
            attached: vec![],
            applying_reorg: false,
            destroyed: false,
        }
    }

    fn core(&self) -> Option<Core> {
        self.core.upgrade().map(|inner| Core { inner })
    }

    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Cmd>) {
        let mut deferred = VecDeque::new();
        loop {
            let cmd = match deferred.pop_front() {
                Some(c) => c,
                None => match rx.recv().await {
                    Some(c) => c,
                    None => break,
                },
            };
            let Some(core) = self.core() else { break };
            let cmd = match cmd {
                Cmd::Wire {
                    peer,
                    msg: Wire::Data(d),
                } if is_plain_block(&d, core.fork()) => {
                    // Coalesce queued block answers into one storage commit.
                    let mut batch = vec![(peer, *d)];
                    while batch.len() < 64 {
                        match rx.try_recv() {
                            Ok(Cmd::Wire {
                                peer,
                                msg: Wire::Data(d),
                            }) if is_plain_block(&d, core.fork()) => batch.push((peer, *d)),
                            Ok(other) => {
                                deferred.push_back(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    self.on_data_batch(&core, batch).await;
                    continue;
                }
                other => other,
            };
            self.handle(&core, cmd).await;
            if self.destroyed {
                break;
            }
        }
        for p in self.peers.iter().flatten() {
            p.tx.close();
        }
        for mux in &self.attached {
            mux.unpair(PROTOCOL, Some(&self.dk));
        }
    }

    async fn handle(&mut self, core: &Core, cmd: Cmd) {
        match cmd {
            Cmd::Pending(reply) => {
                let waiters: usize = self.blocks.values().map(|b| b.waiters.len()).sum();
                let _ = reply.send(waiters + self.seeks.len() + self.ranges.len());
            }
            Cmd::Attach(mux, pairing) => {
                self.attach(core, mux);
                drop(pairing);
            }
            Cmd::MakePeer(mux, req) => {
                self.make_peer(core, &mux);
                drop(req);
            }
            Cmd::Opened { peer, handshake } => self.on_open(core, peer, handshake),
            Cmd::Wire { peer, msg } => self.on_wire(core, peer, msg).await,
            Cmd::Closed { peer, remote } => self.on_close(core, peer, remote),
            Cmd::Drained { peer } => {
                if let Some(p) = self.peer_mut(peer) {
                    p.drain_pending = false;
                }
                self.handle_requests(core, peer);
            }
            Cmd::GetBlock {
                index,
                force,
                waiter,
                reply,
            } => self.add_block(core, index, force, waiter, reply),
            Cmd::Upgrade { waiter, reply } => self.add_upgrade(core, waiter, reply),
            Cmd::Range {
                start,
                end,
                linear,
                waiter,
                reply,
            } => self.add_range(core, start, end, linear, waiter, reply),
            Cmd::Seek {
                bytes,
                padding,
                start,
                end,
                waiter,
                reply,
            } => {
                let id = self.next_id();
                self.seeks.push(SeekReq {
                    id,
                    bytes,
                    padding,
                    start,
                    end,
                    inflight: vec![],
                    waiters: vec![(waiter, reply)],
                });
                self.update_all(core);
            }
            Cmd::Cancel(waiter) => self.cancel(core, waiter),
            Cmd::Active(active) => self.set_active(core, active),
            Cmd::LingerDone(generation) => {
                if self.linger == Some(generation) {
                    self.linger = None;
                    self.set_downloading_now(core, false);
                }
            }
            Cmd::Appended { start, length } => {
                self.on_upgrade(core);
                self.on_have(core, start, length, false);
            }
            Cmd::Truncated { start, length } => {
                self.on_truncate(core, start, length);
                self.on_have(core, start, length, true);
                self.on_upgrade(core);
            }
            Cmd::Cleared { start, length } => self.on_have(core, start, length, true),
            Cmd::Destroy => self.destroyed = true,
        }
    }

    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn peer(&self, id: PeerId) -> Option<&Peer> {
        self.peers.get(id)?.as_ref()
    }

    fn peer_mut(&mut self, id: PeerId) -> Option<&mut Peer> {
        self.peers.get_mut(id)?.as_mut()
    }

    fn frozen(core: &Core) -> bool {
        core.state().header.frozen
    }

    fn is_downloading(&self) -> bool {
        self.downloading || !self.inflight.idle()
    }

    // Connections

    fn attach(&mut self, core: &Core, mux: Mux) {
        let dk = *core.discovery_key();
        let mut requests = mux.pair(PROTOCOL, Some(&dk));
        let tx = self.tx.clone();
        let m = mux.clone();
        tokio::spawn(async move {
            while let Some(req) = requests.recv().await {
                if tx.send(Cmd::MakePeer(m.clone(), Some(req))).is_err() {
                    break;
                }
            }
        });
        self.attached.push(mux.clone());
        self.make_peer(core, &mux);
    }

    fn make_peer(&mut self, core: &Core, mux: &Mux) -> bool {
        if self.destroyed || mux.is_destroyed() {
            return false;
        }
        let dk = *core.discovery_key();
        if mux.is_opened(PROTOCOL, Some(&dk)) {
            return false;
        }
        let info = mux.stream_info();
        let Some(hh) = info.handshake_hash else {
            return false;
        };
        let capability = crypto::replicate_capability(info.is_initiator, core.key(), &hh);
        let handshake = encode(&Handshake {
            seeks: true,
            capability,
        });
        let Some(channel) = mux.open_channel(ChannelOptions {
            protocol: PROTOCOL,
            id: Some(&dk),
            aliases: &["hypercore"],
            unique: true,
            handshake: &handshake,
        }) else {
            return false;
        };
        let id = self
            .peers
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.peers.push(None);
                self.peers.len() - 1
            });
        self.peers[id] = Some(Peer {
            tx: channel.sender(),
            mux: mux.clone(),
            remote_supports_seeks: false,
            inflight: 0,
            paused: false,
            removed: false,
            block_roundtrip: 0.0,
            receiver_queue: VecDeque::new(),
            roundtrip_queue: None,
            can_upgrade: true,
            last_upgradable_length: 0,
            last_upgradable_fork: 0,
            remote_contiguous: 0,
            remote_opened: false,
            remote_bitfield: RemoteBitfield::new(),
            missing_blocks: RemoteBitfield::new(),
            remote_fork: 0,
            remote_length: 0,
            remote_can_upgrade: false,
            remote_uploading: true,
            remote_downloading: true,
            remote_synced: false,
            remote_has_manifest: false,
            remote_requests: HashMap::new(),
            wants: LocalWants::default(),
            remote_wants: RemoteWants::default(),
            length_acked: 0,
            fully_downloaded_signaled: 0,
            drain_pending: false,
            not_available_backoffs: 0,
            backoffs: 0,
            invalid_requests: 0,
        });
        self.if_available += 1;
        tokio::spawn(forward(channel, id, self.tx.clone()));
        true
    }

    fn on_open(&mut self, core: &Core, id: PeerId, handshake: Bytes) {
        let key = *core.key();
        let Some(p) = self.peer_mut(id) else { return };
        let info = p.mux.stream_info().clone();
        let Ok(hs) = decode::<Handshake>(handshake) else {
            p.mux.destroy();
            return;
        };
        let expected = crypto::replicate_capability(
            !info.is_initiator,
            &key,
            &info.handshake_hash.unwrap_or([0; 64]),
        );
        if hs.capability != expected {
            p.mux.destroy(); // INVALID_CAPABILITY
            return;
        }
        if p.remote_opened {
            return;
        }
        p.remote_opened = true;
        p.remote_supports_seeks = hs.seeks;
        let mux = p.mux.clone();
        mux.cork();
        self.send_sync(core, id);
        let (length, contig) = {
            let st = core.state();
            (
                st.tree.length,
                st.header.contiguous_length.min(st.tree.length),
            )
        };
        if contig > 0 {
            self.broadcast_range(core, id, 0, contig, false);
        }
        let _ = length;
        self.if_available -= 1;
        self.had_peers = true;
        self.order.push(id);
        core.set_peer_count(self.order.len());
        self.update_peer(core, id);
        mux.uncork();
    }

    fn on_close(&mut self, core: &Core, id: PeerId, remote: bool) {
        let Some(p) = self.peer_mut(id) else { return };
        let reopen = remote && p.remote_opened && !p.remote_downloading && p.remote_uploading;
        let mux = p.mux.clone();
        if !p.remote_opened {
            self.peers[id] = None;
            self.if_available -= 1;
            self.update_all(core);
            return;
        }
        p.remote_opened = false;
        p.removed = true;
        p.wants.destroy();
        self.order.retain(|&x| x != id);
        core.set_peer_count(self.order.len());
        if self.manifest_peer == Some(id) {
            self.manifest_peer = None;
        }
        let mut had = false;
        for rid in self.inflight.ids_for(id) {
            had = true;
            if let Some(req) = self.inflight.remove(rid, true) {
                self.clear_request(core, rid, &req);
            }
        }
        self.peers[id] = None;
        if had {
            self.update_all(core);
        } else {
            self.check_upgrade_if_available(core);
        }
        if reopen && self.downloading {
            self.make_peer(core, &mux);
        }
        core.check_if_idle();
    }

    // Outgoing state

    fn send_sync(&mut self, core: &Core, id: PeerId) {
        let downloading = self.is_downloading();
        let (fork, length, has_manifest) = {
            let st = core.state();
            (
                st.tree.fork,
                st.tree.length,
                st.header.manifest.is_some() && !st.compat(),
            )
        };
        let Some(p) = self.peer_mut(id) else { return };
        if fork != p.remote_fork {
            p.can_upgrade = false;
        }
        let msg = Sync {
            fork,
            length,
            remote_length: if fork == p.remote_fork {
                p.remote_length
            } else {
                0
            },
            can_upgrade: p.can_upgrade,
            uploading: true,
            downloading,
            has_manifest,
            allow_push: false,
        };
        p.send(MSG_SYNC, &msg);
    }

    fn can_upgrade_remote(&self, core: &Core, remote_length: u64, remote_fork: u64) -> bool {
        let st = core.state();
        if remote_fork != st.tree.fork {
            return false;
        }
        if remote_length == 0 {
            return true;
        }
        if remote_length >= st.tree.length {
            return false;
        }
        merkle::upgradeable(core.storage(), remote_length).unwrap_or(false)
    }

    fn signal_upgrade(&mut self, core: &Core, id: PeerId) {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        let Some(p) = self.peer(id) else { return };
        let should = fork == p.remote_fork && length > p.remote_length && !p.can_upgrade;
        if should {
            let (rl, rf) = (p.remote_length, p.remote_fork);
            let can = self.can_upgrade_remote(core, rl, rf);
            let p = self.peer_mut(id).expect("peer");
            if can == p.can_upgrade {
                return;
            }
            p.can_upgrade = can;
            if can {
                p.last_upgradable_length = rl;
                p.last_upgradable_fork = rf;
            }
        }
        self.send_sync(core, id);
    }

    fn broadcast_range(
        &mut self,
        core: &Core,
        id: PeerId,
        mut start: u64,
        mut length: u64,
        drop: bool,
    ) {
        let frozen = Self::frozen(core);
        if !self.peer(id).is_some_and(|p| p.is_active(frozen)) {
            return;
        }
        if drop {
            self.unclear_local_range(core, id, start, length);
        } else {
            self.clear_local_range(core, id, start, length);
        }
        let (tree_length, contig) = {
            let st = core.state();
            (st.tree.length, st.header.contiguous_length)
        };
        let fully_contig = contig == tree_length;
        let p = self.peer_mut(id).expect("peer");
        if start + LAST_BLOCKS < tree_length
            && !drop
            && !fully_contig
            && !p.remote_wants.has_range(start, length)
        {
            return;
        }
        let mut force = false;
        if fully_contig && !drop {
            start = 0;
            length = tree_length;
            if p.fully_downloaded_signaled < length {
                p.fully_downloaded_signaled = length;
                force = true;
            }
        }
        if !force && !drop {
            if p.remote_contiguous >= start + length {
                return;
            }
            if length == 1 {
                if p.remote_bitfield.get(start) {
                    return;
                }
            } else if p
                .remote_bitfield
                .find_first(false, start)
                .is_some_and(|u| u >= start + length)
            {
                return;
            }
        }
        p.send(
            MSG_RANGE,
            &Range {
                drop,
                start,
                length,
            },
        );
    }

    fn clear_local_range(&mut self, core: &Core, id: PeerId, mut start: u64, mut length: u64) {
        let st = core.state();
        let Some(p) = self.peers.get_mut(id).and_then(Option::as_mut) else {
            return;
        };
        if length == 1 {
            let v = p.remote_has_block(start) && !st.bitfield.get(start);
            p.missing_blocks.set(start, v);
            return;
        }
        let contig = st.tree.length.min(st.header.contiguous_length);
        if start + length < contig {
            p.missing_blocks.set_range(start, contig, false);
            return;
        }
        let rem = start & (PAGE_BITS - 1);
        start -= rem;
        length += rem;
        let end = start + length.min(st.tree.length);
        while start < end {
            if let Some(words) = st.bitfield.page_words(start) {
                p.missing_blocks.clear(start, words);
            }
            start += PAGE_BITS;
        }
    }

    fn reset_missing_block(&mut self, core: &Core, id: PeerId, index: u64) {
        let local = core.has(index);
        if let Some(p) = self.peer_mut(id) {
            let v = p.remote_has_block(index) && !local;
            p.missing_blocks.set(index, v);
        }
    }

    fn unclear_local_range(&mut self, core: &Core, id: PeerId, mut start: u64, mut length: u64) {
        if length == 1 {
            self.reset_missing_block(core, id, start);
            return;
        }
        let seg = crate::bitfield::BITS_PER_PAGE;
        let Some(p) = self.peer_mut(id) else { return };
        let rem = start & (seg - 1);
        start -= rem;
        length += rem;
        let fixed = start;
        let end = start + length.min(p.remote_length);
        for (s, words) in p.remote_bitfield.pages_in(start, end) {
            p.missing_blocks.insert(s, words);
        }
        self.clear_local_range(core, id, fixed, length);
    }

    // Core events

    fn on_have(&mut self, core: &Core, start: u64, length: u64, drop: bool) {
        for id in self.order.clone() {
            self.broadcast_range(core, id, start, length, drop);
        }
    }

    fn on_truncate(&mut self, core: &Core, new_length: u64, truncated: u64) {
        let gone: Vec<u64> = self
            .blocks
            .keys()
            .copied()
            .filter(|&i| i >= new_length)
            .collect();
        for i in gone {
            if let Some(b) = self.blocks.get_mut(&i) {
                for (_, w) in b.waiters.drain(..) {
                    let _ = w.send(Err(CoreError::SnapshotNotAvailable));
                }
            }
            self.gc_block(core, i, false);
        }
        for id in self.order.clone() {
            if let Some(p) = self.peer_mut(id) {
                p.fully_downloaded_signaled = p.fully_downloaded_signaled.min(new_length);
            }
            self.unclear_local_range(core, id, new_length, truncated);
        }
    }

    fn on_upgrade(&mut self, core: &Core) {
        for id in self.order.clone() {
            self.signal_upgrade(core, id);
        }
        if !self.blocks.is_empty() {
            self.resolve_blocks_locally(core);
        }
        if self.upgrade.is_some() {
            self.resolve_upgrade_request(core, None);
        }
        if !self.blocks.is_empty() || !self.ranges.is_empty() || !self.seeks.is_empty() {
            self.update_non_primary(core);
        }
    }

    fn set_active(&mut self, core: &Core, active: bool) {
        self.active = active;
        self.linger = None;
        if active {
            self.set_downloading_now(core, true);
            return;
        }
        // Lets a short gap between sessions keep connections warm, as JS does.
        let generation = self.next_id();
        self.linger = Some(generation);
        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(linger()).await;
            let _ = tx.send(Cmd::LingerDone(generation));
        });
    }

    fn set_downloading_now(&mut self, core: &Core, downloading: bool) {
        if self.downloading == downloading {
            return;
        }
        self.downloading = downloading;
        if !downloading && self.is_downloading() {
            return;
        }
        for id in self.order.clone() {
            self.signal_upgrade(core, id);
        }
        if downloading {
            for mux in self.attached.clone() {
                if !mux.is_destroyed() {
                    self.make_peer(core, &mux);
                }
            }
        } else {
            for id in self.order.clone() {
                self.close_if_idle(id);
            }
        }
    }

    fn close_if_idle(&mut self, id: PeerId) -> bool {
        let downloading = self.is_downloading();
        let Some(p) = self.peer(id) else { return false };
        if !p.remote_downloading && !downloading {
            p.tx.close();
            return true;
        }
        false
    }

    // Local requests

    fn add_block(
        &mut self,
        core: &Core,
        index: u64,
        force: bool,
        waiter: WaiterId,
        reply: oneshot::Sender<Result<Bytes, CoreError>>,
    ) {
        if let Ok(Some(b)) = core.get_raw_local(index) {
            let _ = reply.send(Ok(b));
            return;
        }
        let b = self.blocks.entry(index).or_insert_with(|| BlockReq {
            priority: PRIORITY_HIGH,
            inflight: vec![],
            queued: false,
            hotswap: None,
            force,
            waiters: vec![],
        });
        b.waiters.push((waiter, reply));
        if b.inflight.is_empty() && !b.queued {
            b.queued = true;
            self.queued.push(index);
        }
        self.update_all(core);
    }

    fn add_upgrade(&mut self, core: &Core, waiter: WaiterId, reply: oneshot::Sender<bool>) {
        let fresh = self.upgrade.is_none();
        self.ensure_upgrade(core).waiters.push((waiter, reply));
        if fresh {
            self.update_all(core);
        } else {
            self.check_upgrade_if_available(core);
        }
    }

    fn ensure_upgrade(&mut self, core: &Core) -> &mut UpgradeReq {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        self.upgrade.get_or_insert_with(|| UpgradeReq {
            fork,
            length,
            inflight: vec![],
            waiters: vec![],
        })
    }

    fn add_range(
        &mut self,
        core: &Core,
        start: u64,
        end: Option<u64>,
        linear: bool,
        waiter: WaiterId,
        reply: oneshot::Sender<bool>,
    ) {
        let id = self.next_id();
        let mut r = RangeReq {
            id,
            start,
            end,
            linear,
            user_start: start,
            user_end: end,
            batches: vec![],
            waiters: vec![(waiter, reply)],
        };
        clamp_range(core, &mut r);
        if r.end.is_some_and(|e| r.start >= e) {
            for (_, w) in r.waiters {
                let _ = w.send(true);
            }
            return;
        }
        self.ranges.push(r);
        self.update_all(core);
    }

    fn cancel(&mut self, core: &Core, waiter: WaiterId) {
        let block = self.blocks.iter_mut().find_map(|(i, b)| {
            let pos = b.waiters.iter().position(|(w, _)| *w == waiter)?;
            b.waiters.swap_remove(pos);
            Some(*i)
        });
        if let Some(i) = block {
            if self.blocks.get(&i).is_some_and(|b| b.waiters.is_empty()) {
                self.gc_block(core, i, true);
            }
            self.update_all(core);
            return;
        }
        if let Some(u) = self.upgrade.as_mut() {
            u.waiters.retain(|(w, _)| *w != waiter);
            if u.waiters.is_empty() && u.inflight.is_empty() {
                // JS keeps an eager upgrade alive; nobody waits on it here.
                self.upgrade = None;
            }
        }
        if let Some(i) = self
            .ranges
            .iter()
            .position(|r| r.waiters.iter().any(|(w, _)| *w == waiter))
        {
            self.ranges[i].waiters.retain(|(w, _)| *w != waiter);
            if self.ranges[i].waiters.is_empty() {
                let r = self.ranges.swap_remove(i);
                self.drop_range_wants(core, &r);
            }
        }
        if let Some(i) = self
            .seeks
            .iter()
            .position(|s| s.waiters.iter().any(|(w, _)| *w == waiter))
        {
            self.seeks[i].waiters.retain(|(w, _)| *w != waiter);
            // A late answer to its inflight request still verifies and stores the nodes.
            if self.seeks[i].waiters.is_empty() {
                let s = self.seeks.swap_remove(i);
                self.drop_handle_wants(core, Handle::Seek(s.id));
            }
        }
    }

    fn drop_range_wants(&mut self, core: &Core, r: &RangeReq) {
        self.drop_handle_wants(core, Handle::Range(r.id));
        for &b in &r.batches {
            self.drop_handle_wants(core, Handle::RangeBatch(r.id, b));
        }
    }

    /// JS `Attachable.gc` for wants: drop `handle` everywhere, send unwants.
    fn drop_handle_wants(&mut self, core: &Core, handle: Handle) {
        let mut update = vec![];
        for id in self.order.clone() {
            let Some(p) = self.peer_mut(id) else { continue };
            for (s, l) in p.wants.any_ranges_of(handle) {
                if let Some(u) = p.wants.remove_any_range(s, l, handle) {
                    p.send(MSG_UNWANT, &u);
                    update.push(id);
                }
            }
            if p.wants.remove_handle(handle) {
                update.push(id);
            }
        }
        for id in update {
            self.update_peer(core, id);
        }
    }

    /// Drops a block request; `cancel` also cancels its in-flight requests.
    fn gc_block(&mut self, core: &Core, index: u64, cancel: bool) {
        let Some(b) = self.blocks.remove(&index) else {
            return;
        };
        self.remove_hotswap(&b);
        if cancel {
            for rid in b.inflight.clone() {
                self.cancel_request(core, rid);
            }
        }
        self.drop_handle_wants(core, Handle::Block(index));
    }

    // Hotswap queue (HotswapQueue)

    fn hotswap_add(&mut self, index: u64) {
        let Some(b) = self.blocks.get(&index) else {
            return;
        };
        if let Some(h) = b.hotswap {
            self.hotswap_remove_at(h);
        }
        let b = self.blocks.get_mut(&index).expect("block");
        b.hotswap = None;
        if b.inflight.is_empty() || b.inflight.len() >= 3 {
            return;
        }
        let q = b.inflight.len() - 1;
        self.hotswaps[q].push(index);
        b.hotswap = Some((q, self.hotswaps[q].len() - 1));
    }

    fn hotswap_remove_at(&mut self, (q, i): (usize, usize)) {
        let queue = &mut self.hotswaps[q];
        queue.swap_remove(i);
        if let Some(&moved) = queue.get(i)
            && let Some(b) = self.blocks.get_mut(&moved)
        {
            b.hotswap = Some((q, i));
        }
    }

    fn remove_hotswap(&mut self, b: &BlockReq) -> bool {
        match b.hotswap {
            Some(h) => {
                self.hotswap_remove_at(h);
                true
            }
            None => false,
        }
    }

    // Inflight bookkeeping

    fn request_done(&mut self, core: &Core, id: ReqId, roundtrip: bool) -> Option<Req> {
        let req = self.inflight.remove(id, roundtrip);
        if !self.is_downloading() {
            for p in self.order.clone() {
                self.signal_upgrade(core, p);
            }
        }
        req
    }

    /// `peer._cancelRequest`.
    fn cancel_request(&mut self, core: &Core, rid: ReqId) {
        let Some(req) = self.inflight.get_mut(rid) else {
            return;
        };
        if req.cancelled {
            return;
        }
        req.cancelled = true;
        let peer = req.peer;
        let block = req.block.map(|b| b.index);
        let upgrade = req.upgrade.is_some();
        if let Some(p) = self.peer_mut(peer) {
            p.inflight = p.inflight.saturating_sub(1);
        }
        self.request_done(core, rid, false);
        if let Some(i) = block {
            self.unmark_inflight(core, i);
        }
        if upgrade && let Some(u) = self.upgrade.as_mut() {
            remove_id(&mut u.inflight, rid);
        }
        if let Some(p) = self.peer_mut(peer) {
            let q = p.roundtrip_queue.get_or_insert_with(|| RoundtripQueue {
                queue: VecDeque::new(),
                tick: 0,
            });
            q.tick += 1;
            let tick = q.tick;
            q.queue.push_back((tick, rid));
            p.send(MSG_CANCEL, &Cancel { request: rid });
        }
    }

    /// The remote answered `rid`; returns the request it answered.
    fn on_request_roundtrip(&mut self, core: &Core, rid: ReqId) -> Option<Req> {
        let req = self.inflight.get_mut(rid)?;
        if req.cancelled {
            return None;
        }
        req.cancelled = true;
        let peer = req.peer;
        if let Some(p) = self.peer_mut(peer) {
            p.inflight = p.inflight.saturating_sub(1);
        }
        let req = self.request_done(core, rid, true)?;
        if let Some(q) = self.peer_mut(peer).and_then(|p| p.roundtrip_queue.as_mut()) {
            let mut flushed = vec![];
            while q.queue.front().is_some_and(|(t, _)| *t <= req.rt) {
                flushed.push(q.queue.pop_front().expect("front").1);
            }
            self.inflight.free.extend(flushed);
        }
        Some(req)
    }

    fn mark_inflight(&mut self, index: u64) {
        for p in self.peers.iter_mut().flatten() {
            p.missing_blocks.set(index, false);
        }
    }

    fn unmark_inflight(&mut self, core: &Core, index: u64) {
        for id in self.order.clone() {
            self.reset_missing_block(core, id, index);
        }
    }

    /// `_clearRequest`: a request ended without being answered.
    fn clear_request(&mut self, core: &Core, rid: ReqId, req: &Req) {
        let (block, hash, upgrade) = (
            req.block.map(|b| b.index),
            req.hash.map(|h| h.index / 2),
            req.upgrade.is_some(),
        );
        if let Some(i) = block {
            self.clear_inflight_block(core, i, rid, true);
            self.unmark_inflight(core, i);
        }
        if let Some(i) = hash {
            self.clear_inflight_block(core, i, rid, false);
        }
        if upgrade && let Some(u) = self.upgrade.as_mut() {
            remove_id(&mut u.inflight, rid);
        }
        for s in &mut self.seeks {
            remove_id(&mut s.inflight, rid);
        }
        for f in &mut self.reorgs {
            remove_id(&mut f.inflight, rid);
        }
    }

    fn clear_inflight_block(&mut self, core: &Core, index: u64, rid: ReqId, is_block: bool) {
        let tracker = if is_block {
            &mut self.blocks
        } else {
            &mut self.hashes
        };
        let Some(b) = tracker.get_mut(&index) else {
            return;
        };
        if !remove_id(&mut b.inflight, rid) {
            return;
        }
        if !is_block {
            if b.inflight.is_empty() {
                self.hashes.remove(&index);
            }
            return;
        }
        let had_hotswap = b.hotswap.is_some();
        let still = !b.inflight.is_empty();
        if had_hotswap {
            let h = b.hotswap.take().expect("hotswap");
            self.hotswap_remove_at(h);
            if still {
                self.hotswap_add(index);
            }
        }
        let b = self.blocks.get_mut(&index).expect("block");
        if !b.waiters.is_empty() {
            if b.inflight.is_empty() && !b.queued {
                b.queued = true;
                self.queued.push(index);
            }
            return;
        }
        if b.inflight.is_empty() {
            self.gc_block(core, index, false);
        }
    }

    fn resolve_blocks_locally(&mut self, core: &Core) {
        let have: Vec<u64> = self
            .blocks
            .keys()
            .copied()
            .filter(|&i| core.has(i))
            .collect();
        for i in have {
            let value = core.get_raw_local(i);
            let Some(b) = self.blocks.remove(&i) else {
                continue;
            };
            self.remove_hotswap(&b);
            for (_, w) in b.waiters {
                let _ = w.send(match &value {
                    Ok(Some(v)) => Ok(v.clone()),
                    Ok(None) => Err(CoreError::NotFound),
                    Err(e) => Err(CoreError::BadArgument(e.to_string())),
                });
            }
            for rid in b.inflight {
                self.cancel_request(core, rid);
            }
        }
    }

    fn resolve_block_request(
        &mut self,
        core: &Core,
        is_block: bool,
        index: u64,
        value: Option<Bytes>,
        rid: Option<ReqId>,
    ) {
        let tracker = if is_block {
            &mut self.blocks
        } else {
            &mut self.hashes
        };
        let Some(mut b) = tracker.remove(&index) else {
            return;
        };
        if let Some(rid) = rid {
            remove_id(&mut b.inflight, rid);
        }
        if is_block {
            self.remove_hotswap(&b);
        }
        for (_, w) in b.waiters {
            let _ = w.send(value.clone().ok_or(CoreError::NotFound));
        }
        for rid in b.inflight {
            self.cancel_request(core, rid);
        }
        if is_block {
            self.drop_handle_wants(core, Handle::Block(index));
        }
    }

    fn resolve_upgrade_request(&mut self, core: &Core, rid: Option<ReqId>) -> bool {
        let Some(u) = self.upgrade.as_mut() else {
            return false;
        };
        if let Some(rid) = rid {
            remove_id(&mut u.inflight, rid);
        }
        let head = core.head();
        if head.length == u.length && head.fork == u.fork {
            return false;
        }
        let u = self.upgrade.take().expect("upgrade");
        for (_, w) in u.waiters {
            let _ = w.send(true);
        }
        true
    }

    fn check_upgrade_if_available(&mut self, core: &Core) {
        if self.if_available > 0 && self.order.len() < MAX_PEERS_UPGRADE {
            return;
        }
        let Some(u) = &self.upgrade else { return };
        if u.waiters.is_empty() || !self.had_peers && self.order.is_empty() {
            return;
        }
        let (length, fork) = {
            let st = core.state();
            (st.tree.length, st.tree.fork)
        };
        for &id in self.order.iter().take(MAX_PEERS_UPGRADE) {
            let Some(p) = self.peer(id) else { continue };
            if !p.remote_synced {
                return;
            }
            if length == 0 && p.remote_length > 0 {
                return;
            }
            if p.remote_length <= u.length || p.remote_fork != u.fork {
                continue;
            }
            if p.length_acked != length && p.remote_fork == fork {
                return;
            }
            if p.remote_can_upgrade {
                return;
            }
        }
        if self.applying_reorg
            || self.reorgs.iter().any(|r| !r.inflight.is_empty())
            || !u.inflight.is_empty()
        {
            return;
        }
        let u = self.upgrade.take().expect("upgrade");
        for (_, w) in u.waiters {
            let _ = w.send(false);
        }
    }

    fn should_upgrade(&self, core: &Core, p: &Peer) -> bool {
        if self
            .upgrade
            .as_ref()
            .is_some_and(|u| !u.inflight.is_empty())
        {
            return false;
        }
        let length = core.length();
        p.remote_can_upgrade && p.remote_length > length && p.length_acked == length
    }

    fn auto_upgrade(&self, core: &Core, p: &Peer) -> bool {
        self.upgrade.is_some() && p.remote_fork == core.fork() && self.should_upgrade(core, p)
    }

    // Incoming wire messages

    async fn on_wire(&mut self, core: &Core, id: PeerId, msg: Wire) {
        match msg {
            Wire::Sync(m) => self.on_sync(core, id, m),
            Wire::Request(m) => self.on_request(core, id, m),
            Wire::Cancel(m) => {
                if let Some(p) = self.peer_mut(id) {
                    p.remote_requests.remove(&m.request);
                    p.receiver_queue.retain(|r| r.id != m.request);
                }
            }
            Wire::Data(m) => self.on_data(core, id, *m).await,
            Wire::NoData(m) => self.on_no_data(core, id, m),
            Wire::Want(m) => {
                let accepted = self.peer_mut(id).is_some_and(|p| p.remote_wants.add(m));
                if accepted {
                    self.on_want(core, id, m);
                }
            }
            Wire::Unwant(m) => {
                if let Some(p) = self.peer_mut(id) {
                    p.remote_wants.remove(m);
                }
            }
            Wire::Bitfield(m) => self.on_bitfield(core, id, m),
            Wire::Range(m) => self.on_range(core, id, m),
            Wire::Extension(_) => {}
        }
    }

    fn on_sync(&mut self, core: &Core, id: PeerId, m: Sync) {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        let Some(p) = self.peer_mut(id) else { return };
        let length_changed = m.length != p.remote_length;
        let same_fork = m.fork == fork;
        p.remote_synced = true;
        p.remote_fork = m.fork;
        p.remote_length = m.length;
        p.remote_can_upgrade = m.can_upgrade;
        p.remote_uploading = m.uploading;
        p.remote_downloading = m.downloading;
        p.remote_has_manifest = m.has_manifest;
        if self.close_if_idle(id) {
            return;
        }
        let p = self.peer_mut(id).expect("peer");
        p.length_acked = if same_fork { m.remote_length } else { 0 };
        let (remote_length, length_acked, can) = (p.remote_length, p.length_acked, p.can_upgrade);

        self.update_fork(core, id);
        if remote_length > length && length_acked == length {
            self.ensure_upgrade(core);
            self.update_peer(core, id);
        }
        let upgrade = if !length_changed || !same_fork {
            can && same_fork
        } else {
            self.can_upgrade_remote(core, m.length, m.fork)
        };
        let Some(p) = self.peer_mut(id) else { return };
        if m.length == p.remote_length && m.fork == fork {
            p.can_upgrade = upgrade;
            if upgrade {
                p.last_upgradable_fork = m.fork;
                p.last_upgradable_length = m.length;
            }
        }
        if fork == p.remote_fork && length > p.remote_length {
            self.signal_upgrade(core, id);
        }
        self.update_peer(core, id);
    }

    fn on_request(&mut self, core: &Core, id: PeerId, m: Request) {
        let Some(p) = self.peer_mut(id) else { return };
        if p.remote_requests.insert(m.id, m.clone()).is_some() {
            p.receiver_queue.retain(|r| r.id != m.id);
        }
        if !p.mux.is_drained() || !p.receiver_queue.is_empty() {
            p.receiver_queue.push_back(m);
            self.wait_drain(id);
            return;
        }
        self.handle_request(core, id, m);
    }

    fn wait_drain(&mut self, id: PeerId) {
        let tx = self.tx.clone();
        let Some(p) = self.peer_mut(id) else { return };
        if p.drain_pending {
            return;
        }
        p.drain_pending = true;
        let mux = p.mux.clone();
        tokio::spawn(async move {
            mux.drained().await;
            let _ = tx.send(Cmd::Drained { peer: id });
        });
    }

    fn handle_requests(&mut self, core: &Core, id: PeerId) {
        let Some(p) = self.peer(id) else { return };
        let mux = p.mux.clone();
        mux.cork();
        while let Some(p) = self.peer_mut(id) {
            if !p.remote_opened || p.removed {
                break;
            }
            if !mux.is_drained() {
                self.wait_drain(id);
                break;
            }
            // Priority requests first, as ReceiverQueue does.
            let next = match p.receiver_queue.iter().position(|r| r.priority > 0) {
                Some(i) => p.receiver_queue.remove(i),
                None => p.receiver_queue.pop_front(),
            };
            let Some(m) = next else { break };
            self.handle_request(core, id, m);
        }
        mux.uncork();
    }

    fn handle_request(&mut self, core: &Core, id: PeerId, m: Request) {
        let (fork, has_block) = {
            let st = core.state();
            (
                st.tree.fork,
                m.block.is_some_and(|b| st.bitfield.get(b.index)),
            )
        };
        let req = ProofRequest {
            block: m.block,
            hash: m.hash,
            seek: m.seek,
            upgrade: m.upgrade,
        };
        let proof = if m.fork != fork || (m.block.is_some() && !has_block) {
            Ok(None)
        } else {
            core.proof_for(&req, m.manifest).map(Some)
        };
        let Some(p) = self.peer_mut(id) else { return };
        if p.remote_requests.get(&m.id) != Some(&m) {
            return; // cancelled meanwhile
        }
        p.remote_requests.remove(&m.id);
        match proof {
            Err(_) => {
                p.invalid_requests += 1;
                if p.invalid_requests >= MAX_INVALID_REQUESTS {
                    p.mux.destroy();
                    return;
                }
                // JS backs off before answering an invalid request.
                let tx = p.tx.clone();
                let delay = backoff(p.invalid_requests);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    tx.send(
                        MSG_NO_DATA,
                        &NoData {
                            request: m.id,
                            reason: INVALID_REQUEST,
                        },
                    );
                });
            }
            Ok(None) => {
                let manifest = if m.manifest { core.manifest() } else { None };
                let Some(p) = self.peer_mut(id) else { return };
                match manifest {
                    Some(manifest) => {
                        let d = Data {
                            request: m.id,
                            fork,
                            manifest: Some(manifest),
                            ..Default::default()
                        };
                        p.send(MSG_DATA, &d);
                    }
                    None => {
                        p.send(
                            MSG_NO_DATA,
                            &NoData {
                                request: m.id,
                                reason: NOT_AVAILABLE,
                            },
                        );
                    }
                }
            }
            Ok(Some(mut data)) => {
                let frozen = Self::frozen(core);
                let Some(p) = self.peer_mut(id) else { return };
                if !p.is_active(frozen) && data.block.is_some() {
                    return;
                }
                data.request = m.id;
                data.fork = m.fork;
                if !p.send(MSG_DATA, &data) {
                    self.wait_drain(id);
                }
            }
        }
    }

    async fn on_data(&mut self, core: &Core, id: PeerId, data: Data) {
        if data.request == 0 && data.upgrade.as_ref().is_some_and(|u| u.start == 0) {
            if core.check_conflict(&data).await.unwrap_or(true) {
                return;
            }
            if let Some(p) = self.peer_mut(id) {
                p.paused = false;
            }
        }
        let rid = (data.request > 0)
            .then_some(data.request)
            .filter(|r| self.inflight.get(*r).is_some());
        let reorg = data.fork > core.fork();
        if rid.is_none() && !reorg {
            return; // no push mode
        }
        let mut req = None;
        if let Some(rid) = rid {
            if self.inflight.get(rid).map(|r| r.peer) != Some(id) {
                return;
            }
            req = self.on_request_roundtrip(core, rid);
        }
        if reorg {
            if self.on_reorg_data(core, id, rid, &data).await.is_err() {
                self.unmark_block_request(core, req.as_ref(), &data);
                if let Some(p) = self.peer_mut(id) {
                    p.paused = true;
                }
            }
            return;
        }
        let matching = req.as_ref().is_some_and(|r| matching_request(r, &data));
        let verified = if matching {
            core.verify(data.clone()).await
        } else {
            Ok(None)
        };
        self.after_verify(core, id, rid, req, data, verified);
    }

    fn after_verify(
        &mut self,
        core: &Core,
        id: PeerId,
        rid: Option<ReqId>,
        req: Option<Req>,
        data: Data,
        verified: Result<Option<bool>, CoreError>,
    ) {
        match verified {
            Ok(Some(upgraded)) => {
                self.on_verified_data(core, id, rid, req.as_ref(), data, upgraded)
            }
            Ok(None) => self.on_no_data_inner(core, id, rid, req.as_ref(), 0),
            Err(e) => {
                self.unmark_block_request(core, req.as_ref(), &data);
                let invalid_op = matches!(
                    e,
                    CoreError::Merkle(merkle::MerkleError::InvalidOperation(_))
                );
                if !invalid_op {
                    self.check_if_conflict(core, id);
                }
                if let Some(p) = self.peer_mut(id) {
                    p.paused = true;
                }
                self.on_no_data_inner(core, id, rid, req.as_ref(), 0);
            }
        }
    }

    /// Answers to plain block requests, verified and stored in one commit.
    async fn on_data_batch(&mut self, core: &Core, items: Vec<(PeerId, Data)>) {
        let mut ok = vec![];
        for (id, data) in items {
            let rid = data.request;
            if self.inflight.get(rid).map(|r| r.peer) != Some(id) {
                continue;
            }
            let req = self.on_request_roundtrip(core, rid);
            if req.as_ref().is_some_and(|r| matching_request(r, &data)) {
                ok.push((id, rid, req, data));
            } else {
                self.on_no_data_inner(core, id, Some(rid), req.as_ref(), 0);
            }
        }
        let proofs: Vec<Data> = ok.iter().map(|x| x.3.clone()).collect();
        let results = core.verify_blocks(&proofs).await;
        for ((id, rid, req, data), r) in ok.into_iter().zip(results) {
            self.after_verify(core, id, Some(rid), req, data, r);
        }
    }

    fn unmark_block_request(&mut self, core: &Core, req: Option<&Req>, data: &Data) {
        let idx = match req {
            Some(r) => r.block.map(|b| b.index),
            None => data.block.as_ref().map(|b| b.index),
        };
        if let Some(i) = idx {
            self.unmark_inflight(core, i);
        }
    }

    fn check_if_conflict(&mut self, core: &Core, id: PeerId) {
        let length = core.length();
        let Some(p) = self.peer_mut(id) else { return };
        p.paused = true;
        let length = length.min(p.remote_length);
        if length == 0 {
            return;
        }
        let req = Request {
            id: 0,
            fork: p.remote_fork,
            upgrade: Some(RequestUpgrade { start: 0, length }),
            ..Default::default()
        };
        p.send(MSG_REQUEST, &req);
    }

    fn on_verified_data(
        &mut self,
        core: &Core,
        id: PeerId,
        rid: Option<ReqId>,
        req: Option<&Req>,
        data: Data,
        upgraded: bool,
    ) {
        // Core state changed: let peers know before resolving waiters.
        if upgraded {
            self.on_upgrade(core);
        }
        if let Some(b) = &data.block {
            self.on_have(core, b.index, 1, false);
        }
        if let (Some(req), Some(_)) = (req, &data.block) {
            let elapsed = req.timestamp.elapsed().as_secs_f64() * 1000.0;
            if let Some(p) = self.peer_mut(id) {
                p.block_roundtrip = if p.block_roundtrip == 0.0 {
                    elapsed
                } else {
                    p.block_roundtrip * 0.9 + elapsed * 0.1
                };
            }
        }
        if let Some(b) = &data.block {
            self.resolve_block_request(core, true, b.index, Some(b.value.clone()), rid);
        }
        if let Some(h) = &data.hash
            && h.index & 1 == 0
        {
            self.resolve_block_request(core, false, h.index / 2, None, rid);
        }
        if self.upgrade.is_some() {
            self.resolve_upgrade_request(core, rid);
        }
        if let Some(rid) = rid {
            for s in &mut self.seeks {
                remove_id(&mut s.inflight, rid);
            }
            for f in &mut self.reorgs {
                remove_id(&mut f.inflight, rid);
            }
        }
        if self.manifest_peer == Some(id) && core.manifest().is_some() {
            self.manifest_peer = None;
        }
        if !self.seeks.is_empty() || !self.ranges.is_empty() {
            self.update_non_primary(core);
        }
        self.update_peer(core, id);
        self.request_upgrade_check(core, id);
    }

    fn request_upgrade_check(&mut self, core: &Core, id: PeerId) {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        if self
            .peer(id)
            .is_some_and(|p| fork == p.remote_fork && length > p.remote_length && !p.can_upgrade)
        {
            self.signal_upgrade(core, id);
        }
    }

    fn on_no_data(&mut self, core: &Core, id: PeerId, m: NoData) {
        let rid = (m.request > 0)
            .then_some(m.request)
            .filter(|r| self.inflight.get(*r).is_some_and(|q| q.peer == id));
        let Some(rid) = rid else {
            self.update_all(core);
            return;
        };
        let req = self.on_request_roundtrip(core, rid);
        self.on_no_data_inner(core, id, Some(rid), req.as_ref(), m.reason);
    }

    fn on_no_data_inner(
        &mut self,
        core: &Core,
        id: PeerId,
        rid: Option<ReqId>,
        req: Option<&Req>,
        reason: u64,
    ) {
        if let Some(p) = self.peer_mut(id) {
            if reason == NOT_AVAILABLE {
                p.not_available_backoffs += 1;
                if p.not_available_backoffs >= MAX_BACKOFFS {
                    p.paused = true;
                }
            }
            if reason == INVALID_REQUEST {
                p.backoffs += 1;
                if p.backoffs >= MAX_BACKOFFS {
                    p.paused = true;
                }
            }
        }
        if let (Some(rid), Some(req)) = (rid, req) {
            self.clear_request(core, rid, req);
        }
        self.update_all(core);
    }

    fn on_want(&mut self, core: &Core, id: PeerId, w: Want) {
        let frozen = Self::frozen(core);
        let st = core.state();
        let contig = st.tree.length.min(st.header.contiguous_length);
        let length = st.tree.length;
        let Some(p) = self.peers.get_mut(id).and_then(Option::as_mut) else {
            return;
        };
        if !p.is_active(frozen) {
            return;
        }
        if w.start + w.length < contig || length == contig || (w.any && w.start < contig) {
            p.send(
                MSG_RANGE,
                &Range {
                    drop: false,
                    start: 0,
                    length: contig,
                },
            );
            return;
        }
        let len = w.length.min(length.saturating_sub(w.start));
        if w.any {
            if let Some(bit) = st
                .bitfield
                .find_first(true, w.start)
                .filter(|&b| b < w.start + len)
            {
                p.send(
                    MSG_RANGE,
                    &Range {
                        drop: false,
                        start: bit,
                        length: 1,
                    },
                );
            }
            return;
        }
        for (start, words) in st.bitfield.want(w.start, len) {
            p.send(
                MSG_BITFIELD,
                &WireBitfield {
                    start,
                    bitfield: words,
                },
            );
        }
    }

    fn on_bitfield(&mut self, core: &Core, id: PeerId, m: WireBitfield) {
        let Some(p) = self.peer_mut(id) else { return };
        if m.start < p.remote_contiguous {
            p.remote_contiguous = m.start;
        }
        p.remote_bitfield.insert(m.start, &m.bitfield);
        p.missing_blocks.insert(m.start, &m.bitfield);
        p.remote_contiguous = p.remote_contiguous_length();
        let bits = m.bitfield.len() as u64 * 32;
        self.clear_local_range(core, id, m.start, bits);
        self.update_peer(core, id);
    }

    fn on_range(&mut self, core: &Core, id: PeerId, m: Range) {
        let fork = core.fork();
        let Some(p) = self.peer_mut(id) else { return };
        let has = !m.drop;
        if m.drop && m.start < p.remote_contiguous {
            let end = m.start + m.length;
            let rc = p.remote_contiguous;
            if end < rc {
                p.remote_bitfield.set_range(end, rc, true);
                p.missing_blocks.set_range(end, rc, true);
                p.remote_contiguous = m.start;
                self.clear_local_range(core, id, end, rc - end);
            }
            if let Some(p) = self.peer_mut(id) {
                p.remote_contiguous = m.start;
            }
        }
        let Some(p) = self.peer_mut(id) else { return };
        if m.start == 0 && !m.drop {
            if m.length > p.remote_contiguous {
                p.remote_contiguous = m.length;
            }
            if p.remote_fork == fork {
                core.set_remote_contiguous_length(m.length);
            }
        } else if m.length == 1 {
            p.remote_bitfield.set(m.start, has);
            let local = core.has(m.start);
            let p = self.peer_mut(id).expect("peer");
            p.missing_blocks.set(m.start, has && !local);
        } else {
            let range_end = m.start + m.length;
            if let Some(rs) = p
                .remote_bitfield
                .find_first(!has, m.start)
                .filter(|&rs| rs < range_end)
            {
                p.remote_bitfield.set_range(rs, range_end, has);
                p.missing_blocks.set_range(rs, range_end, has);
                if has && m.start <= p.remote_contiguous && p.remote_contiguous < range_end {
                    p.remote_contiguous = range_end;
                }
                if has {
                    self.clear_local_range(core, id, rs, range_end - rs);
                }
            }
        }
        if let Some(p) = self.peer_mut(id)
            && has
            && m.start <= p.remote_contiguous
        {
            p.remote_contiguous = p.remote_contiguous_length();
        }
        if !m.drop {
            self.update_peer(core, id);
        }
    }

    // Reorgs

    fn add_reorg(&mut self, fork: u64) -> Option<usize> {
        for (i, f) in self.reorgs.iter().enumerate() {
            if f.fork > fork && f.batch.is_some() {
                return None;
            }
            if f.fork == fork {
                return Some(i);
            }
        }
        self.reorgs.push(ForkReq {
            fork,
            inflight: vec![],
            batch: None,
        });
        self.reorgs.sort_by_key(|f| f.fork);
        self.reorgs.iter().position(|f| f.fork == fork)
    }

    fn update_fork(&mut self, core: &Core, id: PeerId) {
        let Some(remote_fork) = self.peer(id).map(|p| p.remote_fork) else {
            return;
        };
        if self.applying_reorg || remote_fork <= core.fork() {
            return;
        }
        let Some(fi) = self.add_reorg(remote_fork) else {
            return;
        };
        if self.reorgs[fi].batch.is_none() && self.reorgs[fi].inflight.is_empty() {
            self.request_fork_proof(core, id, fi);
        }
    }

    async fn on_reorg_data(
        &mut self,
        core: &Core,
        _id: PeerId,
        rid: Option<ReqId>,
        data: &Data,
    ) -> Result<(), CoreError> {
        let new_batch = match data.upgrade {
            Some(_) => Some(core.verify_reorg(data)?),
            None => None,
        };
        let Some(fi) = self.add_reorg(data.fork) else {
            self.update_all(core);
            return Ok(());
        };
        if let Some(rid) = rid {
            remove_id(&mut self.reorgs[fi].inflight, rid);
        }
        if let Some(batch) = self.reorgs[fi].batch.as_mut() {
            core.reorg_update(batch, data)?;
        } else if let Some(b) = new_batch {
            self.reorgs[fi].batch = Some(b);
            let fork = self.reorgs[fi].fork;
            self.reorgs.retain(|f| f.fork >= fork);
        }
        let fi = self.reorgs.iter().position(|f| f.fork == data.fork);
        if let Some(fi) = fi.filter(|&fi| {
            self.reorgs[fi]
                .batch
                .as_ref()
                .is_some_and(Batch::reorg_finished)
        }) {
            self.ensure_upgrade(core);
            self.apply_reorg(core, fi).await;
        }
        self.update_all(core);
        Ok(())
    }

    async fn apply_reorg(&mut self, core: &Core, fi: usize) {
        let f = self.reorgs.remove(fi);
        self.reorgs.clear();
        self.applying_reorg = true;
        let res = match f.batch {
            Some(batch) => core.apply_reorg(batch).await,
            None => Ok(false),
        };
        self.applying_reorg = false;
        if res.is_err()
            && let Some(u) = self.upgrade.take()
        {
            for (_, w) in u.waiters {
                let _ = w.send(false);
            }
        }
        if self.upgrade.is_some() {
            self.resolve_upgrade_request(core, None);
        }
        for id in self.order.clone() {
            self.update_fork(core, id);
        }
        for r in &mut self.ranges {
            r.start = r.user_start;
            r.end = r.user_end;
        }
        self.update_all(core);
    }

    fn request_fork_proof(&mut self, core: &Core, id: PeerId, fi: usize) {
        let has_manifest = core.manifest().is_some();
        let Some(remote_length) = self.peer(id).map(|p| p.remote_length).filter(|&l| l > 0) else {
            return;
        };
        let Some(mut req) = self.make_request(core, id, false, 0, 0) else {
            return;
        };
        req.upgrade = Some(RequestUpgrade {
            start: 0,
            length: remote_length,
        });
        req.manifest = !has_manifest;
        let rid = self.send_request(core, req);
        if let Some(rid) = rid {
            self.reorgs[fi].inflight.push(rid);
        }
    }

    fn request_fork_range(&mut self, core: &Core, id: PeerId, fi: usize) -> bool {
        let Some(want) = self.reorgs[fi]
            .batch
            .as_ref()
            .and_then(|b| b.reorg.as_ref())
            .and_then(|r| r.want.clone())
        else {
            return false;
        };
        let Some(p) = self.peer(id) else { return false };
        if self.reorgs[fi].fork != p.remote_fork {
            return false;
        }
        let end = want.end.min(p.remote_length);
        if end < want.start {
            return false;
        }
        let len = end - want.start;
        if len == 0 {
            return false;
        }
        let off = want.start + rand::thread_rng().gen_range(0..len);
        for i in 0..len {
            let mut index = off + i;
            if index >= end {
                index -= len;
            }
            if !self.peer(id).is_some_and(|p| p.remote_has_block(index)) {
                continue;
            }
            let Some(mut req) = self.make_request(core, id, false, 0, 0) else {
                return false;
            };
            req.hash = Some(RequestBlock {
                index: 2 * index,
                nodes: want.nodes,
            });
            if let Some(rid) = self.send_request(core, req) {
                self.reorgs[fi].inflight.push(rid);
            }
            return true;
        }
        let fork = self.reorgs[fi].fork;
        self.maybe_want_any_range(id, want.start, len, Handle::Fork(fork));
        false
    }

    // Request construction

    fn make_request(
        &self,
        core: &Core,
        id: PeerId,
        needs_upgrade: bool,
        priority: u64,
        min_length: u64,
    ) -> Option<Req> {
        let p = self.peer(id)?;
        let mut needs_upgrade = needs_upgrade;
        if needs_upgrade && !self.should_upgrade(core, p) {
            return None;
        }
        if p.remote_length < min_length {
            return None;
        }
        if !needs_upgrade && self.auto_upgrade(core, p) {
            needs_upgrade = true;
        }
        let (length, has_manifest) = {
            let st = core.state();
            (st.tree.length, st.header.manifest.is_some())
        };
        Some(Req {
            peer: id,
            rt: p.roundtrip_queue.as_ref().map_or(0, |q| q.tick),
            fork: p.remote_fork,
            block: None,
            hash: None,
            seek: None,
            upgrade: needs_upgrade.then(|| RequestUpgrade {
                start: length,
                length: p.remote_length - length,
            }),
            manifest: !has_manifest && p.remote_has_manifest,
            priority,
            timestamp: Instant::now(),
            cancelled: false,
        })
    }

    /// `peer._send`: registers and sends (or resolves a hash locally).
    fn send_request(&mut self, core: &Core, mut req: Req) -> Option<ReqId> {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        if req.fork == fork {
            if let Some(b) = req.block.as_mut() {
                b.nodes = merkle::missing_nodes(core.storage(), 2 * b.index, length).unwrap_or(0);
            }
            if let Some(h) = req.hash.as_mut().filter(|h| h.nodes == 0) {
                h.nodes = merkle::missing_nodes(core.storage(), h.index, length).unwrap_or(0);
                if h.nodes == 0 && h.index & 1 == 0 {
                    let index = h.index / 2;
                    self.resolve_block_request(core, false, index, None, None);
                    return None;
                }
            }
        }
        let peer = req.peer;
        let upgrade = req.upgrade.is_some() && req.fork == fork;
        let rid = self.inflight.add(req);
        if upgrade {
            self.ensure_upgrade(core).inflight.push(rid);
        }
        let wire = self.inflight.get(rid).expect("added").wire(rid);
        if let Some(p) = self.peer_mut(peer) {
            p.inflight += 1;
            p.send(MSG_REQUEST, &wire);
        }
        Some(rid)
    }

    fn can_request(&self, core: &Core, p: &Peer, index: u64) -> bool {
        let st = core.state();
        p.remote_length >= st.tree.length
            || (index < p.last_upgradable_length && p.last_upgradable_fork == st.tree.fork)
            || p.can_upgrade
    }

    fn send_block_request(&mut self, core: &Core, mut req: Req, index: u64) {
        req.block = Some(RequestBlock { index, nodes: 0 });
        self.mark_inflight(index);
        if let Some(rid) = self.send_request(core, req) {
            if let Some(b) = self.blocks.get_mut(&index) {
                b.inflight.push(rid);
            }
            self.hotswap_add(index);
        }
    }

    fn request_block(&mut self, core: &Core, id: PeerId, index: u64) -> bool {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        let Some(p) = self.peer(id) else { return false };
        let Some(b) = self.blocks.get(&index) else {
            return false;
        };
        let (priority, force) = (b.priority, b.force);
        if !p.remote_has_block(index) || fork != p.remote_fork {
            if !core.has(index) {
                self.maybe_want(id, index, Handle::Block(index));
            }
            return false;
        }
        if !force && !self.can_request(core, p, index) {
            return false;
        }
        let Some(req) = self.make_request(core, id, index >= length, priority, index + 1) else {
            return false;
        };
        self.send_block_request(core, req, index);
        true
    }

    fn maybe_want(&mut self, id: PeerId, index: u64, handle: Handle) {
        let Some(p) = self.peer_mut(id) else { return };
        if index < p.remote_contiguous_length() {
            return;
        }
        let Some(WantUpdate { want, unwant }) = p.wants.add(index, handle) else {
            return;
        };
        let batch = want.is_some() && unwant.is_some();
        if batch {
            p.mux.cork();
        }
        if let Some(u) = unwant {
            p.send(MSG_UNWANT, &u);
        }
        if let Some(w) = want {
            p.send(MSG_WANT, &w);
        }
        if batch {
            p.mux.uncork();
        }
    }

    fn maybe_want_any_range(&mut self, id: PeerId, start: u64, length: u64, handle: Handle) {
        let Some(p) = self.peer_mut(id) else { return };
        for (s, l) in p.wants.any_ranges_of(handle) {
            if (s != start || l != length)
                && let Some(u) = p.wants.remove_any_range(s, l, handle)
            {
                p.send(MSG_UNWANT, &u);
            }
        }
        if start + length <= p.remote_contiguous_length() {
            return;
        }
        if let Some(w) = p.wants.add_any_range(start, length, handle) {
            p.send(MSG_WANT, &w);
        }
    }

    fn request_upgrade(&mut self, core: &Core, id: PeerId) -> bool {
        let Some(req) = self.make_request(core, id, true, 0, 0) else {
            return false;
        };
        // Fetch the newest block along with the upgrade when someone waits on it.
        let last = self.peer(id).map(|p| p.remote_length.saturating_sub(1));
        if let Some(index) = last.filter(|&i| i >= core.length() && self.blocks.contains_key(&i))
            && self.peer(id).is_some_and(|p| p.remote_has_block(index))
        {
            self.send_block_request(core, req, index);
            return true;
        }
        self.send_request(core, req);
        true
    }

    fn request_seek(&mut self, core: &Core, id: PeerId, si: usize) -> bool {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        let Some(p) = self.peer(id) else { return false };
        if fork != p.remote_fork {
            return false;
        }
        let seeks = p.remote_supports_seeks;
        let s = &self.seeks[si];
        let seek = seeks.then_some(RequestSeek {
            bytes: s.bytes,
            padding: s.padding,
        });
        if s.start >= length {
            let Some(mut req) = self.make_request(core, id, true, 0, 0) else {
                return false;
            };
            req.seek = seek;
            if let Some(rid) = self.send_request(core, req) {
                self.seeks[si].inflight.push(rid);
            }
            return true;
        }
        let (start, end, sid) = (s.start, s.end, s.id);
        let len = end - start;
        if len == 0 {
            return false;
        }
        let off = start + rand::thread_rng().gen_range(0..len);
        for i in 0..len {
            let mut index = off + i;
            if index >= end {
                index -= len;
            }
            let Some(p) = self.peer(id) else { return false };
            if !p.remote_has_block(index) || core.has(index) || !self.can_request(core, p, index) {
                continue;
            }
            if self
                .blocks
                .get(&index)
                .is_some_and(|b| !b.inflight.is_empty())
            {
                continue;
            }
            if self
                .hashes
                .get(&index)
                .is_some_and(|h| !h.inflight.is_empty())
            {
                continue;
            }
            let Some(mut req) = self.make_request(core, id, false, PRIORITY_NORMAL, index + 1)
            else {
                continue;
            };
            req.hash = Some(RequestBlock {
                index: 2 * index,
                nodes: flat_tree::depth(start + end - 1),
            });
            req.seek = seek;
            self.hashes.entry(index).or_insert_with(|| BlockReq {
                priority: PRIORITY_NORMAL,
                inflight: vec![],
                queued: false,
                hotswap: None,
                force: false,
                waiters: vec![],
            });
            if let Some(rid) = self.send_request(core, req) {
                self.seeks[si].inflight.push(rid);
                if let Some(h) = self.hashes.get_mut(&index) {
                    h.inflight.push(rid);
                }
            }
            return true;
        }
        self.maybe_want_any_range(id, start, len, Handle::Seek(sid));
        false
    }

    fn request_range_block(&mut self, core: &Core, id: PeerId, index: u64, length: u64) -> bool {
        let Some(p) = self.peer(id) else { return false };
        if core.has(index) || !self.can_request(core, p, index) {
            return false;
        }
        let b = self.blocks.entry(index).or_insert_with(|| BlockReq {
            priority: PRIORITY_NORMAL,
            inflight: vec![],
            queued: false,
            hotswap: None,
            force: false,
            waiters: vec![],
        });
        if !b.inflight.is_empty() {
            if let Some(p) = self.peer_mut(id) {
                p.missing_blocks.set(index, false);
            }
            return false;
        }
        let priority = b.priority;
        let Some(req) = self.make_request(core, id, index >= length, priority, index + 1) else {
            if self
                .blocks
                .get(&index)
                .is_some_and(|b| b.waiters.is_empty() && b.inflight.is_empty())
            {
                self.blocks.remove(&index);
            }
            return false;
        };
        self.send_block_request(core, req, index);
        if let Some(b) = self.blocks.get_mut(&index) {
            b.queued = false;
        }
        true
    }

    fn find_next(&self, core: &Core, id: PeerId, mut i: u64) -> Option<u64> {
        let p = self.peer(id)?;
        if i < p.remote_contiguous {
            let st = core.state();
            loop {
                let j = st.bitfield.find_first(false, i)?;
                if j >= p.remote_contiguous {
                    break;
                }
                if self.blocks.get(&j).is_some_and(|b| !b.inflight.is_empty()) {
                    i = j + 1;
                    continue;
                }
                return Some(j);
            }
            i = p.remote_contiguous;
        }
        p.missing_blocks.find_first(true, i)
    }

    fn request_range_batch(
        &mut self,
        core: &Core,
        id: PeerId,
        mut start: u64,
        end: u64,
        length: u64,
    ) -> bool {
        let mut tries = self.peer(id).map_or(0, |p| p.inflight) as i64;
        while let Some(s) = self.find_next(core, id, start).filter(|&s| s < end) {
            if self.request_range_block(core, id, s, length) {
                return true;
            }
            start = s + 1;
            if tries <= 0 {
                break;
            }
            tries -= 1;
        }
        false
    }

    fn valid_end(&self, core: &Core, p: &Peer, max_end: Option<u64>) -> u64 {
        let st = core.state();
        let max_local = if p.can_upgrade || p.remote_length >= st.tree.length {
            st.tree.length
        } else if st.tree.fork == p.last_upgradable_fork {
            p.last_upgradable_length.min(st.tree.length)
        } else {
            0
        };
        max_local.min(max_end.unwrap_or(p.remote_length).min(p.remote_length))
    }

    fn populate_range_batches(&mut self, core: &Core, ri: usize) {
        let st = core.state();
        let r = &mut self.ranges[ri];
        let mut dropped = vec![];
        r.batches.retain(|&b| {
            let min_start = b * WANT_BATCH;
            let max_end = min_start + WANT_BATCH;
            let start = r.start.max(min_start);
            let end = r.end.unwrap_or(max_end).min(max_end);
            let keep = start < end && st.bitfield.has_unset(start, end - start);
            if !keep {
                dropped.push(b);
            }
            keep
        });
        let end = r.end.unwrap_or(st.tree.length);
        if end > r.start {
            if r.batches.len() < 3
                && let Some(next) = st
                    .bitfield
                    .find_last(false, end - 1)
                    .filter(|&n| n >= r.start)
            {
                let b = next / WANT_BATCH;
                if !r.batches.contains(&b) {
                    r.batches.push(b);
                }
            }
            while r.batches.len() < 3 {
                let len = end - r.start;
                let off = r.start
                    + if r.linear {
                        0
                    } else {
                        rand::thread_rng().gen_range(0..len)
                    };
                if !add_range_batch(&st.bitfield, r, off, end)
                    && !add_range_batch(&st.bitfield, r, r.start, end)
                {
                    break;
                }
            }
        }
        let rid = r.id;
        drop(st);
        for b in dropped {
            self.drop_handle_wants(core, Handle::RangeBatch(rid, b));
        }
    }

    fn request_range(&mut self, core: &Core, id: PeerId, ri: usize) -> bool {
        let (fork, length) = {
            let st = core.state();
            (st.tree.fork, st.tree.length)
        };
        self.populate_range_batches(core, ri);
        let Some(p) = self.peer(id) else { return false };
        let end = self.valid_end(core, p, self.ranges[ri].end);
        let r = &self.ranges[ri];
        if end <= r.start || fork != p.remote_fork {
            return false;
        }
        let (rstart, linear, rid) = (r.start, r.linear, r.id);
        for b in r.batches.clone() {
            let batch_start = (b * WANT_BATCH).max(rstart);
            let batch_end = ((b + 1) * WANT_BATCH).min(end);
            if batch_end <= batch_start {
                self.maybe_want(id, batch_start, Handle::RangeBatch(rid, b));
                continue;
            }
            let len = batch_end - batch_start;
            let off = batch_start
                + if linear {
                    0
                } else {
                    rand::thread_rng().gen_range(0..len)
                };
            if self.request_range_batch(core, id, off, end, length)
                || self.request_range_batch(core, id, batch_start, off, length)
            {
                return true;
            }
            self.maybe_want(id, batch_start, Handle::RangeBatch(rid, b));
        }
        false
    }

    // Scheduling

    fn update_ranges(&mut self, core: &Core) {
        let mut i = 0;
        while i < self.ranges.len() {
            clamp_range(core, &mut self.ranges[i]);
            let r = &self.ranges[i];
            if r.end.is_some_and(|e| r.start >= e) {
                let r = self.ranges.swap_remove(i);
                self.drop_range_wants(core, &r);
                for (_, w) in r.waiters {
                    let _ = w.send(true);
                }
            } else {
                i += 1;
            }
        }
    }

    fn update_seeks(&mut self, core: &Core) {
        let mut i = 0;
        while i < self.seeks.len() {
            let s = &self.seeks[i];
            let res = {
                let st = core.state();
                merkle::seek(&st.tree, core.storage(), s.bytes, s.padding)
            };
            match res {
                Ok(Some(merkle::Seek::Need { start, end })) => {
                    self.seeks[i].start = start;
                    self.seeks[i].end = end;
                    i += 1;
                }
                Ok(None) if core.length() == 0 => i += 1,
                other => {
                    let s = self.seeks.swap_remove(i);
                    self.drop_handle_wants(core, Handle::Seek(s.id));
                    let found = matches!(other, Ok(Some(merkle::Seek::Found(..))));
                    for (_, w) in s.waiters {
                        let _ = w.send(found);
                    }
                }
            }
        }
    }

    fn update_non_primary(&mut self, core: &Core) {
        self.update_ranges(core);
        self.update_seeks(core);
        self.update_all(core);
    }

    fn update_hotswap(&mut self, core: &Core, id: PeerId) {
        let frozen = Self::frozen(core);
        let Some(p) = self.peer(id) else { return };
        let max = p.max_hotswap_inflight();
        if !p.is_active(frozen) || p.inflight >= max {
            return;
        }
        // Take over only blocks overdue for this peer (the hotswap fix); an idle peer takes any.
        let overdue = if p.inflight == 0 {
            None
        } else {
            Instant::now().checked_sub(Duration::from_secs_f64(
                HOTSWAP_ROUNDTRIPS * p.block_roundtrip / 1000.0,
            ))
        };
        let idle = p.inflight == 0;
        let mut rng = rand::thread_rng();
        for q in 0..3 {
            let mut ticks = (3 - q) * 16;
            let mut candidates = self.hotswaps[q].clone();
            candidates.shuffle(&mut rng);
            for index in candidates {
                let Some(b) = self.blocks.get(&index) else {
                    continue;
                };
                if b.inflight
                    .iter()
                    .any(|r| self.inflight.get(*r).is_some_and(|r| r.peer == id))
                {
                    continue;
                }
                let last = b
                    .inflight
                    .last()
                    .and_then(|r| self.inflight.get(*r))
                    .map(|r| r.timestamp);
                if !idle {
                    match (last, overdue) {
                        (Some(ts), Some(cut)) if ts > cut => continue,
                        (Some(_), None) => continue,
                        _ => {}
                    }
                }
                if self.request_block(core, id, index)
                    && self.peer(id).is_some_and(|p| p.inflight >= max)
                {
                    return;
                }
                ticks -= 1;
                if ticks == 0 {
                    break;
                }
            }
        }
    }

    fn update_peer_primary(&mut self, core: &Core, id: PeerId) -> bool {
        let frozen = Self::frozen(core);
        let Some(p) = self.peer(id) else { return false };
        if !p.is_active(frozen) || p.inflight >= p.max_inflight() || !p.remote_uploading {
            return false;
        }
        if core.manifest().is_none()
            && self.manifest_peer.is_none()
            && p.remote_length == 0
            && p.remote_has_manifest
        {
            self.manifest_peer = Some(id);
            if let Some(req) = self.make_request(core, id, false, 0, 0) {
                self.send_request(core, req);
            }
        }
        for si in 0..self.seeks.len() {
            if self.seeks[si].inflight.is_empty() && self.request_seek(core, id, si) {
                return true;
            }
        }
        let mut queued = self.queued.clone();
        queued.shuffle(&mut rand::thread_rng());
        for index in queued {
            if !self.blocks.get(&index).is_some_and(|b| b.queued) {
                self.queued.retain(|&i| i != index);
                continue;
            }
            if self.request_block(core, id, index) {
                if let Some(b) = self.blocks.get_mut(&index) {
                    b.queued = false;
                }
                self.queued.retain(|&i| i != index);
                return true;
            }
        }
        false
    }

    fn update_peer_non_primary(&mut self, core: &Core, id: PeerId) -> bool {
        let frozen = Self::frozen(core);
        let Some(p) = self.peer(id) else { return false };
        if !p.is_active(frozen) || p.inflight >= p.max_inflight() || !p.remote_uploading {
            return false;
        }
        let mut order: Vec<usize> = (0..self.ranges.len()).collect();
        order.shuffle(&mut rand::thread_rng());
        for ri in order.into_iter().take(MAX_RANGES) {
            if ri < self.ranges.len() && self.request_range(core, id, ri) {
                return true;
            }
        }
        for fi in (0..self.reorgs.len()).rev() {
            if self.reorgs[fi].batch.is_some()
                && self.reorgs[fi].inflight.is_empty()
                && self.request_fork_range(core, id, fi)
            {
                return true;
            }
        }
        if self.upgrade.as_ref().is_some_and(|u| u.inflight.is_empty())
            && self.request_upgrade(core, id)
        {
            return true;
        }
        false
    }

    fn update_peer(&mut self, core: &Core, id: PeerId) {
        if self.applying_reorg {
            return;
        }
        while self.update_peer_primary(core, id) {}
        while self.update_peer_non_primary(core, id) {}
        if self.order.len() > 1 && !self.blocks.is_empty() {
            self.update_hotswap(core, id);
        }
        self.check_upgrade_if_available(core);
    }

    fn update_all(&mut self, core: &Core) {
        if self.applying_reorg {
            return;
        }
        let mut peers = self.order.clone();
        peers.shuffle(&mut rand::thread_rng());
        // JS requeues a peer that took a request; looping until none do is equivalent.
        loop {
            let mut any = false;
            for &id in &peers {
                any |= self.update_peer_primary(core, id);
            }
            if !any {
                break;
            }
        }
        if !(self.upgrade.as_ref().is_some_and(|u| u.inflight.is_empty())
            || !self.ranges.is_empty()
            || !self.reorgs.is_empty())
        {
            self.check_upgrade_if_available(core);
            return;
        }
        loop {
            let mut any = false;
            for &id in &peers {
                any |= self.update_peer_non_primary(core, id);
            }
            if !any {
                break;
            }
        }
        self.check_upgrade_if_available(core);
    }
}

fn add_range_batch(
    bitfield: &crate::bitfield::Bitfield,
    r: &mut RangeReq,
    mut offset: u64,
    end: u64,
) -> bool {
    while offset < end {
        let Some(next) = bitfield.find_first(false, offset).filter(|&n| n < end) else {
            return false;
        };
        let b = next / WANT_BATCH;
        if !r.batches.contains(&b) {
            r.batches.push(b);
            return true;
        }
        offset = (b + 1) * WANT_BATCH;
    }
    false
}

fn clamp_range(core: &Core, r: &mut RangeReq) {
    let st = core.state();
    let start = st.bitfield.find_first(false, r.start);
    match r.end {
        None => r.start = start.unwrap_or(st.tree.length),
        Some(end) => match start {
            None => r.start = end,
            Some(s) if s >= end => r.start = end,
            Some(s) => {
                r.start = s;
                let last = st.bitfield.find_last(false, end - 1);
                r.end = Some(match last {
                    Some(l) if s < l + 1 => l + 1,
                    _ => s,
                });
            }
        },
    }
}

/// Reads one channel and feeds decoded messages to the actor.
async fn forward(mut channel: protomux::Channel, peer: PeerId, tx: mpsc::UnboundedSender<Cmd>) {
    while let Some(ev) = channel.recv().await {
        let cmd = match ev {
            Event::Opened { handshake } => Cmd::Opened { peer, handshake },
            Event::Message(m) => match decode_wire(m.kind, m.data.clone()) {
                Ok(Some(msg)) => Cmd::Wire { peer, msg },
                Ok(None) => continue,
                Err(_) => {
                    channel.mux().destroy();
                    break;
                }
            },
            Event::Closed { remote } => Cmd::Closed { peer, remote },
        };
        if tx.send(cmd).is_err() {
            break;
        }
    }
}

/// `_matchingRequest`: whether `data` answers what `req` asked.
fn matching_request(req: &Req, data: &Data) -> bool {
    if data
        .block
        .as_ref()
        .is_some_and(|b| req.block.is_none_or(|r| r.index != b.index))
    {
        return false;
    }
    if data
        .hash
        .as_ref()
        .is_some_and(|h| req.hash.is_none_or(|r| r.index != h.index))
    {
        return false;
    }
    if data
        .seek
        .as_ref()
        .is_some_and(|s| req.seek.is_none_or(|r| r.bytes != s.bytes))
    {
        return false;
    }
    if data.upgrade.is_some() && req.upgrade.is_none() {
        return false;
    }
    req.fork == data.fork
}

fn is_plain_block(d: &Data, fork: u64) -> bool {
    d.request != 0
        && d.block.is_some()
        && d.upgrade.is_none()
        && d.manifest.is_none()
        && d.fork == fork
}
