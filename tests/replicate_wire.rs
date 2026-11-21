//! Replication observed on the wire: a scripted peer speaks the hypercore protocol over a
//! raw protomux channel to a real core and checks what the core sends, and when.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use compact_encoding::hypercore::{
    Cancel, Data, Handshake, NoData, Range, Request, RequestBlock, Sync, Want,
};
use compact_encoding::{Bytes, Codec, decode, encode};
use hypercore::crypto::{KeyPair, replicate_capability};
use hypercore::replicator::PROTOCOL;
use hypercore::storage::Store;
use hypercore::{Core, CoreOptions, GetOptions};
use protomux::{Channel, ChannelOptions, Event, FrameRead, Mux, StreamInfo, memory};
use tokio::sync::mpsc;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);
const HANDSHAKE_HASH: [u8; 64] = [7; 64];

const SYNC: u64 = 0;
const REQUEST: u64 = 1;
const CANCEL: u64 = 2;
const DATA: u64 = 3;
const NO_DATA: u64 = 4;
const WANT: u64 = 5;
const UNWANT: u64 = 6;
const RANGE: u64 = 8;
const EXTENSION: u64 = 9;

fn writer(store: &Store, seed: u8) -> Core {
    Core::open(
        store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[seed; 32])),
            ..Default::default()
        },
    )
    .unwrap()
}

fn reader(store: &Store, key: &[u8; 32]) -> Core {
    Core::open(
        store,
        CoreOptions {
            key: Some(*key),
            ..Default::default()
        },
    )
    .unwrap()
}

fn info(is_initiator: bool) -> StreamInfo {
    StreamInfo {
        is_initiator,
        handshake_hash: Some(HANDSHAKE_HASH),
        remote_public_key: None,
    }
}

/// A transport end that counts the frames read through it.
struct CountFrames<R> {
    inner: R,
    frames: Arc<AtomicUsize>,
}

impl<R: FrameRead> FrameRead for CountFrames<R> {
    async fn read(&mut self) -> std::io::Result<Option<Bytes>> {
        let frame = self.inner.read().await;
        if matches!(frame, Ok(Some(_))) {
            self.frames.fetch_add(1, Ordering::SeqCst);
        }
        frame
    }
}

/// The scripted end of a connection to a core.
struct Remote {
    /// The core's mux.
    core_mux: Mux,
    mux: Mux,
    ch: Channel,
    /// Frames the scripted end has read.
    frames: Arc<AtomicUsize>,
}

/// Connects a scripted peer to `core` over a link that holds `capacity` frames each way.
async fn connect(core: &Core, capacity: usize) -> Remote {
    let ((ar, aw), (br, bw)) = memory::duplex(capacity);
    let core_mux = Mux::new(ar, aw, info(false));
    let frames = Arc::new(AtomicUsize::new(0));
    let reader = CountFrames {
        inner: br,
        frames: frames.clone(),
    };
    let mux = Mux::new(reader, bw, info(true));
    core.replicate(&core_mux);
    let ch = open(&mux, core).await;
    Remote {
        core_mux,
        mux,
        ch,
        frames,
    }
}

/// Opens the hypercore channel for `core` from the initiator side of `mux`.
async fn open(mux: &Mux, core: &Core) -> Channel {
    let handshake = encode(&Handshake {
        seeks: true,
        capability: replicate_capability(true, core.key(), &HANDSHAKE_HASH),
    });
    let mut ch = mux
        .open_channel(ChannelOptions {
            id: Some(core.discovery_key()),
            handshake: &handshake,
            ..ChannelOptions::new(PROTOCOL)
        })
        .expect("a channel");
    timeout(T, ch.opened())
        .await
        .expect("the core opens its side")
        .expect("open");
    ch
}

/// Two cores' muxes over one in-memory link.
fn link() -> (Mux, Mux) {
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    (Mux::new(ar, aw, info(true)), Mux::new(br, bw, info(false)))
}

fn sync(length: u64, can_upgrade: bool, uploading: bool, downloading: bool) -> Sync {
    Sync {
        fork: 0,
        length,
        remote_length: length,
        can_upgrade,
        uploading,
        downloading,
        has_manifest: false,
        allow_push: false,
    }
}

fn block_request(id: u64, index: u64, priority: u64) -> Request {
    Request {
        id,
        fork: 0,
        block: Some(RequestBlock { index, nodes: 0 }),
        priority,
        ..Default::default()
    }
}

/// A request for a block no core in these tests holds: answered `noData` at once.
fn marker_request(id: u64) -> Request {
    block_request(id, 1 << 40, 0)
}

/// The request id a `data` or `noData` message answers.
fn answer_id(kind: u64, data: &Bytes) -> Option<u64> {
    match kind {
        DATA => Some(decode::<Data>(data.clone()).unwrap().request),
        NO_DATA => Some(decode::<NoData>(data.clone()).unwrap().request),
        _ => None,
    }
}

impl Remote {
    fn send<M: Codec>(&self, kind: u64, msg: &M) {
        assert!(self.ch.send(kind, msg));
    }

    /// The next message; `None` once the core closed the channel.
    async fn next(&mut self) -> Option<(u64, Bytes)> {
        loop {
            match timeout(T, self.ch.recv()).await.expect("an event") {
                Some(Event::Message(m)) => return Some((m.kind, m.data.clone())),
                Some(Event::Opened { .. }) => {}
                Some(Event::Closed { .. }) | None => return None,
            }
        }
    }

    /// The next message of `kind` that `pred` accepts.
    async fn expect<M: Codec>(&mut self, kind: u64, pred: impl Fn(&M) -> bool) -> M {
        loop {
            let (k, data) = self.next().await.expect("the channel stays open");
            if k == kind {
                let msg: M = decode(data).unwrap();
                if pred(&msg) {
                    return msg;
                }
            }
        }
    }

    /// Sends a marker request and returns everything the core sent before its answer, or
    /// `None` if the core closed the channel first. The core handles messages in order, so
    /// the answer proves it has handled all that this peer sent before.
    async fn marker(&mut self, id: u64) -> Option<Vec<(u64, Bytes)>> {
        self.send(REQUEST, &marker_request(id));
        let mut seen = vec![];
        loop {
            let (kind, data) = self.next().await?;
            if kind == NO_DATA && answer_id(kind, &data) == Some(id) {
                return Some(seen);
            }
            seen.push((kind, data));
        }
    }
}

async fn eventually<F: Future<Output = bool>>(mut check: impl FnMut() -> F) {
    timeout(T, async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the condition holds within the timeout");
}

/// A reader of `w` that has verified `w`'s length and holds no block; no peer is attached.
async fn synced_reader(store: &Store, w: &Core) -> Core {
    let r = reader(store, w.key());
    // Not a session: closing a core's last session closes the core.
    r.set_active(true);
    let (a, b) = link();
    w.replicate(&a);
    r.replicate(&b);
    assert!(timeout(T, r.update(None)).await.unwrap().unwrap());
    r.set_active(false);
    assert_eq!(r.length(), w.length());
    a.destroy();
    b.destroy();
    eventually(|| async { r.peer_count() == 0 }).await;
    r
}

/// Finding 11, `replicator.js` `_requestBlock`: `force` does not skip the upgrade checks,
/// so a peer that is behind us and cannot be upgraded is not asked for a block it claims.
#[tokio::test]
async fn force_does_not_bypass_the_upgrade_checks() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let stores: Vec<_> = dirs
        .iter()
        .map(|d| Store::open(d.path()).unwrap())
        .collect();
    let w = writer(&stores[0], 50);
    w.append(&[b"0".as_slice(), b"1", b"2", b"3", b"4"])
        .await
        .unwrap();
    // The reader holds the roots of length 5 only, so a peer at length 3 cannot be upgraded:
    // block 2 it may hold cannot be proven against a length we accept.
    let r = synced_reader(&stores[1], &w).await;
    let _session = r.session(true);

    let mut h = connect(&r, 64).await;
    h.send(
        SYNC,
        &Sync {
            remote_length: 5,
            ..sync(3, false, true, true)
        },
    );
    h.send(
        RANGE,
        &Range {
            drop: false,
            start: 2,
            length: 1,
        },
    );
    h.marker(1).await.expect("open");

    let get = tokio::spawn({
        let r = r.clone();
        async move {
            let force = GetOptions {
                force: true,
                ..Default::default()
            };
            r.get(2, force).await
        }
    });
    eventually(|| async { r.pending_requests().await == 1 }).await;
    assert_eq!(
        r.inflight_requests().await,
        0,
        "a forced get asks no peer that is behind and cannot be upgraded"
    );

    // Once the peer reaches our length, the same get asks it.
    h.send(SYNC, &sync(5, true, true, true));
    h.expect(REQUEST, |m: &Request| m.block.is_some_and(|b| b.index == 2))
        .await;
    get.abort();
}

/// Forwards every message between `to_r` (the scripted end facing a reader) and `to_w` (the
/// end facing a writer), and reports each one as `(from_reader, kind, data)`.
fn relay(mut to_r: Channel, mut to_w: Channel) -> mpsc::UnboundedReceiver<(bool, u64, Bytes)> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (from_r, event) = tokio::select! {
                e = to_r.recv() => (true, e),
                e = to_w.recv() => (false, e),
            };
            let m = match event {
                Some(Event::Message(m)) => m,
                Some(Event::Opened { .. }) => continue,
                Some(Event::Closed { .. }) | None => break,
            };
            let to = if from_r { &to_w } else { &to_r };
            to.send_raw(m.kind, &m.data);
            if tx.send((from_r, m.kind, m.data.clone())).is_err() {
                break;
            }
        }
    });
    rx
}

/// Finding 9, `replicator.js` `_onrequestroundtrip` / `WRITE_FAILED`: a block that verifies
/// but cannot be stored is a local fault. The peer is paused; it is not probed for a
/// conflict with an upgrade request (`request: 0`) as a peer that sent bad data is.
#[tokio::test]
async fn a_storage_write_failure_does_not_probe_the_peer_for_a_conflict() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let wstore = Store::open(dirs[0].path()).unwrap();
    let w = writer(&wstore, 51);
    w.append(&[b"0".as_slice(), b"1", b"2", b"3"])
        .await
        .unwrap();
    {
        let store = Store::open(dirs[1].path()).unwrap();
        let r = synced_reader(&store, &w).await;
        r.close();
        store.close();
    }
    // Every write to a read-only store fails.
    let store = Store::open_read_only(dirs[1].path()).unwrap();
    let r = reader(&store, w.key());
    assert_eq!(r.length(), 4);
    let _session = r.session(true);

    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let (r_mux, r_remote) = (Mux::new(ar, aw, info(false)), Mux::new(br, bw, info(true)));
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let (w_mux, w_remote) = (Mux::new(ar, aw, info(false)), Mux::new(br, bw, info(true)));
    r.replicate(&r_mux);
    w.replicate(&w_mux);
    let to_r = open(&r_remote, &r).await;
    let to_w = open(&w_remote, &w).await;
    let inject = to_r.sender();
    let mut seen = relay(to_r, to_w);

    let get = tokio::spawn({
        let r = r.clone();
        async move { r.get(0, GetOptions::default()).await }
    });
    let mut next = async || timeout(T, seen.recv()).await.unwrap().expect("relay");
    loop {
        let (from_r, kind, data) = next().await;
        if !from_r && kind == DATA && decode::<Data>(data).unwrap().block.is_some() {
            break;
        }
    }
    // Sent after the block on the same channel, so its answer follows the reader's reaction.
    assert!(inject.send(REQUEST, &marker_request(77)));
    let mut probes = 0;
    loop {
        let (from_r, kind, data) = next().await;
        if !from_r {
            continue;
        }
        if kind == REQUEST && decode::<Request>(data.clone()).unwrap().id == 0 {
            probes += 1;
        }
        if answer_id(kind, &data) == Some(77) {
            break;
        }
    }
    assert_eq!(probes, 0, "no conflict probe after a local write failure");
    assert!(!r.has(0));
    assert!(!get.is_finished());
    get.abort();
}

/// Finding 12 and the second item of 20, `replicator.js` `setDownloading`: when the last
/// activity ends, the core keeps its channels and its `want`s for the not-downloading linger
/// (20 to 40 s); activity within the linger cancels the close; after it, an idle channel
/// closes.
#[tokio::test]
async fn an_inactive_core_keeps_channels_and_wants_for_the_linger() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let stores: Vec<_> = dirs
        .iter()
        .map(|d| Store::open(d.path()).unwrap())
        .collect();
    let w = writer(&stores[0], 52);
    w.append(&[b"0".as_slice(), b"1", b"2"]).await.unwrap();
    let r = synced_reader(&stores[1], &w).await;
    r.set_active(true);

    // A peer that is not downloading and holds no block: idle once we stop downloading.
    let mut h = connect(&r, 64).await;
    h.send(SYNC, &sync(3, true, true, false));
    let get = tokio::spawn({
        let r = r.clone();
        async move { r.get(1, GetOptions::default()).await }
    });
    h.expect(WANT, |_: &Want| true).await;

    r.set_active(false);
    let seen = h
        .marker(1)
        .await
        .expect("the channel stays open when activity ends");
    assert!(
        seen.iter().all(|(kind, _)| *kind != UNWANT),
        "wants are kept"
    );

    let advance = async |secs| {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(secs)).await;
        tokio::time::resume();
    };
    advance(10).await;
    r.set_active(true);
    h.marker(2).await.expect("open");
    // The linger started before the reactivation runs out here; it must not close.
    advance(60).await;
    h.marker(3)
        .await
        .expect("activity within the linger cancels the close");

    r.set_active(false);
    h.marker(4).await.expect("open");
    advance(41).await;
    while h.next().await.is_some() {}
    get.abort();
}

/// The third item of finding 20: extensions are not ported, so an extension message, even a
/// malformed one, is skipped like an unknown message kind instead of ending the connection.
#[tokio::test]
async fn an_extension_message_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let w = writer(&store, 53);
    w.append(&[b"0".as_slice()]).await.unwrap();
    let mut h = connect(&w, 64).await;
    // A name of 5 bytes with no bytes following.
    assert!(h.ch.send_raw(EXTENSION, &[5]));
    h.marker(1).await.expect("the connection survives");
}

/// The first item of finding 20, `core.js` `_onappend` / `_ontruncate`: the replicator corks
/// every peer's mux around the notifications of an append or a truncate, so each reaches a
/// peer as one frame.
#[tokio::test]
async fn an_append_and_a_truncate_reach_a_peer_in_one_frame_each() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let w = writer(&store, 54);
    w.append(&[b"0".as_slice()]).await.unwrap();
    let mut h = connect(&w, 64).await;
    h.send(SYNC, &sync(1, true, false, true));
    h.marker(1).await.expect("open");

    // Messages up to the `sync` that announces `length`, and the frames they took.
    async fn until_sync(h: &mut Remote, length: u64) -> (Vec<u64>, usize) {
        let before = h.frames.load(Ordering::SeqCst);
        let mut kinds = vec![];
        loop {
            let (kind, data) = h.next().await.expect("open");
            kinds.push(kind);
            if kind == SYNC && decode::<Sync>(data).unwrap().length == length {
                return (kinds, h.frames.load(Ordering::SeqCst) - before);
            }
        }
    }
    let before = h.frames.load(Ordering::SeqCst);
    w.append(&[b"1".as_slice()]).await.unwrap();
    let (mut kinds, _) = until_sync(&mut h, 2).await;
    // `onupgrade` then `onhave`: the range follows the sync.
    kinds.push(h.next().await.expect("open").0);
    assert_eq!(kinds, [SYNC, RANGE]);
    assert_eq!(h.frames.load(Ordering::SeqCst) - before, 1);

    // `ontruncate`, `onhave(drop)`, `onupgrade`.
    w.truncate(1, None).await.unwrap();
    let (kinds, frames) = until_sync(&mut h, 1).await;
    assert_eq!((kinds, frames), (vec![RANGE, SYNC], 1));
}

/// Off-actor proofs, `replicator.js` `_fulfillRequest`: a request cancelled while its proof
/// is being built gets no answer; later requests are still answered.
#[tokio::test]
async fn a_request_cancelled_while_its_proof_is_built_gets_no_answer() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let w = writer(&store, 55);
    w.append(&[b"0".as_slice(), b"1"]).await.unwrap();
    let mut h = connect(&w, 64).await;
    h.send(SYNC, &sync(0, true, false, true));
    h.mux.cork();
    h.send(REQUEST, &block_request(1, 0, 0));
    h.send(CANCEL, &Cancel { request: 1 });
    h.send(REQUEST, &block_request(2, 1, 0));
    h.mux.uncork();
    let seen = h.marker(3).await.expect("open");
    let answers: Vec<u64> = seen
        .iter()
        .filter_map(|(kind, data)| answer_id(*kind, data))
        .collect();
    assert_eq!(answers, vec![2]);
}

/// `replicator.js` `ReceiverQueue.shift`: requests parked while the transport is backed up
/// are answered high priority first, newest first, then normal ones in arrival order.
#[tokio::test]
async fn parked_priority_requests_are_answered_newest_first() {
    const FILL: u64 = 20;
    const TOTAL: u64 = FILL + 5;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let w = writer(&store, 56);
    let blocks: Vec<Vec<u8>> = (0..TOTAL).map(|i| vec![i as u8; 1 << 20]).collect();
    w.append(&blocks).await.unwrap();
    let mut h = connect(&w, 1).await;
    h.send(SYNC, &sync(TOTAL, true, false, true));

    // Answers we do not read fill our inbound budget, then the writer's transport queue.
    h.mux.cork();
    for i in 0..FILL {
        h.send(REQUEST, &block_request(i + 1, i, 0));
    }
    h.mux.uncork();
    eventually(|| async { !h.core_mux.is_drained() }).await;

    // Request ids are block index + 1: normal, three high priority, normal.
    h.mux.cork();
    for (i, priority) in (FILL..TOTAL).zip([0, 1, 1, 1, 0]) {
        h.send(REQUEST, &block_request(i + 1, i, priority));
    }
    // Handled after the requests above; its effect shows they are parked.
    h.send(
        RANGE,
        &Range {
            drop: false,
            start: 0,
            length: 1,
        },
    );
    h.mux.uncork();
    eventually(|| async { w.remote_contiguous_length() >= 1 }).await;

    let mut order = vec![];
    while order.len() < TOTAL as usize {
        let (kind, data) = h.next().await.expect("open");
        if kind == DATA {
            order.push(answer_id(kind, &data).unwrap());
        }
    }
    let late: Vec<u64> = order.iter().copied().filter(|&id| id > FILL).collect();
    let fill: Vec<u64> = order.iter().copied().filter(|&id| id <= FILL).collect();
    let (a, b) = (FILL + 1, FILL + 5);
    assert_eq!(late, [b - 1, b - 2, b - 3, a, b], "answer order {order:?}");
    assert_eq!(fill, (1..=FILL).collect::<Vec<_>>());
}

/// `replicator.js` `signalUpgrade`: a writer that must first re-check whether the peer can be
/// upgraded (`_updateCanUpgradeAndSync`) sends the `sync` of an append after its `range`. A
/// reader that already wants the segment sends no second `want`, so that `range` is its only
/// notice of the new block: the part past the synced length is kept and applied at the `sync`.
#[tokio::test]
async fn a_range_sent_ahead_of_its_sync_still_announces_the_block() {
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let stores: Vec<_> = dirs
        .iter()
        .map(|d| Store::open(d.path()).unwrap())
        .collect();
    let w = writer(&stores[0], 53);
    w.append(&[b"0".as_slice()]).await.unwrap();
    let r = reader(&stores[1], w.key());
    let _session = r.session(true);

    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let (r_mux, r_remote) = (Mux::new(ar, aw, info(false)), Mux::new(br, bw, info(true)));
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let (w_mux, w_remote) = (Mux::new(ar, aw, info(false)), Mux::new(br, bw, info(true)));
    r.replicate(&r_mux);
    w.replicate(&w_mux);
    let mut to_r = open(&r_remote, &r).await;
    let mut to_w = open(&w_remote, &w).await;
    let (wanted, mut wants) = mpsc::unbounded_channel();
    // Forwards every message. The writer's `sync` for length 2 is held until the `range` that
    // follows it has gone out: the order npm sends them in on its asynchronous path.
    tokio::spawn(async move {
        let mut held = None;
        let mut swapped = false;
        loop {
            let (from_r, event) = tokio::select! {
                e = to_r.recv() => (true, e),
                e = to_w.recv() => (false, e),
            };
            let m = match event {
                Some(Event::Message(m)) => m,
                Some(Event::Opened { .. }) => continue,
                Some(Event::Closed { .. }) | None => break,
            };
            if from_r {
                if m.kind == WANT {
                    let _ = wanted.send(());
                }
                to_w.send_raw(m.kind, &m.data);
            } else if !swapped
                && m.kind == SYNC
                && decode::<Sync>(m.data.clone()).unwrap().length == 2
            {
                swapped = true;
                held = Some(m.data.clone());
            } else {
                to_r.send_raw(m.kind, &m.data);
                if m.kind == RANGE
                    && let Some(sync) = held.take()
                {
                    to_r.send_raw(SYNC, &sync);
                }
            }
        }
    });

    let first = timeout(T, r.get(0, GetOptions::default())).await.unwrap();
    assert_eq!(first.unwrap().as_deref(), Some(&b"0"[..]));
    // The reader asks for the next block before it exists, which registers its `want`.
    let get = tokio::spawn({
        let r = r.clone();
        async move { r.get(1, GetOptions::default()).await }
    });
    timeout(T, wants.recv())
        .await
        .expect("the reader wants the segment")
        .unwrap();
    eventually(|| async { r.pending_requests().await == 1 }).await;

    w.append(&[b"1".as_slice()]).await.unwrap();
    let block = timeout(T, get)
        .await
        .expect("the reader asks for the block the early range announced")
        .unwrap();
    assert_eq!(block.unwrap().as_deref(), Some(&b"1"[..]));
}
