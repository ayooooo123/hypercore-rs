use std::time::Duration;

use hypercore::crypto::KeyPair;
use hypercore::encryption::EncryptionOptions;
use hypercore::replicator::PROTOCOL;
use hypercore::storage::Store;
use hypercore::{Core, CoreError, CoreOptions, GetOptions};
use protomux::{Mux, StreamInfo, memory};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(10);

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

/// Two muxes over an in-memory link that look like one secret-stream session.
fn link() -> (Mux, Mux) {
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let hh = Some([7u8; 64]);
    (
        Mux::new(
            ar,
            aw,
            StreamInfo {
                is_initiator: true,
                handshake_hash: hh,
                remote_public_key: None,
            },
        ),
        Mux::new(
            br,
            bw,
            StreamInfo {
                is_initiator: false,
                handshake_hash: hh,
                remote_public_key: None,
            },
        ),
    )
}

fn now() -> GetOptions {
    GetOptions {
        wait: false,
        ..Default::default()
    }
}

#[tokio::test]
async fn append_get_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let key = {
        let store = Store::open(dir.path()).unwrap();
        let core = writer(&store, 1);
        assert!(core.writable());
        let head = core
            .append(&[b"a".as_slice(), b"bc", b"def"])
            .await
            .unwrap();
        assert_eq!((head.length, head.byte_length), (3, 6));
        core.append(&[b"ghij"]).await.unwrap();
        assert_eq!(core.byte_range(3).unwrap(), (6, 4));
        assert_eq!(core.seek(5, false).await.unwrap(), Some((2, 2)));
        *core.key()
    };
    let store = Store::open(dir.path()).unwrap();
    let core = reader(&store, &key);
    assert!(
        core.writable(),
        "the key pair is stored with the core, as in JS"
    );
    assert_eq!(core.length(), 4);
    assert_eq!(&core.get(1, now()).await.unwrap().unwrap()[..], b"bc");
    assert_eq!(core.contiguous_length(), 4);
    let w = writer(&store, 1);
    w.append(&[b"k"]).await.unwrap();
    assert_eq!(
        w.length(),
        5,
        "same key pair reopens the stored core writable"
    );
}

#[tokio::test]
async fn encrypted_blocks_are_stored_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let opts = CoreOptions {
        key_pair: Some(KeyPair::from_seed(&[2; 32])),
        encryption_key: Some([9; 32]),
        encryption: EncryptionOptions::default(),
        ..Default::default()
    };
    let core = Core::open(&store, opts.clone()).unwrap();
    core.append(&[b"secret block".as_slice()]).await.unwrap();
    assert_eq!(core.padding(), 8);
    let raw = core.get_raw_local(0).unwrap().unwrap();
    assert_eq!(raw.len(), 8 + 12);
    assert!(!raw.windows(6).any(|w| w == b"secret"));
    assert_eq!(
        &core.get(0, now()).await.unwrap().unwrap()[..],
        b"secret block"
    );
    assert_eq!(
        core.byte_range(0).unwrap(),
        (0, 12),
        "byte ranges exclude padding"
    );
    drop(core);
    let again = Core::open(&store, opts).unwrap();
    assert_eq!(
        &again.get(0, now()).await.unwrap().unwrap()[..],
        b"secret block"
    );
}

#[tokio::test]
async fn truncate_clear_purge() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let core = writer(&store, 3);
    let blocks: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 100]).collect();
    core.append(&blocks).await.unwrap();

    core.truncate(6, None).await.unwrap();
    assert_eq!((core.length(), core.fork()), (6, 1));
    assert!(core.get(7, now()).await.unwrap().is_none());
    core.append(&[b"new".as_slice()]).await.unwrap();
    assert_eq!(&core.get(6, now()).await.unwrap().unwrap()[..], b"new");
    assert!(matches!(
        core.truncate(9, None).await,
        Err(CoreError::BadArgument(_))
    ));

    core.clear(1, 3).await.unwrap();
    assert!(!core.has(1) && !core.has(2) && core.has(3));
    assert_eq!(core.contiguous_length(), 1);
    assert!(core.get(2, now()).await.unwrap().is_none());
    assert_eq!(core.length(), 7, "clear keeps the log length");

    assert_eq!(store.cores().unwrap().len(), 1);
    core.purge().await.unwrap();
    assert!(store.cores().unwrap().is_empty());
}

#[tokio::test]
async fn sparse_download_and_reorg_between_rust_peers() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (sa, sb) = (
        Store::open(da.path()).unwrap(),
        Store::open(db.path()).unwrap(),
    );
    let a = writer(&sa, 4);
    let blocks: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i; 3000]).collect();
    a.append(&blocks).await.unwrap();
    let b = reader(&sb, a.key());
    let _session = b.session(true);
    let (ma, mb) = link();
    a.replicate(&ma);
    b.replicate(&mb);

    assert!(timeout(T, b.update(None)).await.unwrap().unwrap());
    assert_eq!(b.length(), 40);
    let got = timeout(T, b.get(25, GetOptions::default()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(got, blocks[25]);
    assert!(
        b.has(25) && !b.has(24),
        "only the requested block was fetched"
    );

    // The writer rewrites history after block 30; the reader follows the fork.
    a.truncate(30, None).await.unwrap();
    a.append(&[b"fork".as_slice()]).await.unwrap();
    let mut head = b.subscribe();
    timeout(T, head.wait_for(|h| h.fork == 1 && h.length == 31))
        .await
        .unwrap()
        .unwrap();
    let fork_block = timeout(T, b.get(30, GetOptions::default()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&fork_block[..], b"fork");
    assert!(b.has(25), "blocks before the fork point survive the reorg");
}

#[tokio::test]
async fn inactive_sessions_let_the_channel_go_idle() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (sa, sb) = (
        Store::open(da.path()).unwrap(),
        Store::open(db.path()).unwrap(),
    );
    let a = writer(&sa, 5);
    a.append(&[b"x".as_slice()]).await.unwrap();
    let b = reader(&sb, a.key());
    let passive = b.session(false);
    assert!(!passive.is_active());
    let (ma, mb) = link();
    a.replicate(&ma);
    b.replicate(&mb);
    let dk = *a.discovery_key();
    // Nobody downloads: after the sync exchange the peers close the channel.
    let opened = |m: &Mux| m.is_opened(PROTOCOL, Some(&dk));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!opened(&ma) && !opened(&mb), "the idle channel was closed");
    assert_eq!(b.length(), 0);

    // An active session reopens replication and downloads.
    let _active = b.session(true);
    assert!(timeout(T, b.update(None)).await.unwrap().unwrap());
    assert_eq!(b.length(), 1);
}

#[tokio::test]
async fn a_downloaded_manifest_survives_reopening() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (sa, sb) = (
        Store::open(da.path()).unwrap(),
        Store::open(db.path()).unwrap(),
    );
    let kp = KeyPair::from_seed(&[9; 32]);
    let manifest = hypercore::verifier::default_signer_manifest(kp.public_key);
    let a = Core::open(
        &sa,
        CoreOptions {
            key_pair: Some(kp),
            manifest: Some(manifest.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    a.append(&[b"x".as_slice()]).await.unwrap();
    let b = reader(&sb, a.key());
    let session = b.session(true);
    let (ma, mb) = link();
    a.replicate(&ma);
    b.replicate(&mb);
    let got = timeout(T, b.get(0, GetOptions::default()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&got[..], b"x");
    assert_eq!(
        b.manifest(),
        Some(manifest.clone()),
        "the proof carried the manifest"
    );
    drop(session);
    b.close();
    let reopened =
        Core::open_by_discovery_key(&sb, b.discovery_key(), CoreOptions::default()).unwrap();
    assert_eq!(
        reopened.manifest(),
        Some(manifest),
        "the learned manifest is stored, not just remembered"
    );
}

#[tokio::test]
async fn seek_past_the_local_length_waits_for_a_peer() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (sa, sb) = (
        Store::open(da.path()).unwrap(),
        Store::open(db.path()).unwrap(),
    );
    let a = writer(&sa, 11);
    let blocks: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 1000]).collect();
    a.append(&blocks).await.unwrap();
    let b = reader(&sb, a.key());
    let _session = b.session(true);
    let (ma, mb) = link();
    a.replicate(&ma);
    b.replicate(&mb);

    // Nothing is local yet: an empty core asked for a middle offset still resolves, as a peer's
    // seek reply carries the position. Without the wait this is `None` and playback 404s.
    assert_eq!(b.length(), 0);
    let (index, offset) = timeout(T, b.seek(2500, true))
        .await
        .expect("seek waits for the peer")
        .unwrap()
        .expect("the peer's position");
    assert_eq!((index, offset), (2, 500));
    let got = timeout(T, b.get(index, GetOptions::default()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(got, blocks[2]);
}
