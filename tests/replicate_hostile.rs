//! Replication between in-process cores: conflicts and updates without peers.

use std::time::Duration;

use hypercore::crypto::KeyPair;
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

fn link() -> (Mux, Mux) {
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let info = |is_initiator| StreamInfo {
        is_initiator,
        handshake_hash: Some([7; 64]),
        remote_public_key: None,
    };
    (Mux::new(ar, aw, info(true)), Mux::new(br, bw, info(false)))
}

/// Two writers with one key pair sign two trees of length 3. A reader that synced with the
/// first and then gets a proof from the second must fail its waiting read, as JS's
/// `closeAllSessions(err)` does, instead of waiting for ever.
#[tokio::test]
async fn a_proven_conflict_fails_a_pending_get() {
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let stores: Vec<_> = dirs
        .iter()
        .map(|d| Store::open(d.path()).unwrap())
        .collect();
    let first = writer(&stores[0], 40);
    first.append(&[b"a".as_slice(), b"b", b"c"]).await.unwrap();
    let second = writer(&stores[1], 40);
    second.append(&[b"x".as_slice(), b"y", b"z"]).await.unwrap();
    let r = reader(&stores[2], first.key());
    let _session = r.session(true);

    let (m1, m2) = link();
    first.replicate(&m1);
    r.replicate(&m2);
    assert!(timeout(T, r.update(None)).await.unwrap().unwrap());
    assert_eq!(r.length(), 3);
    m1.destroy();
    m2.destroy();

    let pending = tokio::spawn({
        let r = r.clone();
        async move { r.get(1, GetOptions::default()).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pending.is_finished(), "no peer serves block 1 yet");

    let (n1, n2) = link();
    second.replicate(&n1);
    r.replicate(&n2);
    let result = timeout(T, pending)
        .await
        .expect("the conflict ends the read")
        .unwrap();
    assert!(matches!(result, Err(CoreError::Conflict)), "got {result:?}");
}

/// JS `update()` with no `findingPeers` guard and no peer resolves `false` at once.
#[tokio::test]
async fn update_without_peers_or_guard_concludes_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let core = reader(&store, &[0x43; 32]);
    let updated = timeout(Duration::from_secs(1), core.update(None))
        .await
        .expect("concludes without waiting for a peer")
        .unwrap();
    assert!(!updated);
}
