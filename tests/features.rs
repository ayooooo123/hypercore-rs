use hypercore::{
    Core, CoreError, CoreEvent, CoreOptions, GetOptions, crypto::KeyPair, storage::Store,
};

#[tokio::test]
async fn metadata_hash_events_and_close() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[42; 32])),
            ..Default::default()
        },
    )
    .unwrap();
    let mut events = core.events();
    core.set_user_data("key", Some(b"value")).await.unwrap();
    assert_eq!(core.user_data("key").unwrap().unwrap().as_ref(), b"value");
    core.append(&[b"hello"]).await.unwrap();
    assert_eq!(
        events.recv().await.unwrap(),
        CoreEvent::Append {
            start: 0,
            length: 1
        }
    );
    assert_ne!(
        core.tree_hash(1).await.unwrap(),
        core.tree_hash(0).await.unwrap()
    );
    core.set_user_data("key", None).await.unwrap();
    assert!(core.user_data("key").unwrap().is_none());
    assert_eq!(core.remote_contiguous_length(), 0);
    core.close();
    assert_eq!(events.recv().await.unwrap(), CoreEvent::Close);
    assert!(matches!(
        core.get(0, GetOptions::default()).await,
        Err(CoreError::Closed)
    ));
    assert!(matches!(core.append(&[b"x"]).await, Err(CoreError::Closed)));
}

#[test]
fn manifest_keys_match_js() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/manifest.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let mut manifest = hypercore::verifier::default_signer_manifest([42; 32]);
        manifest.version = case["version"].as_u64().unwrap();
        let hash = hypercore::crypto::manifest_hash(&manifest);
        let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, case["key"].as_str().unwrap());
    }
}

#[test]
fn manifest_version_selects_core_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let pair = KeyPair::from_seed(&[9; 32]);
    for version in [1, 3] {
        let mut manifest = hypercore::verifier::default_signer_manifest(pair.public_key);
        manifest.version = version;
        let core = Core::open(
            &store,
            CoreOptions {
                key_pair: Some(pair.clone()),
                manifest_version: version,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(*core.key(), hypercore::crypto::manifest_hash(&manifest));
    }
}

#[tokio::test]
async fn unsigned_prologue_append_is_bounded() {
    use compact_encoding::hypercore::Prologue;
    use hypercore::{AppendOptions, Node, crypto};
    let block = b"anchor";
    let node = Node {
        index: 0,
        size: block.len() as u64,
        hash: crypto::data_hash(block),
    };
    let mut manifest = hypercore::verifier::default_signer_manifest([42; 32]);
    manifest.version = 2;
    manifest.quorum = 0;
    manifest.signers.clear();
    manifest.prologue = Some(Prologue {
        hash: crypto::tree_hash(&[node]),
        length: 1,
    });
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            manifest: Some(manifest),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        core.append(&[block]).await,
        Err(CoreError::NotWritable)
    ));
    let opts = AppendOptions {
        writable: true,
        max_length: Some(1),
    };
    assert_eq!(core.append_with(&[block], opts).await.unwrap().length, 1);
    assert_eq!(core.append_with(&[block], opts).await.unwrap().length, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_activity_changes_keep_session_counts() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[7; 32])),
            ..Default::default()
        },
    )
    .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let core = core.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..100 {
                let mut session = core.session(true);
                session.set_active(false);
                session.set_active(true);
                core.set_active(true);
                core.set_active(false);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(core.active_session_count(), 0);
}

#[tokio::test]
async fn replication_reports_download_and_raw_ciphertext() {
    use protomux::{Mux, StreamInfo, memory};
    use std::time::Duration;
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_store = Store::open(a_dir.path()).unwrap();
    let b_store = Store::open(b_dir.path()).unwrap();
    let a = Core::open(
        &a_store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[11; 32])),
            encryption_key: Some([5; 32]),
            ..Default::default()
        },
    )
    .unwrap();
    a.append(&[b"secret".as_slice(), b"second"]).await.unwrap();
    let b = Core::open(
        &b_store,
        CoreOptions {
            key: Some(*a.key()),
            encryption_key: Some([5; 32]),
            ..Default::default()
        },
    )
    .unwrap();
    let _session = b.session(true);
    let mut events = b.events();
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let info = |initiator| StreamInfo {
        is_initiator: initiator,
        handshake_hash: Some([7; 64]),
        remote_public_key: None,
    };
    let ma = Mux::new(ar, aw, info(true));
    let mb = Mux::new(br, bw, info(false));
    a.replicate(&ma);
    b.replicate(&mb);
    let raw = tokio::time::timeout(
        Duration::from_secs(10),
        b.get(
            0,
            GetOptions {
                raw: true,
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_ne!(raw.as_ref(), b"secret");
    assert_eq!(
        b.get(0, GetOptions::default())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"secret"
    );
    assert!(!b.has(1));
    let hash = tokio::time::timeout(Duration::from_secs(10), b.tree_hash(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hash, a.tree_hash(2).await.unwrap());
    assert!(b.has(1));
    let mut downloaded = false;
    while let Ok(event) = events.try_recv() {
        if matches!(event, CoreEvent::Download { index: 0, .. }) {
            downloaded = true;
        }
    }
    assert!(downloaded);
}

#[tokio::test]
async fn storage_close_stops_actors_and_invalidates_handles() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[13; 32])),
            ..Default::default()
        },
    )
    .unwrap();
    let _session = core.session(true);
    let mut events = core.events();
    core.append(&[b"data"]).await.unwrap();
    let _ = events.recv().await.unwrap();
    store.close();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), events.recv())
            .await
            .unwrap()
            .unwrap(),
        CoreEvent::Close
    );
    assert!(matches!(
        core.get(0, GetOptions::default()).await,
        Err(CoreError::Closed)
    ));
    assert!(matches!(
        core.storage().header(),
        Err(hypercore::storage::StorageError::Closed)
    ));
    assert!(Store::open(dir.path()).is_ok());
}
