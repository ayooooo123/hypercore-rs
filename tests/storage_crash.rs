//! Crash ordering: a killed writer must leave a store the other stack can open.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use bytes::Bytes;
use hypercore_storage::{CreateCore, Store};
use serde_json::Value;

fn js_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/js")
}

fn exe() -> PathBuf {
    std::env::current_exe().expect("test binary")
}

/// Cargo runs this as the child; without `CRASH_STORE` it is a no-op.
#[test]
fn crash_writer() {
    let Ok(dir) = std::env::var("CRASH_STORE") else {
        return;
    };
    let store = Store::open(Path::new(&dir)).expect("open");
    let storage = store
        .create_core(CreateCore {
            key: [1; 32],
            discovery_key: [2; 32],
            ..Default::default()
        })
        .expect("core");
    let block = Bytes::from(vec![7u8; 512 * 1024]);
    let mut index = 0u64;
    loop {
        let mut tx = storage.write();
        for _ in 0..8 {
            tx.put_block(index, block.clone());
            index += 1;
        }
        tx.set_head(&hypercore_storage::CoreHead {
            length: index,
            ..Default::default()
        });
        storage.flush(tx).expect("write");
    }
}

#[test]
#[ignore = "spawns and kills a writer process; needs node and tests/js/node_modules"]
fn killed_write_leaves_a_readable_store() {
    if !js_dir().join("node_modules").exists() {
        let status = Command::new("npm")
            .args(["install", "--no-audit", "--no-fund"])
            .current_dir(js_dir())
            .status()
            .expect("npm");
        assert!(status.success());
    }

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("store");
    let mut child = Command::new(exe())
        .args(["--exact", "crash_writer", "--include-ignored"])
        .env("CRASH_STORE", &dir)
        .spawn()
        .expect("spawn writer");
    std::thread::sleep(Duration::from_millis(1200));
    // SIGKILL: no destructor, no flush, no clean close.
    child.kill().expect("kill");
    let _ = child.wait();

    let output = Command::new("node")
        .arg("list.mjs")
        .arg(&dir)
        .current_dir(js_dir())
        .output()
        .expect("node");
    assert!(
        output.status.success(),
        "JS could not open the killed store: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let cores = listed["cores"].as_array().expect("cores");
    assert_eq!(cores.len(), 1, "the core row survived the kill");
    assert!(
        cores[0]["length"].as_u64().unwrap() > 0,
        "some commits survived"
    );

    let store = Store::open_read_only(&dir).expect("rust reopens the killed store");
    assert_eq!(store.cores().unwrap().len(), 1);
    let storage = store.resume_core(&[2; 32]).unwrap().expect("core");
    assert!(storage.get_head().unwrap().is_some());
    assert!(
        storage.blocks().unwrap().len() as u64 <= storage.get_head().unwrap().unwrap().length,
        "the head never runs ahead of the blocks that are there"
    );
}
