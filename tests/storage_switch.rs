//! JS⇄Rust switch test: `tests/js/store.mjs` builds a corestore with the npm
//! stack, then JS and Rust take turns opening the same directory, checking every
//! core against `<dir>.ledger.json`, appending and writing user data.
//!
//! `#[ignore]`d: it needs node and `tests/js/node_modules`
//! (`cargo test -- --include-ignored`).

use std::path::{Path, PathBuf};
use std::process::Command;

use bytes::Bytes;
use corestore::{Corestore, GetOptions};
use hyperbee::Bee;
use hypercore::GetOptions as ReadOptions;
use serde_json::{Value, json};
use tempfile::TempDir;

fn js_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/js")
}

fn run_node(mode: &str, dir: &Path, writer: &str) -> Value {
    let output = Command::new("node")
        .arg("store.mjs")
        .arg(mode)
        .arg(dir)
        .arg(writer)
        .current_dir(js_dir())
        .output()
        .expect("node");
    assert!(
        output.status.success(),
        "node store.mjs {mode} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("node output is JSON")
}

fn ledger_path(dir: &Path) -> PathBuf {
    PathBuf::from(format!("{}.ledger.json", dir.display()))
}

fn read_ledger(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(ledger_path(dir)).expect("ledger")).expect("ledger json")
}

fn write_ledger(dir: &Path, ledger: &Value) {
    std::fs::write(ledger_path(dir), serde_json::to_vec(ledger).unwrap()).unwrap();
}

fn hex_to_key(hex: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    bytes.try_into().expect("32-byte key")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key_of(ledger: &Value, name: &str) -> [u8; 32] {
    hex_to_key(ledger["cores"][name]["key"].as_str().expect("core key"))
}

const CORES: &[(&str, bool)] = &[
    // name, appendable
    ("alpha", true),
    ("beta", true),
    ("secret", true),
    ("explicit", false),
    ("v2", true),
    ("grouped", true),
    ("sparse", false),
    ("bee", true),
    ("blobs", true),
    ("forked", true),
];

/// Opens every core from the ledger and compares it.
async fn verify(store: &Corestore, ledger: &Value) -> Vec<(String, hypercore::Session)> {
    let mut out = Vec::new();
    for (name, _) in CORES {
        let entry = &ledger["cores"][*name];
        let key = key_of(ledger, name);
        let mut options = if *name == "explicit" {
            GetOptions::key(key)
        } else {
            GetOptions::name(name.as_bytes())
        };
        if *name == "secret" {
            options.encryption_key = Some(hex_to_key(ledger["encryptionKey"].as_str().unwrap()));
        }
        let view = match entry["namespace"].as_str() {
            Some(namespace) => store.namespace(namespace),
            None => store.clone(),
        };
        let session = view
            .get(options)
            .await
            .unwrap_or_else(|e| panic!("{name}: get: {e}"));
        let core = session.core();
        assert_eq!(core.key(), &key, "{name}: key");
        assert_eq!(core.length(), entry["length"].as_u64().unwrap(), "{name}: length");
        assert_eq!(core.fork(), entry["fork"].as_u64().unwrap(), "{name}: fork");
        assert_eq!(
            core.contiguous_length(),
            entry["contiguous"].as_u64().unwrap(),
            "{name}: contiguous"
        );
        let roots = hypercore::merkle::roots_at(core.storage(), core.length())
            .unwrap_or_else(|e| panic!("{name}: roots: {e}"));
        assert_eq!(
            hex(&hypercore::crypto::tree_hash(&roots)),
            entry["rootHash"].as_str().unwrap(),
            "{name}: root hash"
        );
        let stored = core
            .storage()
            .get_head()
            .unwrap()
            .unwrap_or_default();
        assert_eq!(
            stored.signature.as_ref().map(|s| hex(s)),
            entry["signature"].as_str().map(str::to_string),
            "{name}: signature"
        );
        for sample in entry["sample"].as_array().unwrap() {
            let index = sample["index"].as_u64().unwrap();
            let value = core
                .get(index, ReadOptions::default())
                .await
                .unwrap_or_else(|e| panic!("{name}: block {index}: {e}"))
                .unwrap_or_else(|| panic!("{name}: block {index} missing"));
            assert_eq!(hex(&value), sample["value"].as_str().unwrap(), "{name}: block {index}");
        }
        out.push((name.to_string(), session));
    }
    out
}

/// Reads, appends one block per appendable core, writes user data and a bee
/// entry, then updates the ledger.
async fn rust_turn(dir: &Path) -> usize {
    let mut ledger = read_ledger(dir);
    let store = Corestore::open(dir).expect("open store");
    assert_eq!(
        hex(store.primary_key()),
        ledger["primaryKey"].as_str().unwrap(),
        "primary key from the store head seed"
    );
    let cores = verify(&store, &ledger).await;

    let tag = Bytes::from(vec![0x32u8; 32]);
    for (name, session) in &cores {
        let core = session.core();
        let appendable = CORES
            .iter()
            .find(|(core_name, _)| core_name == name)
            .is_some_and(|(_, appendable)| *appendable);
        if !appendable || name == "bee" {
            continue;
        }
        core.append(&[tag.clone()])
            .await
            .unwrap_or_else(|e| panic!("{name}: append: {e}"));
    }
    let alpha = cores
        .iter()
        .find(|(name, _)| name == "alpha")
        .map(|(_, session)| session.core())
        .unwrap();
    alpha
        .set_user_data("last-writer", Some(b"rust"))
        .await
        .expect("user data");

    let bee = Bee::open(&store, None).await.expect("bee");
    let hello = bee.get(b"hello").await.unwrap().expect("hello entry");
    assert_eq!(&hello.value[..], b"world", "bee entry after JS writes");
    let mut batch = bee.batch();
    let turn = ledger["beeEntries"].as_u64().unwrap();
    batch.put(format!("turn-rust-{turn}").into_bytes(), b"ok".to_vec());
    batch.flush().await.expect("bee flush");
    ledger["beeEntries"] = json!(turn + 1);

    // Rewrite the ledger from the new state.
    for (name, session) in &cores {
        let core = session.core();
        let roots = hypercore::merkle::roots_at(core.storage(), core.length()).unwrap();
        let mut sample = Vec::new();
        for index in [0u64, core.length().saturating_sub(1)] {
            if index < core.length() && core.has(index) {
                let value = core.get(index, ReadOptions::default()).await.unwrap().unwrap();
                sample.push(json!({ "index": index, "value": hex(&value) }));
            }
        }
        if sample.is_empty() {
            let value = core.get(0, ReadOptions::default()).await.unwrap().unwrap();
            sample.push(json!({ "index": 0, "value": hex(&value) }));
        }
        let stored = core.storage().get_head().unwrap().unwrap_or_default();
        ledger["cores"][name] = json!({
            "key": hex(core.key()),
            "length": core.length(),
            "fork": core.fork(),
            "rootHash": hex(&hypercore::crypto::tree_hash(&roots)),
            "signature": stored.signature.as_ref().map(|s| hex(s)),
            "contiguous": core.contiguous_length(),
            "sample": sample,
            "appendable": ledger["cores"][name]["appendable"],
            "sparse": ledger["cores"][name]["sparse"],
            "namespace": ledger["cores"][name]["namespace"],
        });
    }

    store.close().await;
    write_ledger(dir, &ledger);
    cores.len()
}

#[tokio::test]
#[ignore = "builds the npm fixture store (needs node and tests/js/node_modules)"]
async fn js_and_rust_switch_on_one_directory() {
    if !js_dir().join("node_modules").exists() {
        let status = Command::new("npm")
            .args(["install", "--no-audit", "--no-fund"])
            .current_dir(js_dir())
            .status()
            .expect("npm");
        assert!(status.success(), "npm install failed");
    }
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("store");
    let built = run_node("build", &dir, "js");
    assert_eq!(built["built"], 10, "fixture cores");

    // Four switches: Rust, JS, Rust, JS.
    for turn in 0..4 {
        if turn % 2 == 0 {
            assert_eq!(rust_turn(&dir).await, CORES.len());
        } else {
            let result = run_node("switch", &dir, "js");
            assert_eq!(result["problems"], 0, "JS found mismatches");
        }
    }

    // The last writer was JS; one more Rust read must see everything it wrote.
    let store = Corestore::open(&dir).expect("open");
    let ledger = read_ledger(&dir);
    let cores = verify(&store, &ledger).await;
    let alpha = cores
        .iter()
        .find(|(name, _)| name == "alpha")
        .unwrap()
        .1
        .core()
        .clone();
    assert_eq!(
        alpha.user_data("last-writer").unwrap().as_deref(),
        Some(&b"js"[..]),
        "user data survives alternating writers"
    );
    let bee = Bee::open(&store, None).await.unwrap();
    assert!(bee.get(b"hello").await.unwrap().is_some());
    for key in ["turn-rust-4", "turn-js-5", "turn-rust-6", "turn-js-7"] {
        assert!(
            bee.get(key.as_bytes()).await.unwrap().is_some(),
            "bee entry {key} written by one stack is missing"
        );
    }
    assert_eq!(ledger["beeEntries"].as_u64().unwrap(), 8);
    store.close().await;
}
