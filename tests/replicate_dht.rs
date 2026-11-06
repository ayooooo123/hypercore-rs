//! npm hypercore on Hyperswarm against hypercore-rs on peeroxide, on a local
//! HyperDHT testnet: discovery by topic, holepunch handshake, UDX over UDP,
//! secret-stream, Protomux, Hypercore, as the apps run it.
//!
//! Size: `HC_INTEROP_MB` (default 32); 1 GiB acceptance:
//! `HC_INTEROP_MB=1024 cargo test --release --test replicate_dht -- --include-ignored --test-threads 1`.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use hypercore::crypto::KeyPair;
use hypercore::storage::Store;
use hypercore::{Core, CoreOptions, GetOptions};
use peeroxide::{JoinOpts, SwarmConfig, SwarmConnection, spawn};
use peeroxide_dht::hyperdht::HyperDhtConfig;
use peeroxide_dht::rpc::DhtConfig;
use protomux::Mux;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;

const BLOCK: usize = 512 * 1024;

fn mib(blocks: u64) -> u64 {
    blocks * BLOCK as u64 / (1024 * 1024)
}

fn blocks() -> u64 {
    let mb: u64 = std::env::var("HC_INTEROP_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    mb * 1024 * 1024 / BLOCK as u64
}

fn block(i: u64, size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    let mut x = i.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1);
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
    }
    out
}

fn sha256_hex(parts: impl Iterator<Item = Vec<u8>>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(&p);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn node(args: &[&str]) -> (Child, Lines<BufReader<ChildStdout>>) {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js"));
    assert!(
        dir.join("node_modules").exists(),
        "run `npm install` in {}",
        dir.display()
    );
    let mut child = Command::new("node")
        .arg("dht.js")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node on PATH");
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    (child, lines)
}

async fn line(out: &mut Lines<BufReader<ChildStdout>>, prefix: &str) -> String {
    loop {
        let l = out
            .next_line()
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("node exited before {prefix:?}"));
        assert!(!l.starts_with("error"), "{l}");
        if let Some(rest) = l.strip_prefix(prefix) {
            return rest.trim().to_owned();
        }
    }
}

async fn rust_swarm(
    bootstrap_port: &str,
) -> (peeroxide::SwarmHandle, mpsc::Receiver<SwarmConnection>) {
    let mut dht = DhtConfig::default();
    dht.bootstrap = vec![format!("127.0.0.1:{bootstrap_port}")];
    dht.host = "127.0.0.1".to_string();
    dht.port = 0;
    let mut hyper = HyperDhtConfig::default();
    hyper.dht = dht;
    let mut config = SwarmConfig::default();
    config.dht = hyper;
    let (_task, handle, conns) = spawn(config).await.expect("peeroxide swarm");
    (handle, conns)
}

/// Replicates `core` on every connection the swarm makes.
fn replicate_all(core: Core, mut conns: mpsc::Receiver<SwarmConnection>) {
    tokio::spawn(async move {
        while let Some(conn) = conns.recv().await {
            core.replicate(&Mux::from_secret_stream(conn.peer.stream));
        }
    });
}

fn opts(client: bool) -> JoinOpts {
    let mut o = JoinOpts::default();
    o.server = !client;
    o.client = client;
    o
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn js_swarm_writes_rust_swarm_reads() {
    let n = blocks();
    let tmp = tempfile::tempdir().unwrap();
    let (_testnet, mut tn) = node(&["testnet"]);
    let port = line(&mut tn, "bootstrap ").await;
    let js_dir = tmp.path().join("js");
    let (_writer, mut out) = node(&[
        "write",
        &port,
        js_dir.to_str().unwrap(),
        &n.to_string(),
        &BLOCK.to_string(),
        &"11".repeat(32),
    ]);
    let key: [u8; 32] = hex_bytes(&line(&mut out, "key ").await).try_into().unwrap();
    line(&mut out, "ready").await;

    let store = Store::open(&tmp.path().join("rust")).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key: Some(key),
            ..Default::default()
        },
    )
    .unwrap();
    let _session = core.session(true);
    let (swarm, conns) = rust_swarm(&port).await;
    replicate_all(core.clone(), conns);
    swarm.join(*core.discovery_key(), opts(true)).await.unwrap();

    let started = Instant::now();
    assert!(
        timeout(Duration::from_secs(60), core.update(None))
            .await
            .expect("upgrade over the DHT")
            .unwrap()
    );
    assert_eq!(core.length(), n);
    assert!(
        timeout(Duration::from_secs(1800), core.download(0, Some(n), false))
            .await
            .unwrap()
            .unwrap()
    );
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "js->rust over udx: {} MiB in {secs:.2}s ({:.1} MiB/s)",
        mib(n),
        mib(n) as f64 / secs
    );
    let mut got = vec![];
    for i in 0..n {
        got.push(
            core.get(
                i,
                GetOptions {
                    wait: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .expect("downloaded")
            .to_vec(),
        );
    }
    assert_eq!(
        sha256_hex(got.into_iter()),
        sha256_hex((0..n).map(|i| block(i, BLOCK)))
    );
    let _ = swarm.destroy().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn rust_swarm_writes_js_swarm_reads() {
    let n = blocks();
    let tmp = tempfile::tempdir().unwrap();
    let (_testnet, mut tn) = node(&["testnet"]);
    let port = line(&mut tn, "bootstrap ").await;

    let store = Store::open(&tmp.path().join("rust")).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[0x22; 32])),
            ..Default::default()
        },
    )
    .unwrap();
    let _session = core.session(true);
    for chunk in (0..n).collect::<Vec<_>>().chunks(64) {
        let data: Vec<Vec<u8>> = chunk.iter().map(|&i| block(i, BLOCK)).collect();
        core.append(&data).await.unwrap();
    }
    let (swarm, conns) = rust_swarm(&port).await;
    replicate_all(core.clone(), conns);
    swarm
        .join(*core.discovery_key(), opts(false))
        .await
        .unwrap();
    swarm.flush().await.unwrap();

    let js_dir = tmp.path().join("js");
    let (_reader, mut out) = node(&["read", &port, js_dir.to_str().unwrap(), &hex(core.key())]);
    let report = timeout(Duration::from_secs(1800), line(&mut out, "sha256 "))
        .await
        .expect("JS download timed out");
    let parts: Vec<&str> = report.split(' ').collect();
    eprintln!("rust->js over udx: {} MiB in {} ms", mib(n), parts[2]);
    assert_eq!(parts[1], n.to_string());
    assert_eq!(parts[0], sha256_hex((0..n).map(|i| block(i, BLOCK))));
    let _ = swarm.destroy().await;
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
