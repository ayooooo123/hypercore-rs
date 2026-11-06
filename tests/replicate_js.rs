//! npm hypercore 11 against hypercore-rs over secret-stream on TCP: JS writes
//! and Rust reads, and Rust writes and JS reads, with content hashes checked.
//!
//! Size: `HC_INTEROP_MB` (default 32). The 1 GiB acceptance run is
//! `HC_INTEROP_MB=1024 cargo test --release --test replicate_js -- --include-ignored`.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use hypercore::core::{Core, CoreOptions, GetOptions};
use hypercore::crypto::KeyPair;
use hypercore::storage::Store;
use peeroxide_dht::noise::generate_keypair;
use peeroxide_dht::secret_stream::SecretStream;
use protomux::Mux;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdout, Command};

const BLOCK: usize = 512 * 1024;

fn js_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js"))
}

fn blocks() -> u64 {
    let mb: u64 = std::env::var("HC_INTEROP_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    mb * 1024 * 1024 / BLOCK as u64
}

/// Same xorshift as `tests/js/peer.js`.
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

fn node(args: &[&str]) -> (Child, Lines<BufReader<ChildStdout>>) {
    assert!(
        js_dir().join("node_modules").exists(),
        "run `npm install` in {}",
        js_dir().display()
    );
    let mut child = Command::new("node")
        .arg("peer.js")
        .args(args)
        .current_dir(js_dir())
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node on PATH");
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    (child, lines)
}

async fn line(lines: &mut Lines<BufReader<ChildStdout>>, prefix: &str) -> String {
    loop {
        let l = lines
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn js_writes_rust_reads() {
    let n = blocks();
    let tmp = tempfile::tempdir().unwrap();
    let js_store = tmp.path().join("js");
    let (_child, mut out) = node(&[
        "write",
        js_store.to_str().unwrap(),
        &n.to_string(),
        &BLOCK.to_string(),
        &"11".repeat(32),
    ]);
    let key: [u8; 32] = hex(&line(&mut out, "key ").await).try_into().unwrap();
    let port = line(&mut out, "port ").await;

    let store = Store::open(&tmp.path().join("rust")).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key: Some(key),
            ..Default::default()
        },
    )
    .unwrap();
    let session = core.session(true);
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let ss = SecretStream::new(true, tcp, generate_keypair())
        .await
        .unwrap();
    let mux = Mux::from_secret_stream(ss);
    core.replicate(&mux);

    let started = Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_secs(30), core.update(None))
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(core.length(), n);
    assert!(
        tokio::time::timeout(Duration::from_secs(900), core.download(0, Some(n), false))
            .await
            .unwrap()
            .unwrap()
    );
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "js->rust: {} MiB in {secs:.2}s ({:.1} MiB/s)",
        n / 2,
        (n / 2) as f64 / secs
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
    drop(session);
    mux.destroy();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn rust_writes_js_reads() {
    let n = blocks();
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(&tmp.path().join("rust")).unwrap();
    let kp = KeyPair::from_seed(&[0x22; 32]);
    let core = Core::open(
        &store,
        CoreOptions {
            key_pair: Some(kp),
            ..Default::default()
        },
    )
    .unwrap();
    let _session = core.session(true);
    for chunk in (0..n).collect::<Vec<_>>().chunks(64) {
        let data: Vec<Vec<u8>> = chunk.iter().map(|&i| block(i, BLOCK)).collect();
        core.append(&data).await.unwrap();
    }
    assert_eq!(core.length(), n);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let key: String = core.key().iter().map(|b| format!("{b:02x}")).collect();
    let js_store = tmp.path().join("js");
    let (mut child, mut out) = node(&["read", js_store.to_str().unwrap(), &key, &port]);
    let (tcp, _) = listener.accept().await.unwrap();
    let ss = SecretStream::new(false, tcp, generate_keypair())
        .await
        .unwrap();
    let mux = Mux::from_secret_stream(ss);
    core.replicate(&mux);

    let report = tokio::time::timeout(Duration::from_secs(900), line(&mut out, "sha256 "))
        .await
        .expect("JS download timed out");
    let parts: Vec<&str> = report.split(' ').collect();
    eprintln!("rust->js: {} MiB in {} ms", n / 2, parts[3]);
    assert_eq!(parts[1], n.to_string());
    assert_eq!(parts[0], sha256_hex((0..n).map(|i| block(i, BLOCK))));
    let _ = child.wait().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn js_encrypted_core_and_its_fork_replicate_to_rust() {
    use tokio::io::AsyncWriteExt;
    let tmp = tempfile::tempdir().unwrap();
    let js_store = tmp.path().join("js");
    let enc = [0x33u8; 32];
    let enc_hex: String = enc.iter().map(|b| format!("{b:02x}")).collect();
    let (mut child, mut out) = node(&[
        "write",
        js_store.to_str().unwrap(),
        "20",
        "1000",
        &"44".repeat(32),
        &enc_hex,
    ]);
    let key: [u8; 32] = hex(&line(&mut out, "key ").await).try_into().unwrap();
    let port = line(&mut out, "port ").await;

    let store = Store::open(&tmp.path().join("rust")).unwrap();
    let core = Core::open(
        &store,
        CoreOptions {
            key: Some(key),
            encryption_key: Some(enc),
            ..Default::default()
        },
    )
    .unwrap();
    let _session = core.session(true);
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let mux = Mux::from_secret_stream(
        SecretStream::new(true, tcp, generate_keypair())
            .await
            .unwrap(),
    );
    core.replicate(&mux);

    assert!(
        tokio::time::timeout(Duration::from_secs(30), core.update(None))
            .await
            .unwrap()
            .unwrap()
    );
    assert!(core.download(0, Some(20), true).await.unwrap());
    for i in 0..20 {
        let b = core
            .get(
                i,
                GetOptions {
                    wait: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b.to_vec(), block(i, 1000), "plaintext of block {i}");
    }
    assert_eq!(
        core.byte_length(),
        20 * (1000 + 8),
        "byte length counts the padding, as in JS"
    );

    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(b"truncate 12\n").await.unwrap();
    assert_eq!(line(&mut out, "truncated ").await, "1 15");
    let mut head = core.subscribe();
    tokio::time::timeout(
        Duration::from_secs(30),
        head.wait_for(|h| h.fork == 1 && h.length == 15),
    )
    .await
    .expect("Rust follows the JS fork")
    .unwrap();
    let b = tokio::time::timeout(Duration::from_secs(30), core.get(13, GetOptions::default()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(&b[..], b"fork-1");
    assert!(
        core.has(11) && !core.has(12),
        "blocks before the fork point are kept"
    );
    mux.destroy();
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
