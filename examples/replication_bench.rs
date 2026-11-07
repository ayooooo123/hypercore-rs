//! Full-core download timing: `cargo run --release --example replication_bench -- rust|js 10000`.
//! CPU is process CPU during replication (both peers summed for JS); setup and content checks excluded.
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use hypercore::crypto::KeyPair;
use hypercore::storage::Store;
use hypercore::{Core, CoreOptions, GetOptions};
use peeroxide_dht::noise::generate_keypair;
use peeroxide_dht::secret_stream::SecretStream;
use protomux::{Mux, StreamInfo, memory};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;

fn cpu_seconds() -> f64 {
    #[repr(C)]
    struct Timespec {
        sec: std::ffi::c_long,
        nsec: std::ffi::c_long,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: std::ffi::c_int, time: *mut Timespec) -> std::ffi::c_int;
    }
    #[cfg(target_os = "macos")]
    const PROCESS_CPU: i32 = 12;
    #[cfg(not(target_os = "macos"))]
    const PROCESS_CPU: i32 = 2;
    let mut time = Timespec { sec: 0, nsec: 0 };
    assert_eq!(unsafe { clock_gettime(PROCESS_CPU, &mut time) }, 0);
    time.sec as f64 + time.nsec as f64 / 1e9
}

fn block(i: u64) -> Vec<u8> {
    let mut out = vec![0u8; 1024];
    let mut x = i.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1);
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
    }
    out
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).expect("rust|js");
    assert!(mode == "rust" || mode == "js");
    let n: u64 = args.get(2).expect("block count").parse().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let destination = Store::open(&tmp.path().join("reader")).unwrap();
    let mut child = None;
    let mut output = None;
    let mut writer = None;
    let mut source_store = None;
    let mut sender_mux = None;
    let (key, port) = if mode == "js" {
        let js_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js"));
        let mut process = Command::new("node")
            .arg("peer.js")
            .args([
                "write",
                tmp.path().join("js").to_str().unwrap(),
                &n.to_string(),
                "1024",
                &"11".repeat(32),
            ])
            .current_dir(js_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
        let key = lines.next_line().await.unwrap().unwrap();
        let key = key.strip_prefix("key ").unwrap();
        let key: [u8; 32] =
            std::array::from_fn(|i| u8::from_str_radix(&key[2 * i..2 * i + 2], 16).unwrap());
        let port = lines.next_line().await.unwrap().unwrap();
        let port = port.strip_prefix("port ").unwrap().to_owned();
        output = Some(lines);
        child = Some(process);
        (key, Some(port))
    } else {
        let store = Store::open(&tmp.path().join("writer")).unwrap();
        let core = Core::open(
            &store,
            CoreOptions {
                key_pair: Some(KeyPair::from_seed(&[0x11; 32])),
                ..Default::default()
            },
        )
        .unwrap();
        for start in (0..n).step_by(64) {
            core.append(&(start..n.min(start + 64)).map(block).collect::<Vec<_>>())
                .await
                .unwrap();
        }
        let key = *core.key();
        writer = Some(core);
        source_store = Some(store);
        (key, None)
    };
    let reader = Core::open(
        &destination,
        CoreOptions {
            key: Some(key),
            ..Default::default()
        },
    )
    .unwrap();
    let _reader_session = reader.session(true);
    let _writer_session = writer.as_ref().map(|core| core.session(true));
    if let Some(process) = &mut child {
        process
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"cpu\n")
            .await
            .unwrap();
    }
    let js_start = if let Some(lines) = &mut output {
        lines
            .next_line()
            .await
            .unwrap()
            .unwrap()
            .strip_prefix("cpu ")
            .unwrap()
            .parse::<f64>()
            .unwrap()
    } else {
        0.0
    };
    let start_cpu = cpu_seconds();
    let started = Instant::now();
    let receiver_mux = if let Some(port) = port {
        let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        Mux::from_secret_stream(
            SecretStream::new(true, tcp, generate_keypair())
                .await
                .unwrap(),
        )
    } else {
        let ((ar, aw), (br, bw)) = memory::duplex(64);
        let a = Mux::new(
            ar,
            aw,
            StreamInfo {
                is_initiator: true,
                handshake_hash: Some([7; 64]),
                remote_public_key: None,
            },
        );
        let b = Mux::new(
            br,
            bw,
            StreamInfo {
                is_initiator: false,
                handshake_hash: Some([7; 64]),
                remote_public_key: None,
            },
        );
        writer.as_ref().unwrap().replicate(&a);
        sender_mux = Some(a);
        b
    };
    reader.replicate(&receiver_mux);
    tokio::time::timeout(Duration::from_secs(120), async {
        reader.update(None).await.unwrap();
        assert_eq!(reader.length(), n);
        assert!(reader.download(0, Some(n), false).await.unwrap());
    })
    .await
    .expect("full download timed out");
    let wall = started.elapsed().as_secs_f64();
    let rust_cpu = cpu_seconds() - start_cpu;
    let js_cpu = if let Some(process) = &mut child {
        process
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"cpu\n")
            .await
            .unwrap();
        output
            .as_mut()
            .unwrap()
            .next_line()
            .await
            .unwrap()
            .unwrap()
            .strip_prefix("cpu ")
            .unwrap()
            .parse::<f64>()
            .unwrap()
            - js_start
    } else {
        0.0
    };
    println!(
        "{mode}->rust blocks={n} bytes={} wall_s={wall:.6} cpu_s={:.6} rust_cpu_s={rust_cpu:.6} js_cpu_s={js_cpu:.6}",
        n * 1024,
        rust_cpu + js_cpu
    );
    assert_eq!(reader.contiguous_length(), n);
    for i in 0..n {
        assert_eq!(
            reader
                .get(
                    i,
                    GetOptions {
                        wait: false,
                        ..Default::default()
                    }
                )
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            block(i)
        );
    }
    receiver_mux.destroy();
    if let Some(mux) = sender_mux {
        mux.destroy();
    }
    if let Some(mut process) = child {
        process.kill().await.unwrap();
        process.wait().await.unwrap();
    }
    drop(source_store);
}
