//! Multi-core full downloads: `cargo run --release --example multi_core_bench -- 8 1000 1 4`.
//! Arguments are cores, blocks per core, connections and runtime workers; zero blocks measures idle cores.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use corestore::{Corestore, GetOptions};
use hypercore::GetOptions as BlockOptions;
use protomux::{Mux, StreamInfo, memory};

struct Allocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

fn allocated(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
    ALLOCS.fetch_add(1, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, size) };
        if !new.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            allocated(size);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|s| s.parse().unwrap())
        .collect();
    let [cores, blocks, connections, workers] = args.as_slice() else {
        panic!("expected cores blocks connections workers");
    };
    assert!(*cores > 0 && (1..=4).contains(connections) && (1..=4).contains(workers));
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(*workers)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(*cores, *blocks, *connections, *workers));
}

async fn run(cores: usize, blocks: usize, connections: usize, workers: usize) {
    let tmp = tempfile::tempdir().unwrap();
    let source = Corestore::open(&tmp.path().join("source")).unwrap();
    let destination = Corestore::open(&tmp.path().join("destination")).unwrap();
    let mut writers = Vec::new();
    let mut readers = Vec::new();
    let baseline = LIVE.load(Ordering::Relaxed);
    for i in 0..cores {
        let writer = source
            .get(GetOptions::name(format!("core-{i}")))
            .await
            .unwrap();
        for start in (0..blocks).step_by(64) {
            let values: Vec<_> = (start..blocks.min(start + 64))
                .map(|index| vec![(index % 251) as u8; 1024])
                .collect();
            writer.append(&values).await.unwrap();
        }
        let reader = destination
            .get(GetOptions::key(*writer.key()))
            .await
            .unwrap();
        writers.push(writer);
        readers.push(reader);
    }
    let idle = LIVE.load(Ordering::Relaxed).saturating_sub(baseline);
    let allocations = ALLOCS.load(Ordering::Relaxed);
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let started = Instant::now();
    let mut muxes = Vec::new();
    if blocks > 0 {
        for _ in 0..connections {
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
            source.replicate(&a);
            destination.replicate(&b);
            muxes.extend([a, b]);
        }
        let mut tasks = tokio::task::JoinSet::new();
        for reader in &readers {
            let core = reader.core().clone();
            tasks.spawn(async move {
                core.update(None).await.unwrap();
                assert!(core.download(0, Some(blocks as u64), false).await.unwrap());
                assert_eq!(core.contiguous_length(), blocks as u64);
            });
        }
        tokio::time::timeout(Duration::from_secs(300), async {
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        })
        .await
        .expect("multi-core download timed out");
    }
    println!(
        "cores={cores} blocks={blocks} connections={connections} workers={workers} wall_s={:.6} idle_rust_bytes={idle} peak_rust_bytes={} replication_allocs={}",
        started.elapsed().as_secs_f64(),
        PEAK.load(Ordering::Relaxed),
        ALLOCS.load(Ordering::Relaxed) - allocations
    );
    for reader in &readers {
        for index in 0..blocks {
            let value = reader
                .get(
                    index as u64,
                    BlockOptions {
                        wait: false,
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(value.as_ref(), vec![(index % 251) as u8; 1024]);
        }
    }
    for mux in muxes {
        mux.destroy();
    }
    source.close().await;
    destination.close().await;
}
