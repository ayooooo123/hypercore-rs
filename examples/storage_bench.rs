//! Storage throughput through `Core`: appends and reads 512 KiB blocks.
//!
//! `cargo run --release --example storage_bench -- <dir> <mib>`

use std::path::PathBuf;
use std::time::Instant;

use hypercore::crypto::KeyPair;
use hypercore::storage::Store;
use hypercore::{Core, CoreOptions, GetOptions};

const BLOCK: usize = 512 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().unwrap_or_else(|| {
        std::env::temp_dir()
            .join("hypercore-storage-bench")
            .display()
            .to_string()
    }));
    let mib: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1024);
    let _ = std::fs::remove_dir_all(&dir);

    let store = Store::open(&dir)?;
    let core = Core::open(
        &store,
        CoreOptions {
            key_pair: Some(KeyPair::from_seed(&[1; 32])),
            ..Default::default()
        },
    )?;

    let block = vec![7u8; BLOCK];
    let count = mib * 1024 * 1024 / BLOCK as u64;

    // 16 blocks per append: one write batch per 8 MiB.
    let started = Instant::now();
    let mut appended = 0;
    while appended < count {
        let batch = vec![&block[..]; 16.min(count - appended) as usize];
        core.append(&batch).await?;
        appended += batch.len() as u64;
    }
    let write = started.elapsed();

    let started = Instant::now();
    let mut read = 0u64;
    for index in 0..count {
        let value = core
            .get(
                index,
                GetOptions {
                    wait: false,
                    ..Default::default()
                },
            )
            .await?
            .expect("block");
        read += value.len() as u64;
    }
    let read_time = started.elapsed();

    let written = (count * BLOCK as u64) as f64 / (1024.0 * 1024.0);
    println!("{} {}", std::env::consts::ARCH, std::env::consts::OS);
    println!(
        "wrote {written:.0} MiB of {} KiB blocks in {write:.2?} ({:.0} MiB/s), read in {read_time:.2?} ({:.0} MiB/s)",
        BLOCK / 1024,
        written / write.as_secs_f64(),
        (read as f64 / (1024.0 * 1024.0)) / read_time.as_secs_f64(),
    );

    drop(core);
    store.close();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
