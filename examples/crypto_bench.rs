//! Throughput of the per-block crypto on this machine:
//! `cargo run --release --example crypto_bench`.

use std::hint::black_box;
use std::time::Instant;

use hypercore::crypto::{self, KeyPair};
use hypercore::encryption::{BlockEncryption, EncryptionOptions};

const BLOCK: usize = 512 * 1024;
const ROUNDS: usize = 400;

fn rate(label: &str, bytes: usize, f: impl FnMut()) {
    let mut f = f;
    f();
    let t = Instant::now();
    for _ in 0..ROUNDS {
        f();
    }
    let s = t.elapsed().as_secs_f64();
    let per_op = s * 1e6 / ROUNDS as f64;
    if bytes == 0 {
        println!(
            "{label:<34} {:>9.0} ops/s  {per_op:>9.2} µs/op",
            ROUNDS as f64 / s
        );
    } else {
        let mib = (bytes * ROUNDS) as f64 / (1024.0 * 1024.0);
        println!("{label:<34} {:>9.1} MiB/s  {per_op:>9.2} µs/op", mib / s);
    }
}

fn main() {
    println!("{} {}", std::env::consts::ARCH, std::env::consts::OS);
    let mut block = vec![7u8; BLOCK];
    rate("blake2b leaf hash, 512 KiB", BLOCK, || {
        black_box(crypto::block_node(3, black_box(&block)));
    });
    let enc = BlockEncryption::new(&[1; 32], &[2; 32], EncryptionOptions::default());
    rate("xsalsa20 encrypt, 512 KiB", BLOCK, || {
        enc.encrypt(5, black_box(&mut block[..]), 0);
    });
    let kp = KeyPair::from_seed(&[9; 32]);
    let msg = [3u8; 112];
    let sig = kp.sign(&msg);
    rate("ed25519 sign (tree signable)", 0, || {
        black_box(kp.sign(black_box(&msg)));
    });
    rate("ed25519 verify (tree signable)", 0, || {
        black_box(crypto::verify(black_box(&msg), &sig, &kp.public_key));
    });
}
