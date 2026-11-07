# hypercore-rs

[Hypercore](https://github.com/holepunchto/hypercore) 11 for Rust and tokio: signed, sparse,
append-only logs that replicate with npm hypercore peers byte for byte.

```rust,no_run
use hypercore::{Core, CoreOptions, GetOptions};
use hypercore::crypto::KeyPair;
use hypercore::storage::Store;

# async fn demo(mux: protomux::Mux) -> Result<(), Box<dyn std::error::Error>> {
let store = Store::open("./storage".as_ref())?;
let core = Core::open(&store, CoreOptions { key_pair: Some(KeyPair::generate()), ..Default::default() })?;
core.append(&[b"hello".as_slice(), b"world"]).await?;

// A reader elsewhere: open by key, keep a session active, replicate over a
// Protomux connection (e.g. `Mux::from_secret_stream` on a peeroxide stream).
let reader = Core::open(&store, CoreOptions { key: Some(*core.key()), ..Default::default() })?;
let _session = reader.session(true);
reader.replicate(&mux);
reader.update(None).await?;
let block = reader.get(1, GetOptions::default()).await?;
# Ok(()) }
```

## What is here

- `merkle`: the v11 flat merkle tree, proof generation (block, hash, seek, upgrade, additional
  nodes) and verification, fork (reorg) resolution, byte offsets and seeks.
- `verifier`: manifests v0–v3, single signers, quorum multisigs with patches, prologues, and
  pre-manifest ("compat") cores. Signatures are deterministic Ed25519, identical to JS.
- `encryption`: hypercore 11 block encryption (BLAKE2b key derivation, XSalsa20, the 8-byte padding
  that carries the blinded fork).
- `replicator`: the `hypercore/alpha` Protomux protocol: sync, request/data/noData, cancel,
  want/unwant, bitfield and range messages, inflight windows, eager upgrades, sparse downloads,
  seeks, reorgs and conflict detection. Block takeover follows the hotswap rule: a busy peer only
  re-requests a block once it has been in flight three times that peer's block round trip; an idle
  peer takes any.
- `core`: append, get (local or from peers, with timeouts), update, download ranges, seek,
  truncate, clear, purge, and sessions. Inactive sessions do not keep downloads active; closing the
  last session shuts down its physical core once any detached exclusive lease is released.
  `replication_closed().await` waits for its actor to release channels and pairers;
  `same_instance()` distinguishes physical generations of the same key.
- `storage`: npm `hypercore-storage`'s RocksDB layout, read and written by
  [`hypercore-storage-rs`](../hypercore-storage-rs): one `corestore` column family holds the store
  head, the discovery-key index, aliases, groups, and per core the auth row, head, hints, every
  block, tree node, bitfield page and user-data entry. A directory written by corestore 7.16.1 on
  node can be opened here and the reverse, so both stacks can take turns on one directory.
- `Core::events` exposes append, replicated download, truncation, peer and close notifications;
  `subscribe` remains available for head changes. User metadata is persisted with `set_user_data`,
  and `GetOptions::raw` returns stored ciphertext without decrypting.
- `RequestBag` cancels pending and subsequent reads with a sticky reason; pass it through
  `GetOptions::bag` or `download_with_bag`. Cancellation is scoped to that bag.
- `Core::replicate` registers its Protomux pairer synchronously, so callers may mark the mux
  ready immediately, including when the remote core open arrived during setup. Closed cores
  leave pairing to corestore so a stored core can be reopened on demand.

Not ported: push mode, repair mode, protocol extensions, block-list ranges, sessions on named
branches/snapshots/atoms, and RTT-scaled inflight windows (the JS non-UDX window of 48 is used).

## Compatibility

- `tests/tree_fixtures.rs`: a core written by npm hypercore 11.40.3 (`fixtures/gen`). Tree hashes,
  roots, nodes, byte offsets and signatures match at every length; 100+ JS proofs are reproduced
  byte for byte and verify with the same outcome as in JS (including the requests JS rejects).
  Fork resolution finds the JS fork point.
- `src/encryption.rs` checks 120 vectors from `hypercore/lib/default-encryption` (`fixtures/encryption`).
- `tests/replicate_dht.rs` (needs `npm install` in `tests/js`): npm hypercore on Hyperswarm against
  hypercore-rs on a peeroxide swarm, on a local `hyperdht/testnet`: topic discovery, holepunch
  handshake, UDX, secret-stream, as the apps run it. JS writes and Rust reads, Rust writes and JS
  reads, with SHA-256 of every byte compared. The size is `HC_INTEROP_MB` (default 32); the 1 GiB
  run is `HC_INTEROP_MB=1024 cargo test --release --test replicate_dht -- --include-ignored --test-threads 1`.
  It needs the peeroxide fork next to this repo (`../peeroxide`, patched in `Cargo.toml`).
  The same suite includes Rust-to-Rust and JS-to-JS baselines. `PERF` lines exclude
  discovery/setup and byte verification from transfer throughput; CPU-seconds per
  GiB use the reader process for mixed/JS runs and both endpoints for Rust-to-Rust.
  CPU reporting requires Unix `ps`; these opt-in runs use private temporary stores.
- `tests/storage_switch.rs` (needs `npm install` in `tests/js`): npm corestore 7.16.1 writes a
  store with ten cores, then JS and Rust take turns opening that same directory, appending, writing
  user data, and comparing every core's length, tree and blocks. `tests/storage_crash.rs` kills a
  writer mid-append and checks the directory still opens on both sides. Neither stack has a private
  format: the directory is the interchange format.
- `tests/replicate_js.rs`: the same over secret-stream on TCP, plus an encrypted JS core and a JS
  truncation (reorg). A fast regression check that doesn't involve the DHT.
- `cargo run --release --example crypto_bench` measures the per-block crypto. On an Apple M-series
  laptop (aarch64), it does blake2b leaf hashing at ~930 MiB/s, XSalsa20 at ~600 MiB/s (512 KiB
  blocks), ed25519 signing at ~36k/s and verifying at ~24k/s.
- `cargo run --release --example storage_bench -- <dir> 1024` appends and reads back 1 GiB of
  512 KiB blocks through `Core`; the numbers are in
  [`hypercore-storage-rs`](../hypercore-storage-rs#throughput).
- `cargo run --release --example replication_bench -- rust 10000` downloads an entire
  10000-block core (1 KiB deterministic blocks) over an in-memory Protomux stream;
  replace `rust` with `js` for npm Hypercore over loopback TCP/secret-stream.
  Repeat with 1000 blocks and without `--release` for the dev profile. It reports
  transfer wall time and process CPU-seconds, excluding source creation and the
  subsequent every-block content check. CPU includes both Rust endpoints for
  Rust-to-Rust, or Rust plus the JS sender for JS-to-Rust.

Replication tree reads batch missing ancestors, proof siblings, and roots. The
storage layer shares a bounded tree-node LRU across cores in a store. Shared
block verification reuses authenticated nodes from earlier proofs in the same
write batch; a parent hash is reused only when both children match exactly, and
matching authenticated nodes are persisted only once per batch.

Local arm64 Mac, 2026-11-07: medians of three interleaved fresh-core runs with
1 KiB blocks. Baseline: hypercore `7e0f155`, storage `82e8cd9`; unchanged
cryptography, stream, and storage format. These are synthetic local downloads,
not an Android or real-network CPU certification.

| Profile | Transfer | Blocks | CPU seconds before → after | Wall seconds before → after |
| --- | --- | ---: | ---: | ---: |
| release | Rust → Rust | 1000 | 0.015076 → 0.012769 | 0.010901 → 0.009581 |
| release | Rust → Rust | 10000 | 0.177226 → 0.147845 | 0.120973 → 0.098150 |
| release | JS → Rust | 1000 | 0.153970 → 0.152329 | 0.072305 → 0.066292 |
| release | JS → Rust | 10000 | 1.104757 → 1.076564 | 0.478879 → 0.456003 |
| dev | Rust → Rust | 1000 | 0.155082 → 0.154799 | 0.134075 → 0.137070 |
| dev | Rust → Rust | 10000 | 1.750974 → 1.663616 | 1.355556 → 1.360207 |
| dev | JS → Rust | 1000 | 0.457095 → 0.458508 | 0.306859 → 0.298475 |
| dev | JS → Rust | 10000 | 4.099539 → 4.037683 | 2.879966 → 2.808512 |

The tree-node LRU is one approximately 4 MiB budget per Store/Corestore, shared
by all its cores and sessions, not per core. An 8192-node cache regressed the
10000-block workload after eviction; the final bound is 32768 nodes.
For 10000 blocks, `/usr/bin/time -l` peak RSS (including setup and content
validation) was **41.88 → 47.66 MiB** release and **48.45 → 54.47 MiB** dev for
Rust → Rust, which uses two separate stores. JS → Rust command peak RSS,
including the sender child, was **131.00 → 133.17 MiB** release and
**131.14 → 131.84 MiB** dev; it does not isolate the Rust reader's memory.
Time the built example, not `cargo`, to reproduce command peak RSS.

Where JS has a bug the port does not copy it: JS returns `NaN` for byte offsets past the first
root, and so refuses (or silently drops) some valid seeks; Rust answers them.

## License

MIT OR Apache-2.0
