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
  `Core::inflight_requests().await` snapshots outstanding wire requests across live peers
  without counting queued ranges or adding per-block atomics.
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
branches/snapshots/atoms. Hosts attach live UDX RTT with `Mux::set_udx_rtt` before replication:
the request window then uses JS's 50 ms latency scaling and live peer-count factor,
bounded by the configured range. Other transports retain the JS non-UDX limit.

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
  The WAL-free cache regression exits a subprocess without destructors after a
  flushed checkpoint and an unflushed batch. Reopening loses only the tail; every
  block still advertised locally verifies against its signed Merkle tree.
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

## Concurrent cores and idle memory

`cargo run --release --example multi_core_bench -- 32 10000 4 4` downloads
32 cores of 10000 1 KiB blocks over four in-memory Protomux connections on four
Tokio workers. Arguments are cores, blocks, connections and workers; use zero
blocks to measure idle open cores. The harness uses two real Corestores,
verifies every downloaded block, and counts live/peak Rust allocation bytes and
allocation calls. Native RocksDB allocations are excluded from those counters;
measure the built binary with `/usr/bin/time -l` for whole-process peak RSS.
Reported replication wall time excludes setup and content validation.

Release measurements on an arm64 Mac, before and after the storage-lock,
lazy-event/cache and bitfield changes (three-run medians unless marked †):

| Cores × blocks | Connections / workers | Replication wall seconds | Process CPU seconds | Peak RSS MiB |
|---|---|---|---|---|
| 8 × 1000 | 1 / 1 | 0.1243 → 0.0879 | 0.19 → 0.19 | 45.72 → 46.92 |
| 8 × 1000 | 1 / 4 | 0.1268 → 0.0781 | 0.36 → 0.42 | 47.63 → 49.06 |
| 8 × 1000 | 4 / 4 | 0.1316 → 0.0936 | 0.41 → 0.50 | 52.44 → 51.81 |
| 32 × 10000 | 1 / 1 † | 18.877 → 15.633 | 27.82 → 23.47 | 93.47 → 93.58 |
| 32 × 10000 | 1 / 4 † | 17.608 → 8.145 | 38.55 → 39.17 | 92.92 → 105.11 |
| 32 × 10000 | 4 / 1 † | 24.174 → 15.033 | 32.32 → 23.19 | 99.28 → 102.20 |
| 32 × 10000 | 4 / 4 | 14.582 → 6.659 | 30.88 → 34.66 | 108.41 → 118.22 |
| 1 × 10000 | 1 / 1 | 0.1198 → 0.1182 | 0.22 → 0.22 | 48.13 → 47.02 |

† One run per revision. Process CPU/RSS cover the entire command, including
setup and validation. The counting allocator adds overhead to both revisions.
More concurrency improves bulk latency, not necessarily CPU or peak RSS.
Four workers now beat one by 1.92× on 32 cores/one connection; before, 1.07×.
No parallelism was added within a connection or a core's ordered replication actor.
The shared tree-node LRU remains capped at 32768 nodes (about 4 MiB).

With 128 empty cores on each of two stores, aggregate core/session Rust heap falls
from 6315504 to 3137008 bytes; total live Rust heap falls from 14895929 to
3198761 bytes, and command peak RSS from 17.05 to 13.56 MiB. Event rings are
allocated only on the first `events()` subscription, retaining their 256-event
capacity. The tree cache starts empty and grows within its existing cap.
Discarding already-persisted bitfield dirtiness without encoding pages again,
measured separately, reduced 8-core/1000-block/one-worker allocation calls from
313185 to 293374 and wall time from 0.1243 to 0.1097 seconds.

The original `replication_bench` (two workers, three release runs) stayed close:
Rust→Rust 1000/10000-block wall times 0.00881/0.09543 → 0.00849/0.09050 s;
JS→Rust 0.07124/0.42916 → 0.06832/0.42962 s. Combined peer replication CPU
for JS→Rust 10000 blocks was 1.02894 → 1.00586 s.
Dev-profile sanity: eight cores/1000 blocks/one connection took 0.6636 s with
one worker and 0.2408 s with four; one 10000-block core took 0.7189 s with four.

Rejected as a blanket tuning rule: four workers for one core (one vs four workers:
0.1182 vs 0.1162 s, process CPU 0.22 vs 0.25 s), or extra connections for eight
cores (one vs four connections,
four workers: 0.0781 vs 0.0936 s). No per-crate pools, request-per-task expansion,
smaller cache cap, wire/storage changes, or speculative peer-state rewrites.
Corestore, Protomux and wakeup lifecycle logic is unchanged. All five crates'
`cargo test -- --include-ignored` and `cargo clippy --all-targets -- -D warnings`
pass, including storage switching, JS interop and pairing/teardown regressions.

## License

MIT OR Apache-2.0
