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
  truncate, clear, purge, and sessions. Sessions opened with `active: false` don't keep the core
  downloading; once no active session remains the replicator lingers 20–40 s (as JS does) and lets
  idle channels close.
- `storage`: private to each peer. One redb database per directory holds headers, tree nodes,
  bitfield pages and small blocks; blocks of 16 KiB or more go to append-only segment files (128
  blocks per file), deleted once every block in them is cleared.

Not ported: push mode, repair mode, protocol extensions, block-list ranges, sessions on named
branches/snapshots/atoms, and RTT-scaled inflight windows (the JS non-UDX window of 48 is used).

## Compatibility

- `tests/tree_fixtures.rs`: a core written by npm hypercore 11.39.5 (`fixtures/gen`). Tree hashes,
  roots, nodes, byte offsets and signatures match at every length; 100+ JS proofs are reproduced
  byte for byte and verify with the same outcome as in JS (including the requests JS rejects).
  Fork resolution finds the JS fork point.
- `src/encryption.rs` checks 120 vectors from `hypercore/lib/default-encryption` (`fixtures/encryption`).
- `tests/replicate_js.rs` (needs `npm install` in `tests/js`): npm hypercore and hypercore-rs over
  secret-stream on TCP. JS writes and Rust reads, Rust writes and JS reads, with SHA-256 of every
  byte compared; an encrypted JS core replicates to Rust and Rust follows a JS truncation. The size
  is `HC_INTEROP_MB` (default 32); the 1 GiB run is
  `HC_INTEROP_MB=1024 cargo test --release --test replicate_js -- --include-ignored`.

Where JS has a bug the port does not copy it: JS returns `NaN` for byte offsets past the first
root, and so refuses (or silently drops) some valid seeks; Rust answers them.

## License

MIT OR Apache-2.0
