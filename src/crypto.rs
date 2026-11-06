//! Hashes, signatures and capability derivations from `hypercore-crypto` and
//! `hypercore/lib/caps.js`. All hashes are BLAKE2b-256, as libsodium's
//! `crypto_generichash`.

use std::sync::LazyLock;

use blake2b_simd::Params;
use compact_encoding::hypercore::{Manifest, Node};
use compact_encoding::{Codec, Writer};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

const LEAF_TYPE: u8 = 0;
const PARENT_TYPE: u8 = 1;
const ROOT_TYPE: u8 = 2;

fn hasher(key: &[u8]) -> blake2b_simd::State {
    Params::new().hash_length(32).key(key).to_state()
}

/// `crypto_generichash_batch(out, parts)`.
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    keyed_hash(&[], parts)
}

/// `crypto_generichash_batch(out, parts, key)`.
pub fn keyed_hash(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = hasher(key);
    for p in parts {
        h.update(p);
    }
    h.finalize().as_bytes().try_into().expect("32-byte digest")
}

/// `hypercore-crypto` `namespace(name, count)`.
pub fn namespace(name: &[u8], count: u8) -> Vec<[u8; 32]> {
    let mut ns = [0u8; 33];
    ns[..32].copy_from_slice(&hash(&[name]));
    (0..count)
        .map(|i| {
            ns[32] = i;
            hash(&[&ns])
        })
        .collect()
}

struct Caps {
    tree: [u8; 32],
    replicate_initiator: [u8; 32],
    replicate_responder: [u8; 32],
    manifest: [u8; 32],
    default_namespace: [u8; 32],
    default_encryption: [u8; 32],
}

static CAPS: LazyLock<Caps> = LazyLock::new(|| {
    let n = namespace(b"hypercore", 6);
    Caps {
        tree: n[0],
        replicate_initiator: n[1],
        replicate_responder: n[2],
        manifest: n[3],
        default_namespace: n[4],
        default_encryption: n[5],
    }
});

pub fn default_namespace() -> [u8; 32] {
    CAPS.default_namespace
}

pub fn default_encryption_namespace() -> [u8; 32] {
    CAPS.default_encryption
}

/// Leaf hash of a block.
pub fn data_hash(data: &[u8]) -> [u8; 32] {
    hash(&[&[LEAF_TYPE], &(data.len() as u64).to_le_bytes(), data])
}

pub fn block_node(index: u64, data: &[u8]) -> Node {
    Node {
        index,
        size: data.len() as u64,
        hash: data_hash(data),
    }
}

/// Parent hash; the children are ordered by index.
pub fn parent_hash(a: &Node, b: &Node) -> [u8; 32] {
    let (a, b) = if a.index > b.index { (b, a) } else { (a, b) };
    hash(&[
        &[PARENT_TYPE],
        &(a.size + b.size).to_le_bytes(),
        &a.hash,
        &b.hash,
    ])
}

pub fn parent_node(index: u64, a: &Node, b: &Node) -> Node {
    Node {
        index,
        size: a.size + b.size,
        hash: parent_hash(a, b),
    }
}

/// Hash of a tree given its full roots.
pub fn tree_hash(roots: &[Node]) -> [u8; 32] {
    let mut h = hasher(&[]);
    h.update(&[ROOT_TYPE]);
    for r in roots {
        h.update(&r.hash);
        h.update(&r.index.to_le_bytes());
        h.update(&r.size.to_le_bytes());
    }
    h.finalize().as_bytes().try_into().expect("32-byte digest")
}

pub fn discovery_key(key: &[u8; 32]) -> [u8; 32] {
    keyed_hash(key, &[b"hypercore"])
}

/// The capability each side proves in the replication handshake.
pub fn replicate_capability(is_initiator: bool, key: &[u8; 32], handshake_hash: &[u8]) -> [u8; 32] {
    let ns = if is_initiator {
        &CAPS.replicate_initiator
    } else {
        &CAPS.replicate_responder
    };
    keyed_hash(handshake_hash, &[ns, key])
}

/// What a signer signs for manifest version >= 1 (and v0 with a namespace).
pub fn tree_signable(ctx: &[u8; 32], tree_hash: &[u8; 32], length: u64, fork: u64) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[..32].copy_from_slice(&CAPS.tree);
    out[32..64].copy_from_slice(ctx);
    out[64..96].copy_from_slice(tree_hash);
    out[96..104].copy_from_slice(&length.to_le_bytes());
    out[104..].copy_from_slice(&fork.to_le_bytes());
    out
}

/// Pre-manifest ("compat") signable; `no_header` is the legacy-legacy form.
pub fn tree_signable_compat(
    tree_hash: &[u8; 32],
    length: u64,
    fork: u64,
    no_header: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    if !no_header {
        out.extend_from_slice(&CAPS.tree);
    }
    out.extend_from_slice(tree_hash);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&fork.to_le_bytes());
    out
}

/// A core's key: the hash of its manifest.
pub fn manifest_hash(manifest: &Manifest) -> [u8; 32] {
    let mut w = Writer::with_capacity(manifest.encoded_len());
    manifest.encode(&mut w);
    hash(&[&CAPS.manifest, &w.into_vec()])
}

/// Ed25519 key pair in libsodium layout: `secret_key = seed ++ public_key`.
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 64],
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// `crypto_sign_seed_keypair`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(seed);
        let public_key = sk.verifying_key().to_bytes();
        let mut secret_key = [0u8; 64];
        secret_key[..32].copy_from_slice(seed);
        secret_key[32..].copy_from_slice(&public_key);
        Self {
            public_key,
            secret_key,
        }
    }

    pub fn generate() -> Self {
        Self::from_seed(&rand::random())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let seed: [u8; 32] = self.secret_key[..32].try_into().expect("seed");
        SigningKey::from_bytes(&seed).sign(message).to_bytes()
    }
}

/// `crypto_sign_verify_detached`.
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8; 32]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(pk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    pk.verify_strict(message, &Signature::from_bytes(&sig))
        .is_ok()
}
