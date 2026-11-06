//! Manifest-driven signature checks (`hypercore/lib/verifier.js` and
//! `multisig.js`): single signers, quorum multisigs with patches, prologues,
//! and pre-manifest ("compat") cores.

use std::collections::HashMap;

use compact_encoding::hypercore::Data;
use compact_encoding::hypercore::{
    DataUpgrade, HashAlgo, Manifest, MultiSignatureV0, MultiSignatureV1, MultisigInput, Node,
    Prologue, SignatureAlgo, Signer,
};
use compact_encoding::{Bytes, decode, encode};

use crate::crypto::{self, KeyPair};
use crate::flat_tree::{self, Iter};
use crate::merkle::Batch;

/// One signer's input to [`Verifier::assemble`].
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub signer: u64,
    pub signature: [u8; 64],
    /// Number of blocks this signature extends past the batch it is checked against.
    pub patch: u64,
    pub nodes: Option<Vec<Node>>,
}

#[derive(Debug, Clone)]
struct SignerKey {
    public_key: [u8; 32],
    namespace: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Verifier {
    pub manifest_hash: [u8; 32],
    pub compat: bool,
    pub version: u64,
    pub allow_patch: bool,
    pub quorum: u64,
    pub prologue: Option<Prologue>,
    legacy: bool,
    signers: Vec<SignerKey>,
}

impl Verifier {
    /// `new Verifier(manifestHash, manifest, { legacy })`; compat is inferred as in JS.
    pub fn new(manifest_hash: [u8; 32], manifest: &Manifest, legacy: bool) -> Self {
        let compat = is_compat(&manifest_hash, manifest);
        Self {
            manifest_hash,
            compat,
            version: if compat { 0 } else { manifest.version },
            allow_patch: !compat && manifest.allow_patch,
            quorum: if compat { 1 } else { manifest.quorum },
            prologue: if compat {
                None
            } else {
                manifest.prologue.clone()
            },
            legacy,
            signers: manifest
                .signers
                .iter()
                .map(|s| SignerKey {
                    public_key: s.public_key,
                    namespace: s.namespace,
                })
                .collect(),
        }
    }

    pub fn from_manifest(manifest: &Manifest) -> Self {
        Self::new(crypto::manifest_hash(manifest), manifest, false)
    }

    fn signable(&self, signer: &SignerKey, batch: &Batch) -> Vec<u8> {
        if self.compat {
            return batch.signable_compat(self.legacy);
        }
        let ctx = if self.version == 0 {
            &signer.namespace
        } else {
            &self.manifest_hash
        };
        batch.signable(ctx).to_vec()
    }

    fn signer_verifies(&self, i: usize, batch: &Batch, signature: &[u8]) -> bool {
        let s = &self.signers[i];
        crypto::verify(&self.signable(s, batch), signature, &s.public_key)
    }

    pub fn verify(&self, batch: &Batch, signature: Option<&[u8]>) -> bool {
        if self.version == 0 {
            let Some(sig) = signature else { return false };
            if self.compat || (!self.allow_patch && self.signers.len() == 1) {
                return self.signer_verifies(0, batch, sig);
            }
            return self.verify_multi(batch, sig);
        }
        if let Some(p) = &self.prologue
            && batch.length <= p.length
        {
            return batch.length == p.length && batch.hash() == p.hash;
        }
        signature.is_some_and(|s| self.verify_multi(batch, s))
    }

    fn inflate(&self, signature: &[u8]) -> Option<MultiSignatureV1> {
        let bytes = Bytes::copy_from_slice(signature);
        if self.version >= 1 {
            return decode(bytes).ok();
        }
        let v0: MultiSignatureV0 = decode(bytes).ok()?;
        Some(MultiSignatureV1 {
            proofs: v0
                .proofs
                .into_iter()
                .map(|p| MultisigInput {
                    signer: p.signer,
                    signature: p.signature,
                    patch: p.patch.map_or(0, |p| p.length),
                })
                .collect(),
            patch: v0.patch,
        })
    }

    fn verify_multi(&self, batch: &Batch, signature: &[u8]) -> bool {
        if self.quorum == 0 {
            return false;
        }
        let Some(MultiSignatureV1 { proofs, patch }) = self.inflate(signature) else {
            return false;
        };
        if (proofs.len() as u64) < self.quorum {
            return false;
        }
        let nodes: Option<HashMap<u64, Node>> = (self.allow_patch && !patch.is_empty())
            .then(|| patch.iter().map(|n| (n.index, *n)).collect());
        let mut tried = vec![false; self.signers.len()];

        for inp in proofs.iter().take(self.quorum as usize) {
            let mut patched;
            let mut tree = batch;
            if inp.patch != 0 && self.allow_patch {
                patched = batch.clone();
                let Some(upgrade) = generate_upgrade(nodes.as_ref(), batch.length, inp.patch)
                else {
                    return false;
                };
                let proof = Data {
                    fork: patched.fork,
                    upgrade: Some(upgrade),
                    ..Default::default()
                };
                if !matches!(patched.verify_upgrade(&proof), Ok(true)) {
                    return false;
                }
                tree = &patched;
            }
            let i = inp.signer as usize;
            if i >= self.signers.len() || tried[i] {
                return false;
            }
            tried[i] = true;
            if !self.signer_verifies(i, tree, &inp.signature) {
                return false;
            }
        }
        true
    }

    /// Signs `batch` with `key_pair`, in the format this manifest expects.
    pub fn sign(&self, batch: &Batch, key_pair: &KeyPair) -> Option<Bytes> {
        let i = self
            .signers
            .iter()
            .position(|s| s.public_key == key_pair.public_key)?;
        let signature = key_pair.sign(&self.signable(&self.signers[i], batch));
        if self.signers.len() != 1 || self.version == 0 {
            return Some(Bytes::copy_from_slice(&signature));
        }
        Some(self.assemble(&[PartialSignature {
            signer: 0,
            signature,
            patch: 0,
            nodes: None,
        }]))
    }

    pub fn assemble(&self, inputs: &[PartialSignature]) -> Bytes {
        if self.version == 0 {
            assemble_v0(inputs)
        } else {
            assemble(inputs)
        }
    }
}

fn is_compat(key: &[u8; 32], manifest: &Manifest) -> bool {
    manifest.signers.len() == 1 && &manifest.signers[0].public_key == key
}

/// `Verifier.defaultSignerManifest`.
pub fn default_signer_manifest(public_key: [u8; 32]) -> Manifest {
    Manifest {
        version: 1,
        hash: HashAlgo::Blake2b,
        allow_patch: false,
        quorum: 1,
        signers: vec![Signer {
            signature: SignatureAlgo::Ed25519,
            namespace: crypto::default_namespace(),
            public_key,
        }],
        prologue: None,
        linked: None,
        user_data: None,
    }
}

/// Whether `manifest` hashes to `key`.
pub fn is_valid_manifest(key: &[u8; 32], manifest: &Manifest) -> bool {
    &crypto::manifest_hash(manifest) == key
}

fn generate_upgrade(
    patch: Option<&HashMap<u64, Node>>,
    start: u64,
    length: u64,
) -> Option<DataUpgrade> {
    let patch = patch?;
    let mut nodes: Option<Vec<Node>> = None;
    let from = start * 2;
    let to = from + length * 2;
    let mut ite = Iter::new(0);
    while ite.full_root(to) {
        if ite.index + ite.factor / 2 < from {
            ite.next_tree();
            continue;
        }
        if nodes.is_none() && from >= 2 && ite.contains(from - 2) {
            let mut out = vec![];
            let root = ite.index;
            let target = from - 2;
            ite.seek(target);
            while ite.index != root {
                ite.sibling();
                if ite.index > target {
                    out.push(*patch.get(&ite.index)?);
                }
                ite.parent();
            }
            nodes = Some(out);
            ite.next_tree();
            continue;
        }
        nodes
            .get_or_insert_with(Vec::new)
            .push(*patch.get(&ite.index)?);
        ite.next_tree();
    }
    Some(DataUpgrade {
        start,
        length,
        nodes: nodes.unwrap_or_default(),
        additional_nodes: vec![],
        signature: None,
    })
}

fn assemble(inputs: &[PartialSignature]) -> Bytes {
    let mut patch: Vec<Node> = vec![];
    for u in inputs {
        for n in u.nodes.iter().flatten() {
            if !patch.iter().any(|p| p.index == n.index) {
                patch.push(*n);
            }
        }
    }
    let proofs = inputs
        .iter()
        .map(|u| MultisigInput {
            signer: u.signer,
            signature: u.signature,
            patch: u.patch,
        })
        .collect();
    encode(&MultiSignatureV1 { proofs, patch })
}

fn assemble_v0(inputs: &[PartialSignature]) -> Bytes {
    use compact_encoding::hypercore::{MultisigInputV0, PatchV0};
    let mut patch: Vec<Node> = vec![];
    let proofs = inputs
        .iter()
        .map(|u| MultisigInputV0 {
            signer: u.signer,
            signature: u.signature,
            patch: (u.patch != 0).then(|| {
                let nodes = u.nodes.as_deref().unwrap_or_default();
                let start = nodes
                    .last()
                    .map_or(0, |n| flat_tree::right_span(n.index) / 2 + 1);
                let mut idx = vec![];
                for n in nodes {
                    match patch.iter().position(|p| p == n) {
                        Some(i) => idx.push(i as u64),
                        None => {
                            patch.push(*n);
                            idx.push(patch.len() as u64 - 1);
                        }
                    }
                }
                PatchV0 {
                    start,
                    length: u.patch,
                    nodes: idx,
                }
            }),
        })
        .collect();
    encode(&MultiSignatureV0 { proofs, patch })
}
