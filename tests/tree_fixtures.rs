//! `fixtures/tree.json` comes from npm hypercore 11.40.3 (`fixtures/gen`). The
//! Rust tree must hash, sign, prove and verify exactly as JS does.

use std::collections::HashMap;

use compact_encoding::hypercore::{
    Data, Manifest, MultiSignatureV1, MultisigInput, Node, RequestBlock, RequestSeek,
    RequestUpgrade,
};
use compact_encoding::{Bytes, decode, encode};
use hypercore::crypto::{KeyPair, discovery_key, manifest_hash};
use hypercore::merkle::{self, Batch, ProofRequest, TreeState};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn h32(v: &Value) -> [u8; 32] {
    unhex(v.as_str().unwrap()).try_into().unwrap()
}

fn node(v: &Value) -> Node {
    Node {
        index: v["index"].as_u64().unwrap(),
        size: v["size"].as_u64().unwrap(),
        hash: h32(&v["hash"]),
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/tree.json")).unwrap()
}

/// Appends `blocks` one commit at a time, like `core.append` in a loop.
fn build(blocks: &[Vec<u8>]) -> (TreeState, HashMap<u64, Node>, Vec<TreeState>) {
    let mut state = TreeState::default();
    let mut store = HashMap::new();
    let mut history = vec![];
    for b in blocks {
        let mut batch = Batch::new(&state);
        batch.append(b);
        let ops = batch.commit_ops();
        assert!(ops.delete.is_empty() && ops.delete_range.is_none());
        store.extend(ops.put.iter().map(|n| (n.index, *n)));
        state = batch.state();
        history.push(state.clone());
    }
    (state, store, history)
}

fn blocks(f: &Value, key: &str) -> Vec<Vec<u8>> {
    f[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| unhex(b.as_str().unwrap()))
        .collect()
}

fn sign(kp: &KeyPair, state: &TreeState, key: &[u8; 32]) -> Bytes {
    let signature = kp.sign(&state.signable(key));
    encode(&MultiSignatureV1 {
        proofs: vec![MultisigInput {
            signer: 0,
            signature,
            patch: 0,
        }],
        patch: vec![],
    })
}

fn request(v: &Value) -> ProofRequest {
    let rb = |v: &Value| RequestBlock {
        index: v["index"].as_u64().unwrap(),
        nodes: v["nodes"].as_u64().unwrap(),
    };
    ProofRequest {
        block: v.get("block").map(rb),
        hash: v.get("hash").map(rb),
        seek: v.get("seek").map(|s| RequestSeek {
            bytes: s["bytes"].as_u64().unwrap(),
            padding: s["padding"].as_u64().unwrap(),
        }),
        upgrade: v.get("upgrade").map(|u| RequestUpgrade {
            start: u["start"].as_u64().unwrap(),
            length: u["length"].as_u64().unwrap(),
        }),
    }
}

#[test]
fn appends_hash_and_sign_like_js() {
    let f = fixture();
    let blocks = blocks(&f, "blocks");
    let (mut state, store, history) = build(&blocks);

    for (want, got) in f["lengths"].as_array().unwrap().iter().zip(&history) {
        assert_eq!(got.length, want["length"].as_u64().unwrap());
        assert_eq!(got.byte_length, want["byteLength"].as_u64().unwrap());
        assert_eq!(
            hex(&got.hash()),
            want["hash"].as_str().unwrap(),
            "tree hash at length {}",
            got.length
        );
        let roots: Vec<Node> = want["roots"].as_array().unwrap().iter().map(node).collect();
        assert_eq!(got.roots, roots);
    }

    let mut want_nodes: Vec<Node> = f["nodes"].as_array().unwrap().iter().map(node).collect();
    let mut got_nodes: Vec<Node> = store.values().copied().collect();
    want_nodes.sort_by_key(|n| n.index);
    got_nodes.sort_by_key(|n| n.index);
    assert_eq!(got_nodes, want_nodes);

    let manifest: Manifest = decode(unhex(f["manifest"].as_str().unwrap())).unwrap();
    let key = manifest_hash(&manifest);
    assert_eq!(hex(&key), f["key"].as_str().unwrap());
    assert_eq!(
        hex(&discovery_key(&key)),
        f["discoveryKey"].as_str().unwrap()
    );

    let kp = KeyPair::from_seed(&h32(&f["keySeed"]));
    assert_eq!(hex(&kp.public_key), f["publicKey"].as_str().unwrap());
    assert_eq!(manifest.signers[0].public_key, kp.public_key);
    state.signature = Some(sign(&kp, &state, &key));
    assert_eq!(
        hex(state.signature.as_ref().unwrap()),
        f["signature"].as_str().unwrap()
    );

    let verifier = hypercore::verifier::Verifier::from_manifest(&manifest);
    let batch = Batch::new(&state);
    assert_eq!(
        verifier.sign(&batch, &kp).as_deref(),
        state.signature.as_deref()
    );
    assert!(verifier.verify(&batch, state.signature.as_deref()));
    let mut wrong = batch.clone();
    wrong.fork = 1;
    assert!(
        !verifier.verify(&wrong, state.signature.as_deref()),
        "fork is part of the signable"
    );
}

#[test]
fn byte_offsets_match_js() {
    let f = fixture();
    let blocks = blocks(&f, "blocks");
    let (state, store, _) = build(&blocks);
    for pair in f["byteOffsets"].as_array().unwrap() {
        let index = pair[0].as_u64().unwrap();
        let got = merkle::byte_offset(&state, &store, index).unwrap();
        // JS returns NaN past the first root (it sums `.size` of plain numbers);
        // there the answer is checked against the block sizes instead.
        let leaf = hypercore::flat_tree::left_span(index) / 2;
        let want = pair[1]
            .as_u64()
            .unwrap_or_else(|| blocks[..leaf as usize].iter().map(|b| b.len() as u64).sum());
        assert_eq!(got, want, "offset of {index}");
    }
}

#[test]
fn proofs_are_byte_identical_and_verify() {
    let f = fixture();
    let blocks = blocks(&f, "blocks");
    let (mut state, store, history) = build(&blocks);
    let key = h32(&f["key"]);
    state.signature = Some(sign(&KeyPair::from_seed(&h32(&f["keySeed"])), &state, &key));

    let mut checked = 0;
    for case in f["proofs"].as_array().unwrap() {
        let req = request(&case["request"]);
        let got = merkle::proof(&state, &store, &req);
        let Some(want_hex) = case["data"].as_str() else {
            // JS's NaN byte offset (see above) makes it refuse some valid seeks.
            if case["error"] != "INVALID_OPERATION: Invalid seek" {
                assert!(
                    got.is_err(),
                    "JS rejected {}: {}, Rust produced a proof",
                    case["request"],
                    case["error"]
                );
            }
            continue;
        };
        let mut got = match got {
            Ok(p) => p,
            // Same NaN: JS silently drops a seek outside the subtree; Rust refuses it.
            Err(e) if e.to_string().ends_with("Invalid seek") => {
                let js: Data = decode(unhex(want_hex)).unwrap();
                assert!(
                    js.seek.is_none() && case["request"].get("seek").is_some(),
                    "{}",
                    case["request"]
                );
                continue;
            }
            Err(e) => panic!("{}: {e}", case["request"]),
        };
        if let Some(b) = got.block.as_mut() {
            b.value = Bytes::from(blocks[b.index as usize].clone());
        }
        assert_eq!(
            hex(&encode(&got)),
            want_hex,
            "proof for {}",
            case["request"]
        );

        // The remote side: a tree of `remoteLength` verifies the JS proof.
        let remote_length = case["remoteLength"].as_u64().unwrap() as usize;
        let (remote, remote_store) = if remote_length == 0 {
            (TreeState::default(), HashMap::new())
        } else {
            let (s, st, _) = build(&blocks[..remote_length]);
            (s, st)
        };
        let data: Data = decode(unhex(want_hex)).unwrap();
        let verified = merkle::verify(&remote, &remote_store, &data);
        match (&case["verified"], verified) {
            (Value::Null, res) => assert!(
                res.is_err(),
                "JS verify failed ({}), Rust passed {}",
                case["verifyError"],
                case["request"]
            ),
            (want, Ok(batch)) => {
                assert_eq!(
                    batch.length,
                    want["length"].as_u64().unwrap(),
                    "{}",
                    case["request"]
                );
                assert_eq!(
                    hex(&batch.hash()),
                    want["hash"].as_str().unwrap(),
                    "{}",
                    case["request"]
                );
                if data.upgrade.is_some() {
                    assert_eq!(batch.hash(), history[batch.length as usize - 1].hash());
                }
            }
            (_, Err(e)) => panic!("verify {}: {e}", case["request"]),
        }
        checked += 1;
    }
    assert!(checked > 80, "only {checked} proofs checked");
}

#[test]
fn tampered_proofs_fail_verification() {
    let f = fixture();
    let blocks = blocks(&f, "blocks");
    let (remote, remote_store, _) = build(&blocks[..16]);
    for case in f["proofs"].as_array().unwrap() {
        let req = &case["request"];
        if case["remoteLength"] != 16
            || case["data"].is_null()
            || req.get("block").is_none()
            || req.get("upgrade").is_some()
        {
            continue;
        }
        let mut data: Data = decode(unhex(case["data"].as_str().unwrap())).unwrap();
        let b = data.block.as_mut().unwrap();
        let mut v = b.value.to_vec();
        v.push(1);
        b.value = Bytes::from(v);
        assert!(
            merkle::verify(&remote, &remote_store, &data).is_err(),
            "tampered {}",
            case["request"]
        );
    }
}

#[test]
fn reorg_finds_the_fork_point() {
    let f = fixture();
    let f1 = &f["fork1"];
    let base = blocks(&f, "blocks");
    let (old, old_store, _) = build(&base[..30]);
    let mut want_old: Vec<Node> = f1["oldNodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(node)
        .collect();
    let mut got_old: Vec<Node> = old_store.values().copied().collect();
    want_old.sort_by_key(|n| n.index);
    got_old.sort_by_key(|n| n.index);
    assert_eq!(got_old, want_old);

    // The writer's new tree: first 20 blocks, then the fork's blocks.
    let mut new_blocks = base[..20].to_vec();
    new_blocks.extend(blocks(f1, "newBlocks"));
    let (mut new, new_store, _) = build(&new_blocks);
    new.fork = 1;
    assert_eq!(hex(&new.hash()), f1["treeHash"].as_str().unwrap());

    let proof: Data = decode(unhex(f1["upgradeFromZero"]["data"].as_str().unwrap())).unwrap();
    let mut batch = Batch::new_reorg(&old);
    merkle::reorg(&old_store, &proof, &mut batch).unwrap();
    assert_eq!(batch.length, 37);
    assert_eq!(batch.fork, 1);

    let mut rounds = 0;
    while !batch.reorg_finished() {
        let want = batch.reorg.as_ref().unwrap().want.clone().unwrap();
        let req = ProofRequest {
            hash: Some(RequestBlock {
                index: 2 * want.start,
                nodes: want.nodes,
            }),
            ..Default::default()
        };
        let p = merkle::proof(&new, &new_store, &req).unwrap();
        assert!(batch.reorg_update(&old_store, &p).unwrap() || !batch.reorg_finished());
        rounds += 1;
        assert!(rounds < 64, "reorg did not converge");
    }
    assert_eq!(batch.ancestors, 20, "fork point");

    let ops = batch.commit_ops();
    assert_eq!(ops.delete_range, Some((40, 60)));
    assert!(batch.truncated);
    assert!(
        ops.delete.contains(&39),
        "parent spanning the fork point is dropped: {:?}",
        ops.delete
    );
}

#[test]
fn upgrades_made_for_another_length_are_refitted() {
    let f = fixture();
    let blocks = blocks(&f, "blocks");
    let (_, _, history) = build(&blocks);
    // A JS upgrade from length 5 to the head, applied by a peer that is at 16 by now.
    let case = f["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["remoteLength"] == 5
                && c["request"].as_object().unwrap().len() == 1
                && c["request"]["upgrade"]["length"] == 32
        })
        .expect("plain upgrade from 5");
    let data: Data = decode(unhex(case["data"].as_str().unwrap())).unwrap();
    let (local, store, _) = build(&blocks[..16]);
    assert!(
        merkle::verify(&local, &store, &data).is_err(),
        "does not apply as is"
    );
    let refitted = merkle::refit(&local, &store, &data)
        .unwrap()
        .expect("nodes suffice");
    assert_eq!(refitted.upgrade.as_ref().unwrap().start, 16);
    let batch = merkle::verify(&local, &store, &refitted).unwrap();
    assert_eq!(batch.length, 37);
    assert_eq!(batch.hash(), history[36].hash());

    // From further back the carried nodes cannot bridge the gap.
    let (behind, behind_store, _) = build(&blocks[..1]);
    let short = f["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["remoteLength"] == 20 && c["request"].as_object().unwrap().len() == 1)
        .unwrap();
    let data: Data = decode(unhex(short["data"].as_str().unwrap())).unwrap();
    assert!(
        merkle::refit(&behind, &behind_store, &data)
            .unwrap()
            .is_none()
    );
}
