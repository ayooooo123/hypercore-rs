// Prints ../tree.json: a signed core written by npm hypercore, its tree nodes,
// per-length hashes, byte offsets, and proofs for many request shapes.
const os = require('os')
const fs = require('fs')
const path = require('path')
const Hypercore = require('hypercore')
const crypto = require('hypercore-crypto')
const { MerkleTree } = require('hypercore/lib/merkle-tree')
const m = require('hypercore/lib/messages')
const c = require('compact-encoding')

const hex = (b) => (b ? Buffer.from(b).toString('hex') : null)
const node = (n) => ({ index: n.index, size: n.size, hash: hex(n.hash) })

let seed = 7
function rand(n) {
  seed = (seed * 1103515245 + 12345) % 2147483648
  return seed % n
}
const block = (i) => Buffer.from(Array.from({ length: i === 3 ? 0 : 1 + rand(300) }, () => rand(256)))

async function write(dir, blocks, keySeed) {
  const keyPair = crypto.keyPair(Buffer.alloc(32, keySeed))
  const core = new Hypercore(dir, { keyPair })
  await core.ready()
  for (const b of blocks) await core.append(b)
  return { core, keyPair }
}

async function makeProof(core, req) {
  const rx = core.state.storage.read()
  let p
  try {
    p = await MerkleTree.proof(core.state, rx, JSON.parse(JSON.stringify(req)))
  } catch (err) {
    rx.destroy()
    return { error: err.message }
  }
  rx.tryFlush()
  try {
    const proof = await p.settle()
    if (proof.block) proof.block.value = await core.get(proof.block.index, { wait: false })
    return { data: hex(c.encode(m.wire.data, { request: 0, ...proof })) }
  } catch (err) {
    return { error: err.message }
  }
}

async function allNodes(core, length) {
  const out = []
  for (let i = 0; i < 2 * length; i++) {
    const n = await MerkleTree.get(core.state, i)
    if (n) out.push(node(n))
  }
  return out
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hc-fixture-'))
  const N = 37
  const blocks = Array.from({ length: N }, (_, i) => block(i))
  const { core, keyPair } = await write(path.join(tmp, 'a'), blocks, 1)

  const lengths = []
  const probe = new Hypercore(path.join(tmp, 'probe'), { keyPair: crypto.keyPair(Buffer.alloc(32, 9)) })
  await probe.ready()
  for (let i = 0; i < N; i++) {
    await probe.append(blocks[i])
    lengths.push({
      length: probe.length,
      byteLength: probe.byteLength,
      hash: hex(MerkleTree.hash(probe.state)),
      roots: probe.state.roots.map(node)
    })
  }

  const byteOffsets = []
  for (let i = 0; i <= 2 * N; i += 1) byteOffsets.push([i, await MerkleTree.byteOffset(core.state, i).catch(() => null)])

  const max = (i, len) => MerkleTree.maxMissingNodes(2 * i, len)
  const requests = []
  for (const L of [0, 1, 5, 16, 20, 36]) {
    const up = { start: L, length: N - L }
    requests.push({ remoteLength: L, upgrade: up })
    requests.push({ remoteLength: L, upgrade: { start: L, length: Math.max(1, Math.floor((N - L) / 2)) } })
    for (const i of [L, Math.min(N - 1, L + 3), N - 1]) {
      requests.push({ remoteLength: L, block: { index: i, nodes: 0 }, upgrade: up })
    }
    requests.push({ remoteLength: L, seek: { bytes: Math.floor(core.byteLength / 3), padding: 0 }, upgrade: up })
    if (L === 0) continue
    for (const i of [0, Math.floor(L / 2), L - 1]) {
      requests.push({ remoteLength: L, block: { index: i, nodes: max(i, L) } })
      requests.push({ remoteLength: L, block: { index: i, nodes: max(i, L) }, upgrade: up })
      requests.push({ remoteLength: L, block: { index: i, nodes: 0 } })
    }
    requests.push({ remoteLength: L, hash: { index: 1, nodes: 0 } })
    requests.push({ remoteLength: L, hash: { index: 2 * (L - 1), nodes: max(L - 1, L) } })
    requests.push({ remoteLength: L, block: { index: 0, nodes: max(0, L) }, seek: { bytes: 10, padding: 0 } })
    requests.push({ remoteLength: L, block: { index: L - 1, nodes: 2 }, seek: { bytes: 400, padding: 0 } })
  }
  // requests JS rejects
  requests.push({ remoteLength: 5, upgrade: { start: 5, length: N } })
  requests.push({ remoteLength: 5, block: { index: 30, nodes: 0 }, seek: { bytes: 3, padding: 0 }, upgrade: { start: 5, length: 32 } })

  // A fork: the same writer truncates at 20 and appends different data.
  const forked = await write(path.join(tmp, 'b'), blocks.slice(0, 30), 2)
  const oldNodes = await allNodes(forked.core, 30)
  const remotes = new Map()
  const remoteFor = async (L) => {
    if (!remotes.has(L)) {
      const r = new Hypercore(path.join(tmp, 'remote-' + L), { keyPair: crypto.keyPair(Buffer.alloc(32, 10 + L)) })
      await r.ready()
      for (let i = 0; i < L; i++) await r.append(blocks[i])
      remotes.set(L, r)
    }
    return remotes.get(L)
  }

  const proofs = []
  for (const r of requests) {
    const { remoteLength, ...req } = r
    const res = await makeProof(core, req)
    if (res.data) {
      // What a JS remote at `remoteLength` makes of this proof.
      const remote = await remoteFor(remoteLength)
      try {
        const batch = await MerkleTree.verify(remote.state, c.decode(m.wire.data, Buffer.from(res.data, 'hex')))
        res.verified = { length: batch.length, hash: hex(batch.hash()) }
      } catch (err) {
        res.verifyError = err.message
      }
    }
    proofs.push({ remoteLength, request: req, ...res })
  }
  for (const r of remotes.values()) await r.close()
  const oldSignature = hex(forked.core.state.signature)
  await forked.core.truncate(20)
  const extra = Array.from({ length: 17 }, () => Buffer.from('fork-' + rand(1e6)))
  for (const b of extra) await forked.core.append(b)

  const out = {
    keySeed: hex(Buffer.alloc(32, 1)),
    publicKey: hex(keyPair.publicKey),
    key: hex(core.key),
    discoveryKey: hex(core.discoveryKey),
    manifest: hex(c.encode(m.manifest, core.manifest)),
    blocks: blocks.map(hex),
    length: core.length,
    byteLength: core.byteLength,
    fork: core.fork,
    treeHash: hex(MerkleTree.hash(core.state)),
    signature: hex(core.state.signature),
    nodes: await allNodes(core, N),
    lengths,
    byteOffsets,
    proofs,
    fork1: {
      keySeed: hex(Buffer.alloc(32, 2)),
      key: hex(forked.core.key),
      oldLength: 30,
      oldNodes,
      oldSignature,
      newBlocks: extra.map(hex),
      length: forked.core.length,
      fork: forked.core.fork,
      treeHash: hex(MerkleTree.hash(forked.core.state)),
      signature: hex(forked.core.state.signature),
      nodes: await allNodes(forked.core, forked.core.length),
      upgradeFromZero: await makeProof(forked.core, { upgrade: { start: 0, length: forked.core.length } }),
      upgradeFromOld: await makeProof(forked.core, { upgrade: { start: 30, length: forked.core.length - 30 } })
    }
  }

  await core.close()
  await probe.close()
  await forked.core.close()
  fs.rmSync(tmp, { recursive: true, force: true })
  process.stdout.write(JSON.stringify(out, null, 1) + '\n')
}

main()
