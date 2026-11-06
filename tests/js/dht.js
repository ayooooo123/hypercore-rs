// HyperDHT testnet + Hyperswarm side of tests/replicate_dht.rs (UDX over UDP).
//
// node dht.js testnet
//   runs a 3-node local testnet, prints "bootstrap <port>"; exits when stdin closes.
// node dht.js write <bootstrap-port> <dir> <blocks> <blockSize> <seed-hex>
//   writes a core, announces its discovery key, prints "key <hex>" and "ready".
// node dht.js read <bootstrap-port> <dir> <key-hex>
//   finds peers for the key, downloads everything, prints "sha256 <hex> <length> <ms>".
const fs = require('fs')
const crypto = require('crypto')
const Hypercore = require('hypercore')
const Hyperswarm = require('hyperswarm')
const createTestnet = require('hyperdht/testnet')

const log = (s) => process.stdout.write(s + '\n')
const [mode, ...args] = process.argv.slice(2)
process.stdin.on('end', () => process.exit(0))
process.stdin.resume()

// Same generator as tests/js/peer.js and the Rust tests.
function block(i, size) {
  const out = Buffer.alloc(size)
  let x = (BigInt(i) * 0x9e3779b97f4a7c15n + 1n) & 0xffffffffffffffffn
  for (let j = 0; j < size; j += 8) {
    x ^= x << 13n
    x &= 0xffffffffffffffffn
    x ^= x >> 7n
    x ^= x << 17n
    x &= 0xffffffffffffffffn
    const b = Buffer.alloc(8)
    b.writeBigUInt64LE(x)
    b.copy(out, j, 0, Math.min(8, size - j))
  }
  return out
}

function swarm(port) {
  return new Hyperswarm({ bootstrap: [{ host: '127.0.0.1', port: Number(port) }] })
}

async function testnet() {
  const t = await createTestnet(3, { host: '127.0.0.1' })
  log('bootstrap ' + t.bootstrap[0].port)
}

async function write() {
  const [port, dir, blocks, size, seed] = args
  fs.rmSync(dir, { recursive: true, force: true })
  const keyPair = require('hypercore-crypto').keyPair(Buffer.from(seed, 'hex'))
  const core = new Hypercore(dir, { keyPair })
  await core.ready()
  const batch = []
  for (let i = 0; i < Number(blocks); i++) {
    batch.push(block(i, Number(size)))
    if (batch.length === 64) await core.append(batch.splice(0))
  }
  if (batch.length) await core.append(batch)
  const s = swarm(port)
  s.on('connection', (conn) => core.replicate(conn))
  await s.join(core.discoveryKey, { server: true, client: false }).flushed()
  log('key ' + core.key.toString('hex'))
  log('ready')
}

async function read() {
  const [port, dir, key] = args
  fs.rmSync(dir, { recursive: true, force: true })
  const core = new Hypercore(dir, Buffer.from(key, 'hex'))
  await core.ready()
  const s = swarm(port)
  s.on('connection', (conn) => core.replicate(conn))
  const done = core.findingPeers()
  s.join(core.discoveryKey, { server: false, client: true })
  s.flush().then(done, done)
  // flush() can settle before the holepunched connection is up: retry until it is.
  while (core.length === 0) {
    await core.update({ wait: true })
    if (core.length === 0) await new Promise((resolve) => setTimeout(resolve, 200))
  }
  const started = Date.now()
  await core.download({ start: 0, end: core.length }).done()
  const hash = crypto.createHash('sha256')
  for (let i = 0; i < core.length; i++) hash.update(await core.get(i))
  log('sha256 ' + hash.digest('hex') + ' ' + core.length + ' ' + (Date.now() - started))
  await s.destroy()
  await core.close()
  process.exit(0)
}

;({ testnet, write, read })[mode]().catch((err) => {
  log('error ' + err.stack)
  process.exit(1)
})
