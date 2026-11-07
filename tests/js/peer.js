// npm hypercore peer for tests/replicate_js.rs, over secret-stream on TCP.
//
// node peer.js write <dir> <blocks> <blockSize> <seed-hex>
//   writes a core, listens, prints "key <hex>" and "port <n>", then seeds it.
// node peer.js read <dir> <key-hex> <port>
//   connects, downloads the whole core, prints "sha256 <hex> <length> <bytes>".
// Exits when the remote closes the connection.
const net = require('net')
const fs = require('fs')
const crypto = require('crypto')
const Hypercore = require('hypercore')
const SecretStream = require('@hyperswarm/secret-stream')

const log = (s) => process.stdout.write(s + '\n')
const [mode, dir, ...args] = process.argv.slice(2)
fs.rmSync(dir, { recursive: true, force: true })

// Deterministic pseudo-random block i, same generator as the Rust side.
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

async function write() {
  const [blocks, size, seed, encryptionKey] = args
  const keyPair = require('hypercore-crypto').keyPair(Buffer.from(seed, 'hex'))
  const opts = { keyPair }
  if (encryptionKey) opts.encryptionKey = Buffer.from(encryptionKey, 'hex')
  const core = new Hypercore(dir, opts)
  await core.ready()
  // "truncate <n>" on stdin: fork the core at n and append three new blocks.
  require('readline')
    .createInterface({ input: process.stdin })
    .on('line', async (line) => {
      const [cmd, n] = line.split(' ')
      if (cmd !== 'truncate') return
      await core.truncate(Number(n))
      await core.append([Buffer.from('fork-0'), Buffer.from('fork-1'), Buffer.from('fork-2')])
      log('truncated ' + core.fork + ' ' + core.length)
    })
  const batch = []
  for (let i = 0; i < Number(blocks); i++) {
    batch.push(block(i, Number(size)))
    if (batch.length === 64) await core.append(batch.splice(0))
  }
  if (batch.length) await core.append(batch)
  log('key ' + core.key.toString('hex'))
  const server = net.createServer((socket) => {
    const ss = new SecretStream(false, socket)
    core.replicate(ss)
    ss.on('close', async () => {
      await core.close()
      process.exit(0)
    })
    ss.on('error', () => {})
  })
  server.listen(0, '127.0.0.1', () => log('port ' + server.address().port))
}

async function read() {
  const [key, port] = args
  const core = new Hypercore(dir, Buffer.from(key, 'hex'))
  await core.ready()
  const ss = new SecretStream(true, net.connect(Number(port), '127.0.0.1'))
  ss.on('error', () => {})
  const peer = new Promise(resolve => core.once('peer-add', resolve))
  core.replicate(ss)
  await peer
  await core.update({ wait: true })
  const started = Date.now()
  await core.download({ start: 0, end: core.length }).done()
  const hash = crypto.createHash('sha256')
  let bytes = 0
  for (let i = 0; i < core.length; i++) {
    const b = await core.get(i)
    hash.update(b)
    bytes += b.byteLength
  }
  log('sha256 ' + hash.digest('hex') + ' ' + core.length + ' ' + bytes + ' ' + (Date.now() - started))
  ss.destroy()
  await core.close()
  process.exit(0)
}

;(mode === 'write' ? write() : read()).catch((err) => {
  log('error ' + err.stack)
  process.exit(1)
})
