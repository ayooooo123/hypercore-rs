// Builds or switches a corestore directory for tests/storage_switch.rs.
//
//   node store.mjs build  <dir>
//   node store.mjs switch <dir> <writer>
//
// `build` writes the fixture and `<dir>.ledger.json`; `switch` opens the same
// directory, checks every invariant in the ledger, appends and sets user data,
// then rewrites the ledger. The Rust side does the same through corestore-rs.

import Corestore from 'corestore'
import Hypercore from 'hypercore'
import Hyperbee from 'hyperbee2'
import storageKeys from 'hypercore-storage/lib/keys.js'
import crypto from 'hypercore-crypto'
import b4a from 'b4a'
import fs from 'fs'

const [mode, dir, writer] = process.argv.slice(2)
if (!dir || (mode !== 'build' && mode !== 'switch')) {
  throw new Error('usage: node store.mjs build|switch <dir> [writer]')
}

const ledgerPath = dir + '.ledger.json'
const readLedger = () => JSON.parse(fs.readFileSync(ledgerPath, 'utf8'))
const writeLedger = (ledger) => fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2))
const hex = (buf) => (buf === null || buf === undefined ? null : b4a.toString(buf, 'hex'))
const block = (fill, len = 32) => b4a.alloc(len, fill)

// The group the `grouped` core joins; its rows are shared by every member.
const GROUP_TOPIC = b4a.alloc(32, 0x77)

const CORES = [
  { name: 'alpha', appendable: true },
  { name: 'beta', namespace: 'app', appendable: true },
  { name: 'secret', encrypted: true, appendable: true },
  { name: 'explicit', keyed: true, appendable: false },
  { name: 'v2', manifestVersion: 2, appendable: true },
  { name: 'grouped', grouped: true, appendable: true },
  { name: 'sparse', appendable: false, sparse: true },
  { name: 'bee', bee: true, appendable: true },
  { name: 'blobs', appendable: true },
  { name: 'forked', appendable: true }
]

function openCore(store, spec, ledger) {
  if (spec.keyed) return store.get({ key: b4a.from(ledger.cores[spec.name].key, 'hex') })
  const opts = { name: spec.name }
  if (spec.encrypted) opts.encryptionKey = b4a.from(ledger.encryptionKey, 'hex')
  if (spec.manifestVersion) opts.manifestVersion = spec.manifestVersion
  const view = spec.namespace ? store.namespace(spec.namespace) : store
  return view.get(opts)
}

// One entry per core: what the next side must see.
async function describe(core, spec, extra = {}) {
  const sample = []
  if (!spec.sparse) {
    for (const index of [0, core.length - 1]) {
      if (index < 0) continue
      const value = await core.get(index)
      sample.push({ index, value: hex(value) })
    }
  } else {
    const value = await core.get(0)
    sample.push({ index: 0, value: hex(value) })
  }
  return {
    key: hex(core.key),
    length: core.length,
    fork: core.fork,
    // `treeHash()` fetches the last block on a sparse core; the storage read does not.
    rootHash: hex(await Hypercore.treeHashFromStorage(core, core.length)),
    signature: hex(core.core.header.tree.signature),
    contiguous: core.contiguousLength,
    sample,
    appendable: spec.appendable,
    sparse: !!spec.sparse,
    ...extra
  }
}

// `group.entry`'s key: uint tag, uint group, uint64be timestamp, uint pointer.
function decodeGroupEntry(key) {
  let i = 0
  const uint = () => {
    let n = 0
    let shift = 0
    for (;;) {
      const byte = key[i++]
      n += (byte & 0x7f) * 2 ** shift
      if (!(byte & 0x80)) return n
      shift += 7
    }
  }
  uint()
  uint()
  const timestamp = Number(key.readBigUInt64BE(i))
  i += 8
  return { timestamp, ptr: uint() }
}

// Every row of a group's update log, oldest first.
async function groupRows(store, topic) {
  const group = await store.storage.getGroup(topic)
  if (group === null) return []
  const gte = storageKeys.group.entry(group, 0, 0)
  const lt = storageKeys.group.entry(group + 1, 0, 0)
  const rows = []
  for await (const { key, value } of store.storage.db.iterator({ gte, lt })) {
    rows.push({ ...decodeGroupEntry(key), key: hex(value) })
  }
  return rows
}

// The ledger keeps what both stacks must agree on; the timestamps are wall
// clock, so only their position relative to the head is checked.
async function describeGroup(store) {
  return (await groupRows(store, GROUP_TOPIC)).map(({ ptr, key }) => ({ ptr, key }))
}

async function checkGroup(store, ledger, opened, problems) {
  const expected = ledger.groups[hex(GROUP_TOPIC)] || []
  const rows = await groupRows(store, GROUP_TOPIC)
  if (rows.length !== expected.length) {
    problems.push(`group: ${rows.length} rows != ${expected.length}`)
  }
  for (let i = 0; i < Math.min(rows.length, expected.length); i++) {
    if (rows[i].ptr !== expected[i].ptr) problems.push(`group row ${i}: ptr`)
    if (rows[i].key !== expected[i].key) problems.push(`group row ${i}: key`)
  }
  const grouped = opened.grouped
  const head = grouped.core.header.tree
  const own = rows.find((row) => row.key === hex(grouped.key))
  if (!own) problems.push('group: the grouped core has no row')
  else if (own.timestamp !== head.timestamp) {
    problems.push(`group: row timestamp ${own.timestamp} != head ${head.timestamp}`)
  }
}

async function build(dir) {
  const store = new Corestore(dir)
  await store.ready()
  const ledger = { primaryKey: hex(store.primaryKey), cores: {} }

  const alpha = store.get({ name: 'alpha' })
  await alpha.ready()
  for (let i = 0; i < 5; i++) await alpha.append(block(i + 1))
  await alpha.setUserData('title', 'alpha core')
  await alpha.setUserData('binary', b4a.from([0, 1, 2, 255]))

  const app = store.namespace('app')
  const beta = app.get({ name: 'beta' })
  await beta.ready()
  for (let i = 0; i < 3; i++) await beta.append(block(0x40 + i))

  ledger.encryptionKey = hex(crypto.randomBytes(32))
  const secret = store.get({ name: 'secret', encryptionKey: b4a.from(ledger.encryptionKey, 'hex') })
  await secret.ready()
  for (let i = 0; i < 4; i++) await secret.append(block(0x80 + i))
  await secret.setUserData('encrypted-by', 'default-encryption')

  const explicit = store.get({ keyPair: crypto.keyPair() })
  await explicit.ready()
  await explicit.append(block(0xa0))
  await explicit.append(block(0xa1))

  store.manifestVersion = 2
  const v2 = store.get({ name: 'v2' })
  await v2.ready()
  await v2.append(block(0x60))
  await v2.append(block(0x61))
  store.manifestVersion = 1

  const grouped = store.get({ name: 'grouped', group: GROUP_TOPIC })
  await grouped.ready()
  await grouped.append(block(0x50))
  await grouped.append(block(0x51))

  // Sparse: replicate six blocks from a throwaway corestore that shares the
  // primary key, then download only the first three.
  const sourceDir = dir + '.source'
  const source = new Corestore(sourceDir, { primaryKey: store.primaryKey, unsafe: true })
  await source.ready()
  const origin = source.get({ name: 'sparse' })
  await origin.ready()
  for (let i = 0; i < 6; i++) await origin.append(block(0xc0 + i, 1024))
  const sparse = store.get({ name: 'sparse' })
  await sparse.ready()
  const s1 = store.replicate(true)
  const s2 = source.replicate(false)
  const peer = new Promise((resolve) => sparse.once('peer-add', resolve))
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('no replication peer')), 20000).unref()
  )
  s1.pipe(s2).pipe(s1)
  await Promise.race([peer, timeout])
  await sparse.download({ start: 0, end: 3 }).done()
  await origin.close()
  s1.destroy()
  s2.destroy()
  await source.close()
  fs.rmSync(sourceDir, { recursive: true, force: true })

  const bee = new Hyperbee(store)
  await bee.ready()
  const batch = bee.write()
  batch.tryPut(b4a.from('hello'), b4a.from('world'))
  batch.tryPut(b4a.from('pear'), b4a.from('tube'))
  batch.tryPut(b4a.from('a'), b4a.from('1'))
  batch.tryPut(b4a.from('zz'), b4a.from('last'))
  await batch.flush()

  const blobs = store.get({ name: 'blobs' })
  await blobs.ready()
  for (let i = 0; i < 3; i++) await blobs.append(block(0x10 + i, 512 * 1024))

  const forked = store.get({ name: 'forked' })
  await forked.ready()
  for (let i = 0; i < 8; i++) await forked.append(block(0xe0 + i))
  await forked.truncate(3, 4)
  await forked.append(block(0xf0))
  await forked.append(block(0xf1))

  const opened = { alpha, beta, secret, explicit, v2, grouped, sparse, blobs, forked }
  for (const spec of CORES) {
    const core = spec.bee ? bee : opened[spec.name]
    const storage = spec.bee ? bee.core : core
    ledger.cores[spec.name] = await describe(storage, spec, {
      ...(spec.bee ? { bee: true } : {}),
      ...(spec.namespace ? { namespace: spec.namespace } : {})
    })
  }
  ledger.beeEntries = 4
  ledger.groups = { [hex(GROUP_TOPIC)]: await describeGroup(store) }
  writeLedger(ledger)
  await closeAll(store, opened, bee)
  return ledger
}

// Reads every core, compares it with the ledger, then writes one block per
// appendable core (and one bee entry), then rewrites the ledger.
async function open(store, ledger) {
  const opened = {}
  const problems = []
  for (const spec of CORES) {
    const entry = ledger.cores[spec.name]
    const core = openCore(store, spec, ledger)
    await core.ready()
    opened[spec.name] = core
    if (hex(core.key) !== entry.key) problems.push(`${spec.name}: key`)
    if (core.length !== entry.length) problems.push(`${spec.name}: length ${core.length} != ${entry.length}`)
    if (core.fork !== entry.fork) problems.push(`${spec.name}: fork ${core.fork} != ${entry.fork}`)
    const root = hex(await Hypercore.treeHashFromStorage(core, core.length))
    if (root !== entry.rootHash) problems.push(`${spec.name}: root hash ${root} != ${entry.rootHash}`)
    const signature = hex(core.core.header.tree.signature)
    if (signature !== entry.signature) problems.push(`${spec.name}: signature`)
    if (core.contiguousLength !== entry.contiguous) {
      problems.push(`${spec.name}: contiguous ${core.contiguousLength} != ${entry.contiguous}`)
    }
    for (const sample of entry.sample) {
      const value = hex(await core.get(sample.index))
      if (value !== sample.value) problems.push(`${spec.name}: block ${sample.index}`)
    }
  }
  await checkGroup(store, ledger, opened, problems)
  return { opened, problems }
}

async function switchDir(dir, writer) {
  const ledger = readLedger()
  const store = new Corestore(dir)
  await store.ready()
  const { opened, problems } = await open(store, ledger)
  if (problems.length) {
    await store.close()
    throw new Error('ledger mismatch: ' + problems.join('; '))
  }

  const tag = block(writer === 'js' ? 0x31 : 0x32, 32)
  for (const spec of CORES) {
    if (!spec.appendable || spec.bee) continue
    const core = opened[spec.name]
    await core.append(tag)
  }
  await opened.alpha.setUserData('last-writer', writer)

  // hyperbee2 reads and writes go through the same core.
  const bee = new Hyperbee(store)
  await bee.ready()
  const hello = await bee.get(b4a.from('hello'))
  if (hex(hello && hello.value) !== hex(b4a.from('world'))) {
    throw new Error('bee entry missing')
  }
  const batch = bee.write()
  batch.tryPut(b4a.from('turn-' + writer + '-' + ledger.beeEntries), b4a.from('ok'))
  await batch.flush()
  ledger.beeEntries += 1

  for (const spec of CORES) {
    const core = spec.bee ? bee : opened[spec.name]
    const storage = spec.bee ? bee.core : core
    ledger.cores[spec.name] = await describe(storage, spec, {
      ...(spec.bee ? { bee: true } : {}),
      ...(spec.namespace ? { namespace: spec.namespace } : {})
    })
  }
  ledger.groups = { [hex(GROUP_TOPIC)]: await describeGroup(store) }
  writeLedger(ledger)
  await closeAll(store, opened, bee)
  return { cores: Object.keys(ledger.cores).length, problems: 0 }
}

async function closeAll(store, opened, bee) {
  for (const [name, core] of Object.entries(opened)) {
    if (!core.closed) await core.close()
  }
  if (bee && !bee.closed) {
    await bee.close()
  }
  await store.close()
}

const result = mode === 'build' ? await build(dir) : await switchDir(dir, writer)
console.log(JSON.stringify(mode === 'build' ? { built: Object.keys(result.cores).length } : result))
