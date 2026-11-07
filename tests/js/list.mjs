// Lists what a corestore directory holds, straight from storage.
//
//   node list.mjs <dir>
//
// Used by the crash test: a store killed mid-write must still open here.

import Corestore from 'corestore'

const dir = process.argv[2]
const store = new Corestore(dir)
await store.ready()

const cores = []
for await (const { discoveryKey } of store.storage.createCoreStream()) {
  const core = store.get({ discoveryKey })
  await core.ready()
  cores.push({ discoveryKey: discoveryKey.toString('hex'), key: core.key && core.key.toString('hex'), length: core.length })
  await core.close()
}
await store.close()
console.log(JSON.stringify({ cores }))
