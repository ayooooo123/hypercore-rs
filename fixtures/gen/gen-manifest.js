const Hypercore = require('../../tests/js/node_modules/hypercore')

const publicKey = Buffer.alloc(32, 42)
const cases = [1, 3].map(version => ({
  version,
  publicKey: publicKey.toString('hex'),
  key: Hypercore.key({ version, signers: [{ publicKey }] }).toString('hex')
}))
console.log(JSON.stringify(cases, null, 2))
