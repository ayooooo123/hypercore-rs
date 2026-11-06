// Generates ../encryption.json: block encryption golden vectors for hypercore 11.
const { createHash } = require('node:crypto')
const DefaultEncryption = require('hypercore/lib/default-encryption')
const { version } = require('hypercore/package.json')

const PADDING = DefaultEncryption.PADDING
const LENGTHS = [0, 1, 31, 100, 4096]
const INDEXES = [0, 1, 2 ** 32 + 5]
const FORKS = [0, 3]
const OPTIONS = [
  { block: false, compat: false },
  { block: false, compat: true },
  { block: true, compat: false },
  { block: true, compat: true }
]

const cases = OPTIONS.map((options) => {
  const encryptionKey = key(`encryption key ${JSON.stringify(options)}`)
  const hypercoreKey = key(`hypercore key ${JSON.stringify(options)}`)
  const enc = new DefaultEncryption(encryptionKey, hypercoreKey, options)

  const vectors = []
  for (const length of LENGTHS) {
    const plaintext = block(length)
    for (const index of INDEXES) {
      for (const fork of FORKS) {
        const buffer = Buffer.alloc(PADDING + length)
        plaintext.copy(buffer, PADDING)
        enc.encrypt(index, buffer, fork, { compat: options.compat })
        vectors.push({
          length,
          index,
          fork,
          plaintext: plaintext.toString('hex'),
          ciphertext: buffer.toString('hex')
        })
      }
    }
  }

  return {
    options,
    encryptionKey: encryptionKey.toString('hex'),
    hypercoreKey: hypercoreKey.toString('hex'),
    blockKey: enc.blockKey.toString('hex'),
    blindingKey: enc.blindingKey.toString('hex'),
    vectors
  }
})

console.log(JSON.stringify({ hypercore: version, padding: PADDING, cases }, null, 2))

function key (label) {
  // sha256 keeps the vectors deterministic without depending on npm layout.
  return createHash('sha256').update(label).digest()
}

function block (length) {
  const buffer = Buffer.alloc(length)
  for (let i = 0; i < length; i++) buffer[i] = (i * 31 + length) & 0xff
  return buffer
}
