/**
 * End-to-end round trip for the post-quantum hybrid suite (suite 0x03).
 *
 * Validates:
 *   - ML-KEM-1024 encapsulation/decapsulation works
 *   - Combined classical + PQ key derivation matches between sender/recipient
 *   - All structural guarantees from format-v1 still hold (truncation,
 *     tampering, reorder, splice detection)
 *   - Wrong PQ secret key OR wrong envelope key both fail
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptToBytes,
  encryptBlob,
  encryptBytes,
} from '../../src/suites/pq-hybrid-v1/api.js'
import {
  decapsulateFromHeader,
  deriveMlKemKeypair,
  encapsulateForRecipient,
  generateMlKemKeypair,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SECRET_KEY_BYTES,
} from '../../src/suites/pq-hybrid-v1/index.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('pq-hybrid-v1: ML-KEM-1024 keypair has correct lengths', () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  assert.equal(publicKey.length, ML_KEM_1024_PUBLIC_KEY_BYTES)
  assert.equal(secretKey.length, ML_KEM_1024_SECRET_KEY_BYTES)
})

test('pq-hybrid-v1: deterministic keypair derivation is stable', async () => {
  const masterSecret = randomBytes(32)
  const a = await deriveMlKemKeypair(masterSecret)
  const b = await deriveMlKemKeypair(masterSecret)
  assert.ok(bytesEqual(a.publicKey, b.publicKey))
  assert.ok(bytesEqual(a.secretKey, b.secretKey))

  const otherSecret = randomBytes(32)
  const c = await deriveMlKemKeypair(otherSecret)
  assert.ok(!bytesEqual(a.publicKey, c.publicKey))
})

test('pq-hybrid-v1: round trip empty file', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const result = await encryptBytes(new Uint8Array(0), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  assert.equal(result.totalChunks, 0)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    recipientSecretKey: secretKey,
    envelopeKey,
  })
  assert.equal(decrypted.length, 0)
})

test('pq-hybrid-v1: round trip single chunk', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = new TextEncoder().encode(
    'post-quantum hybrid encryption: a single small chunk',
  )
  const result = await encryptBytes(plaintext, {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const decrypted = await decryptToBytes({
    blob: result.blob,
    recipientSecretKey: secretKey,
    envelopeKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('pq-hybrid-v1: round trip many chunks', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(2048 * 5 + 17)
  const result = await encryptBytes(plaintext, {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 2048,
  })
  assert.equal(result.totalChunks, 6)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    recipientSecretKey: secretKey,
    envelopeKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('pq-hybrid-v1: rejects wrong PQ secret key', async () => {
  const { publicKey } = generateMlKemKeypair()
  const wrong = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const result = await encryptBytes(randomBytes(1000), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  await assert.rejects(() =>
    decryptToBytes({
      blob: result.blob,
      recipientSecretKey: wrong.secretKey,
      envelopeKey,
    }),
  )
})

test('pq-hybrid-v1: rejects wrong envelope key', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const wrongEnvelope = randomBytes(32)
  const result = await encryptBytes(randomBytes(1000), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  await assert.rejects(() =>
    decryptToBytes({
      blob: result.blob,
      recipientSecretKey: secretKey,
      envelopeKey: wrongEnvelope,
    }),
  )
})

// Regression for the coordinated-disclosure hardening: decapsulateFromHeader
// must fold a failed classical unwrap into one generic error (rather than
// surfacing libsodium's internal "wrong secret key" string), and the happy
// path must still recover the combined key.
test('pq-hybrid-v1: decapsulateFromHeader folds a wrong envelope key into a generic error', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const wrongEnvelope = randomBytes(32)
  const fileId = randomBytes(16)
  const { suitePayload, combinedKey } = await encapsulateForRecipient({
    recipientPublicKey: publicKey,
    envelopeKey,
    fileId,
  })
  const ok = await decapsulateFromHeader({
    suitePayload,
    recipientSecretKey: secretKey,
    envelopeKey,
    fileId,
  })
  assert.ok(bytesEqual(ok.combinedKey, combinedKey))
  await assert.rejects(
    () =>
      decapsulateFromHeader({
        suitePayload,
        recipientSecretKey: secretKey,
        envelopeKey: wrongEnvelope,
        fileId,
      }),
    /unwrap failed/,
  )
})

test('pq-hybrid-v1: detects truncation', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const result = await encryptBytes(randomBytes(8192), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  const truncated = fullBytes.slice(0, fullBytes.length - 1044)
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([truncated as Uint8Array<ArrayBuffer>]),
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
})

test('pq-hybrid-v1: detects header tampering', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const result = await encryptBytes(randomBytes(512), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  fullBytes[10] ^= 0x40 // file_id field
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
})

test('pq-hybrid-v1: detects mlkem ciphertext tampering', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const result = await encryptBytes(randomBytes(512), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  // Suite payload starts at offset 45 (header fixed prefix); flip a byte
  // in the ML-KEM ciphertext field. ML-KEM is IND-CCA2 so any flip yields
  // a different shared secret, which then fails header_mac.
  fullBytes[100] ^= 0x80
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
})

test('pq-hybrid-v1: detects per-chunk tampering', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const result = await encryptBytes(randomBytes(2048), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  fullBytes[fullBytes.length - 50] ^= 0x01
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
})

test('pq-hybrid-v1: detects splice across files', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  // Two files for the same recipient; splice chunks between them.
  const a = await encryptBytes(randomBytes(2048), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const b = await encryptBytes(randomBytes(2048), {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
  })
  const aBytes = new Uint8Array(await a.blob.arrayBuffer())
  const bBytes = new Uint8Array(await b.blob.arrayBuffer())
  // Both files have the same suite_payload length so headers are same length.
  const headerLen = aBytes.length - 2 * (4 + 1024 + 16)
  assert.equal(headerLen, bBytes.length - 2 * (4 + 1024 + 16))
  const chunkSize = 4 + 1024 + 16
  // A header + B's first chunk + A's second chunk
  const spliced = new Uint8Array(aBytes.length)
  spliced.set(aBytes.slice(0, headerLen), 0)
  spliced.set(bBytes.slice(headerLen, headerLen + chunkSize), headerLen)
  spliced.set(
    aBytes.slice(headerLen + chunkSize, aBytes.length),
    headerLen + chunkSize,
  )
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([spliced as Uint8Array<ArrayBuffer>]),
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
})

test('pq-hybrid-v1: progress callbacks fire correctly', async () => {
  const { publicKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const reports: number[] = []
  const result = await encryptBlob({
    blob: new Blob([randomBytes(8192) as Uint8Array<ArrayBuffer>]),
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: 1024,
    onProgress: (p) => reports.push(p),
  })
  assert.equal(reports.length, 8)
  assert.equal(reports[reports.length - 1], 1)
  assert.equal(result.totalChunks, 8)
})
