/**
 * End-to-end round trip for XChaCha20-Poly1305 v1 suite.
 * Mirrors the AES-GCM tests; same architectural guarantees must hold.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptToBytes,
  encryptBlob,
  encryptBytes,
} from '../../src/suites/xchacha-v1/api.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('xchacha-v1: round trip empty file', async () => {
  const result = await encryptBytes(new Uint8Array(0), { chunkSize: 1024 })
  assert.equal(result.totalChunks, 0)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.equal(decrypted.length, 0)
})

test('xchacha-v1: round trip single chunk', async () => {
  const plaintext = new TextEncoder().encode('xchacha hello')
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('xchacha-v1: round trip many chunks with partial final', async () => {
  const plaintext = randomBytes(2048 * 7 + 99)
  const result = await encryptBytes(plaintext, { chunkSize: 2048 })
  assert.equal(result.totalChunks, 8)
  assert.equal(result.plaintextSize, plaintext.length)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('xchacha-v1: rejects wrong content key', async () => {
  const plaintext = new TextEncoder().encode('top secret')
  const result = await encryptBytes(plaintext, {})
  await assert.rejects(() =>
    decryptToBytes({
      blob: result.blob,
      contentKey: randomBytes(32),
    }),
  )
})

test('xchacha-v1: detects truncation (last chunk dropped)', async () => {
  const plaintext = randomBytes(8192)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  // Drop last chunk = 4 bytes length + 1024 + 16 tag = 1044 bytes
  const truncated = fullBytes.slice(0, fullBytes.length - 1044)
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([truncated as Uint8Array<ArrayBuffer>]),
      contentKey: result.contentKey,
    }),
  )
})

test('xchacha-v1: detects per-chunk tampering', async () => {
  const plaintext = randomBytes(2048)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  fullBytes[fullBytes.length - 50] ^= 0x01
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
      contentKey: result.contentKey,
    }),
  )
})

test('xchacha-v1: detects header tampering', async () => {
  const plaintext = randomBytes(512)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  fullBytes[10] ^= 0x40 // file_id byte
  await assert.rejects(
    () =>
      decryptToBytes({
        blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
        contentKey: result.contentKey,
      }),
    /header_mac_mismatch/,
  )
})

test('xchacha-v1: detects chunk reordering', async () => {
  const plaintext = randomBytes(2048)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  const headerLen = fullBytes.length - 2 * (4 + 1024 + 16)
  const chunk1End = headerLen + (4 + 1024 + 16)
  const swapped = new Uint8Array(fullBytes.length)
  swapped.set(fullBytes.slice(0, headerLen), 0)
  swapped.set(fullBytes.slice(chunk1End, fullBytes.length), headerLen)
  swapped.set(
    fullBytes.slice(headerLen, chunk1End),
    headerLen + (fullBytes.length - chunk1End),
  )
  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([swapped as Uint8Array<ArrayBuffer>]),
      contentKey: result.contentKey,
    }),
  )
})

test('xchacha-v1: detects splice across files', async () => {
  const sharedKey = randomBytes(32)
  const a = await encryptBytes(randomBytes(2048), {
    chunkSize: 1024,
    contentKey: sharedKey,
    fileId: randomBytes(16),
  })
  const b = await encryptBytes(randomBytes(2048), {
    chunkSize: 1024,
    contentKey: sharedKey,
    fileId: randomBytes(16),
  })
  const aBytes = new Uint8Array(await a.blob.arrayBuffer())
  const bBytes = new Uint8Array(await b.blob.arrayBuffer())
  const headerLen = aBytes.length - 2 * (4 + 1024 + 16)
  const chunkSize = 4 + 1024 + 16
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
      contentKey: sharedKey,
    }),
  )
})

test('xchacha-v1: progress callbacks', async () => {
  const reports: number[] = []
  await encryptBlob({
    blob: new Blob([randomBytes(8192) as Uint8Array<ArrayBuffer>]),
    chunkSize: 1024,
    onProgress: (p) => reports.push(p),
  })
  assert.equal(reports.length, 8)
  assert.equal(reports[reports.length - 1], 1)
})
