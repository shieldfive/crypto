/**
 * End-to-end round trip for AES-GCM v1 suite.
 * Encrypts random plaintexts of various sizes, decrypts, and asserts equality.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptToBytes,
  encryptBlob,
  encryptBytes,
} from '../../src/suites/aes-gcm-v1/api.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('aes-gcm-v1: round trip empty file', async () => {
  // The format permits zero-byte files; this exercises the totalChunks=0 path.
  const result = await encryptBytes(new Uint8Array(0), { chunkSize: 1024 })
  assert.equal(result.totalChunks, 0)
  assert.equal(result.plaintextSize, 0)
  // Header only, no chunks.
  assert.ok(result.blob.size > 0)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.equal(decrypted.length, 0)
})

test('aes-gcm-v1: round trip single small chunk', async () => {
  const plaintext = new TextEncoder().encode(
    'hello shieldfive — this fits in a single chunk',
  )
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  assert.equal(result.totalChunks, 1)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v1: round trip exactly one chunk size', async () => {
  const plaintext = randomBytes(2048)
  const result = await encryptBytes(plaintext, { chunkSize: 2048 })
  assert.equal(result.totalChunks, 1)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v1: round trip exactly two chunks (boundary)', async () => {
  const plaintext = randomBytes(4096)
  const result = await encryptBytes(plaintext, { chunkSize: 2048 })
  assert.equal(result.totalChunks, 2)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v1: round trip many chunks with partial final', async () => {
  const plaintext = randomBytes(2048 * 5 + 17) // 5 full + 17 trailing bytes
  const result = await encryptBytes(plaintext, { chunkSize: 2048 })
  assert.equal(result.totalChunks, 6)
  assert.equal(result.plaintextSize, plaintext.length)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v1: progress callbacks fire monotonically and end at 1', async () => {
  const plaintext = randomBytes(8192)
  const reports: number[] = []
  const result = await encryptBlob({
    blob: new Blob([plaintext]),
    chunkSize: 1024,
    onProgress: (p) => reports.push(p),
  })
  assert.equal(result.totalChunks, 8)
  assert.equal(reports.length, 8)
  for (let i = 1; i < reports.length; i += 1) {
    assert.ok(reports[i]! >= reports[i - 1]!)
  }
  assert.equal(reports[reports.length - 1], 1)
})

test('aes-gcm-v1: rejects wrong content key', async () => {
  const plaintext = new TextEncoder().encode('top secret')
  const result = await encryptBytes(plaintext, {})
  const wrongKey = randomBytes(32)
  await assert.rejects(
    () =>
      decryptToBytes({
        blob: result.blob,
        contentKey: wrongKey,
      }),
    (err: Error) =>
      /header_mac_mismatch/.test(err.message) ||
      /OperationError/.test(err.message),
  )
})

test('aes-gcm-v1: detects truncation (last chunk dropped)', async () => {
  const plaintext = randomBytes(8192)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  assert.equal(result.totalChunks, 8)
  const fullBlob = result.blob
  const fullBytes = new Uint8Array(await fullBlob.arrayBuffer())

  // Drop the last chunk: cipher_len 4 bytes + cipher 1024+16 bytes = 1044 bytes.
  const truncated = fullBytes.slice(0, fullBytes.length - 1044)
  const truncatedBlob = new Blob([truncated as Uint8Array<ArrayBuffer>])

  await assert.rejects(
    () =>
      decryptToBytes({
        blob: truncatedBlob,
        contentKey: result.contentKey,
      }),
    /chunk_truncated|chunk_length_truncated|trailing_bytes|plaintext_size_mismatch|header/,
  )
})

test('aes-gcm-v1: detects per-chunk tampering', async () => {
  const plaintext = randomBytes(2048)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())

  // Flip one bit somewhere in the middle of the first chunk's ciphertext.
  // Header is bounded; flipping after 200 bytes is well into chunk territory
  // for our small test.
  const flipIndex = fullBytes.length - 50
  fullBytes[flipIndex] ^= 0x01

  await assert.rejects(
    () =>
      decryptToBytes({
        blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
        contentKey: result.contentKey,
      }),
  )
})

test('aes-gcm-v1: detects header tampering', async () => {
  const plaintext = randomBytes(512)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())

  // Flip a byte in the file_id field (offset = magic(5) + suite(1) + flags(1) = 7).
  fullBytes[10] ^= 0x40

  await assert.rejects(
    () =>
      decryptToBytes({
        blob: new Blob([fullBytes as Uint8Array<ArrayBuffer>]),
        contentKey: result.contentKey,
      }),
    /header_mac_mismatch/,
  )
})

test('aes-gcm-v1: detects chunk reordering', async () => {
  // Two equal-size full chunks; we'll swap them and expect failure due to
  // chunk-index AAD mismatch (and IV mismatch, which surfaces as an AEAD failure).
  const plaintext = randomBytes(2048)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())

  // Find where chunks start (after header). We already know the header layout,
  // but we just probe by scanning for the magic and computing.
  // Easier: header_length = total - 2 * (4 + 1024 + 16) = total - 2080
  const headerLen = fullBytes.length - 2 * (4 + 1024 + 16)
  const chunk1Start = headerLen
  const chunk1End = chunk1Start + 4 + 1024 + 16
  const chunk2End = chunk1End + 4 + 1024 + 16
  assert.equal(chunk2End, fullBytes.length)

  const swapped = new Uint8Array(fullBytes.length)
  swapped.set(fullBytes.slice(0, headerLen), 0)
  swapped.set(fullBytes.slice(chunk1End, chunk2End), headerLen)
  swapped.set(
    fullBytes.slice(chunk1Start, chunk1End),
    headerLen + (chunk2End - chunk1End),
  )

  await assert.rejects(
    () =>
      decryptToBytes({
        blob: new Blob([swapped as Uint8Array<ArrayBuffer>]),
        contentKey: result.contentKey,
      }),
  )
})

test('aes-gcm-v1: detects splice of chunk from another file', async () => {
  // Two files with the SAME content key but different file_ids and plaintexts.
  // Splice file B's chunk into file A. With file_id-bound AAD, this MUST fail.
  const sharedKey = randomBytes(32)
  const fileIdA = randomBytes(16)
  const fileIdB = randomBytes(16)

  const plainA = randomBytes(2048)
  const plainB = randomBytes(2048)

  const a = await encryptBytes(plainA, {
    chunkSize: 1024,
    contentKey: sharedKey,
    fileId: fileIdA,
  })
  const b = await encryptBytes(plainB, {
    chunkSize: 1024,
    contentKey: sharedKey,
    fileId: fileIdB,
  })

  const aBytes = new Uint8Array(await a.blob.arrayBuffer())
  const bBytes = new Uint8Array(await b.blob.arrayBuffer())

  const headerLenA = aBytes.length - 2 * (4 + 1024 + 16)
  const chunk1AStart = headerLenA
  const chunk1AEnd = chunk1AStart + 4 + 1024 + 16

  const headerLenB = bBytes.length - 2 * (4 + 1024 + 16)
  const chunk1BStart = headerLenB
  const chunk1BEnd = chunk1BStart + 4 + 1024 + 16

  // Splice: A header + B's first chunk + A's second chunk
  const spliced = new Uint8Array(aBytes.length)
  spliced.set(aBytes.slice(0, headerLenA), 0)
  spliced.set(bBytes.slice(chunk1BStart, chunk1BEnd), headerLenA)
  spliced.set(aBytes.slice(chunk1AEnd, aBytes.length), headerLenA + (chunk1BEnd - chunk1BStart))

  await assert.rejects(
    () =>
      decryptToBytes({
        blob: new Blob([spliced as Uint8Array<ArrayBuffer>]),
        contentKey: sharedKey,
      }),
  )
})
