/**
 * End-to-end round trip for AES-GCM v2 suite (0x04).
 *
 * The shape mirrors the v1 round-trip test plus the three v2-specific
 * properties called out in the suite's design note:
 *
 *   - Round trip at 1 / 10 / 1000 chunks (covers single-chunk, small
 *     multi-chunk, and a chunk count that exercises the 4-byte BE
 *     counter past the low byte).
 *   - Per-chunk tampering: flipping a byte inside a ciphertext chunk
 *     must fail decryption.
 *   - Domain separation: deriving the nonce prefix under a different
 *     HKDF info string yields a different prefix, so blobs encrypted
 *     under the alternate prefix fail to decrypt with the canonical
 *     suite.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptBlob,
  decryptToBytes,
  encryptBlob,
  encryptBytes,
} from '../../src/suites/aes-gcm-v2/api.js'
import {
  AES_GCM_V2_IV_BYTES,
  AES_GCM_V2_NONCE_PREFIX_LENGTH,
  AES_GCM_V2_TAG_BYTES,
} from '../../src/suites/aes-gcm-v2/index.js'
import { buildChunkAad, buildAuthenticatedHeader } from '../../src/format/header.js'
import { hkdfSha256 } from '../../src/internal/hkdf.js'
import { getSubtle, randomBytes } from '../../src/internal/runtime.js'
import { asBlobPart, uint32BE } from '../../src/internal/encoding.js'
import {
  HEADER_SIZES,
  HKDF_INFO,
  SUITE,
} from '../../src/internal/types.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('aes-gcm-v2: round trip single chunk', async () => {
  const plaintext = new TextEncoder().encode(
    'hello shieldfive — 8-byte prefix + 4-byte counter',
  )
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  assert.equal(result.totalChunks, 1)
  assert.equal(result.suite, SUITE.AES_256_GCM_V2)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v2: round trip 10 chunks', async () => {
  const plaintext = randomBytes(1024 * 10)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  assert.equal(result.totalChunks, 10)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v2: round trip 1000 chunks', async () => {
  // 1000 chunks of 64 bytes = 64 KiB. Exercises chunk indices spanning
  // multiple low bytes of the 4-byte BE counter.
  const chunkSize = 64
  const totalChunks = 1000
  const plaintext = randomBytes(chunkSize * totalChunks)
  const result = await encryptBlob({
    blob: new Blob([asBlobPart(plaintext)]),
    chunkSize,
  })
  assert.equal(result.totalChunks, totalChunks)
  const decrypted = await decryptToBytes({
    blob: result.blob,
    contentKey: result.contentKey,
  })
  assert.equal(decrypted.length, plaintext.length)
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('aes-gcm-v2: progress callbacks fire monotonically and end at 1', async () => {
  const plaintext = randomBytes(8192)
  const reports: number[] = []
  const result = await encryptBlob({
    blob: new Blob([asBlobPart(plaintext)]),
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

test('aes-gcm-v2: tampering with chunk index byte fails decryption', async () => {
  // Two equal-size full chunks; mutating the counter byte of the second
  // chunk's IV is not directly possible because the IV is derived, not
  // stored. The reader-visible analogue is mutating the ciphertext of a
  // specific chunk so the AAD-bound (chunk_index, total_chunks, is_final)
  // tuple no longer authenticates. We flip one byte in the second chunk's
  // ciphertext, which makes its tag invalid under that chunk's IV.
  const plaintext = randomBytes(2048)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  assert.equal(result.totalChunks, 2)
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())

  // Layout: [header][len|cipher_0 (1024+16)][len|cipher_1 (1024+16)]
  // Flip a byte well inside the second chunk's ciphertext.
  const chunkBytes = AES_GCM_V2_TAG_BYTES + 1024
  const lenPrefix = 4
  const headerLen = fullBytes.length - 2 * (lenPrefix + chunkBytes)
  const secondChunkStart = headerLen + (lenPrefix + chunkBytes) + lenPrefix
  fullBytes[secondChunkStart + 100] ^= 0x01

  await assert.rejects(() =>
    decryptToBytes({
      blob: new Blob([asBlobPart(fullBytes)]),
      contentKey: result.contentKey,
    }),
  )
})

test('aes-gcm-v2: detects header tampering', async () => {
  // Flip a byte in the file_id; the header MAC must reject before any
  // chunk-level work runs.
  const plaintext = randomBytes(512)
  const result = await encryptBytes(plaintext, { chunkSize: 1024 })
  const fullBytes = new Uint8Array(await result.blob.arrayBuffer())
  // file_id starts at offset = magic(5) + suite(1) + flags(1) = 7
  fullBytes[10] ^= 0x40

  await assert.rejects(
    () =>
      decryptToBytes({
        blob: new Blob([asBlobPart(fullBytes)]),
        contentKey: result.contentKey,
      }),
    /header_mac_mismatch/,
  )
})

test('aes-gcm-v2: different HKDF info byte yields different prefix (decrypt fails)', async () => {
  // Hand-build a valid v2-format blob, but derive the nonce prefix using
  // an attacker-chosen HKDF `info` string. The derived prefix differs
  // from the canonical one, so the decrypt path computes a different IV
  // and the AEAD tag verification must fail.
  const subtle = getSubtle()
  const contentKey = randomBytes(32)
  const fileId = randomBytes(HEADER_SIZES.FILE_ID)
  const chunkSize = 64
  const plaintext = randomBytes(chunkSize)
  const totalChunks = 1
  const plaintextSize = plaintext.length

  const suitePayload = new Uint8Array(72) // zero-filled wrapped_key+wrap_iv
  const header = await buildAuthenticatedHeader(
    {
      suite: SUITE.AES_256_GCM_V2,
      fileId,
      chunkSize,
      totalChunks,
      plaintextSize,
      suitePayload,
    },
    contentKey,
  )

  // Canonical chunk_key derivation, intentionally mis-derived nonce
  // prefix using a different `info` string. Note the trailing `-evil`.
  const chunkKey = await hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.AES_GCM_CHUNK_KEY,
    length: 32,
  })
  const evilNoncePrefix = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.AES_GCM_V2_NONCE_PREFIX + '-evil',
    length: AES_GCM_V2_NONCE_PREFIX_LENGTH,
  })
  const evilIv = new Uint8Array(AES_GCM_V2_IV_BYTES)
  evilIv.set(evilNoncePrefix, 0)
  evilIv.set(uint32BE(0), AES_GCM_V2_NONCE_PREFIX_LENGTH)

  const cryptoKey = await subtle.importKey(
    'raw',
    chunkKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const aad = buildChunkAad(0, totalChunks, true)
  const ctBuf = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: evilIv as Uint8Array<ArrayBuffer>,
      additionalData: aad as Uint8Array<ArrayBuffer>,
      tagLength: 128,
    },
    cryptoKey,
    plaintext as Uint8Array<ArrayBuffer>,
  )
  const ct = new Uint8Array(ctBuf)

  const blob = new Blob([
    asBlobPart(header),
    asBlobPart(uint32BE(ct.length)),
    asBlobPart(ct),
  ])

  await assert.rejects(() =>
    decryptBlob({
      blob,
      contentKey,
    }),
  )
})
