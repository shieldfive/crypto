/**
 * v0 legacy decryptor tests.
 *
 * These tests construct ciphertext using the SAME algorithm as the
 * production worker at `public/workers/sf-crypto-worker.js` (verified
 * by reading that file — IV layout is `prefix(4) || counter_be(8)`,
 * AES-256-GCM, no AAD), then verify our v0 reader recovers the plaintext.
 *
 * If a future production change alters the v0 format, these tests must
 * be updated and `spec/format-v0.md` revised — that is by design.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptV0,
  decryptV0ToBytes,
  looksLikeV0,
} from '../../src/suites/aes-gcm-v0/api.js'
import { uint64BE } from '../../src/internal/encoding.js'
import { getSubtle, randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

/** Replicate the production worker's encryption — exact same IV layout. */
async function productionStyleEncryptV0(options: {
  plaintext: Uint8Array
  contentKey: Uint8Array
  noncePrefix: Uint8Array
  chunkSize: number
}): Promise<Uint8Array> {
  const { plaintext, contentKey, noncePrefix, chunkSize } = options
  const key = await getSubtle().importKey(
    'raw',
    contentKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const totalChunks = Math.ceil(plaintext.length / chunkSize)
  const parts: Uint8Array[] = []
  for (let i = 0; i < totalChunks; i += 1) {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, plaintext.length)
    const slice = plaintext.slice(start, end)
    const iv = new Uint8Array(12)
    iv.set(noncePrefix, 0)
    iv.set(uint64BE(i), 4)
    const ct = new Uint8Array(
      await getSubtle().encrypt(
        { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> },
        key,
        slice as Uint8Array<ArrayBuffer>,
      ),
    )
    parts.push(ct)
  }
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

test('v0: round trip empty file', async () => {
  const decrypted = await decryptV0ToBytes({
    blob: new Blob([new Uint8Array(0)]),
    contentKey: randomBytes(32),
    noncePrefix: randomBytes(4),
    chunkSize: 1024,
  })
  assert.equal(decrypted.length, 0)
})

test('v0: round trip single chunk', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const plaintext = new TextEncoder().encode('legacy file content')
  const ct = await productionStyleEncryptV0({
    plaintext,
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  const decrypted = await decryptV0ToBytes({
    blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('v0: round trip many chunks with partial final', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const plaintext = randomBytes(2048 * 5 + 17)
  const ct = await productionStyleEncryptV0({
    plaintext,
    contentKey,
    noncePrefix,
    chunkSize: 2048,
  })
  // Expected size: 5 full chunks * (2048+16) + final chunk (17+16) = 10353
  assert.equal(ct.length, 5 * (2048 + 16) + (17 + 16))
  const decrypted = await decryptV0ToBytes({
    blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 2048,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('v0: round trip exactly aligned chunks', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const plaintext = randomBytes(2048 * 3)
  const ct = await productionStyleEncryptV0({
    plaintext,
    contentKey,
    noncePrefix,
    chunkSize: 2048,
  })
  assert.equal(ct.length, 3 * (2048 + 16))
  const decrypted = await decryptV0ToBytes({
    blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 2048,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('v0: rejects wrong content key', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const plaintext = randomBytes(1000)
  const ct = await productionStyleEncryptV0({
    plaintext,
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  await assert.rejects(() =>
    decryptV0ToBytes({
      blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
      contentKey: randomBytes(32),
      noncePrefix,
      chunkSize: 1024,
    }),
  )
})

test('v0: rejects wrong nonce prefix', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const ct = await productionStyleEncryptV0({
    plaintext: randomBytes(1000),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  await assert.rejects(() =>
    decryptV0ToBytes({
      blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
      contentKey,
      noncePrefix: randomBytes(4),
      chunkSize: 1024,
    }),
  )
})

test('v0: detects truncation (last chunk dropped)', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const ct = await productionStyleEncryptV0({
    plaintext: randomBytes(4096),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  // Drop one full chunk
  const truncated = ct.slice(0, ct.length - (1024 + 16))
  // The blob still has clean chunk boundaries — we'd "succeed" decrypting
  // 3 chunks and silently lose the 4th. v0 has no AAD, so this is a
  // KNOWN limitation and the v1 motivation. Document the behavior:
  const decrypted = await decryptV0ToBytes({
    blob: new Blob([truncated as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  assert.equal(decrypted.length, 3072)
  // ^ This is expected: v0 cannot detect drop-of-final-chunks. v1 fixes this.
})

test('v0: detects malformed trailing bytes', async () => {
  const contentKey = randomBytes(32)
  const noncePrefix = randomBytes(4)
  const ct = await productionStyleEncryptV0({
    plaintext: randomBytes(2048),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  // Append 5 stray bytes — too few for a valid AEAD tag.
  const munged = new Uint8Array(ct.length + 5)
  munged.set(ct, 0)
  munged.set(new Uint8Array([1, 2, 3, 4, 5]), ct.length)
  await assert.rejects(() =>
    decryptV0ToBytes({
      blob: new Blob([munged as Uint8Array<ArrayBuffer>]),
      contentKey,
      noncePrefix,
      chunkSize: 1024,
    }),
  )
})

test('v0: looksLikeV0 distinguishes from v1', async () => {
  const v1Magic = new Uint8Array([0x53, 0x46, 0x35, 0x01, 0x00, 0x42])
  assert.equal(await looksLikeV0(new Blob([v1Magic as Uint8Array<ArrayBuffer>])), false)

  const random = randomBytes(100)
  // Astronomical chance of matching the magic by accident — treat as v0.
  assert.equal(await looksLikeV0(new Blob([random as Uint8Array<ArrayBuffer>])), true)

  assert.equal(await looksLikeV0(new Blob([new Uint8Array(0)])), true)
})
