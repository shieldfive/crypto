/**
 * Streaming pq-hybrid-v1 encrypt/decrypt tests.
 *
 * Verifies that the streaming path produces decryptable output and that
 * all the security guarantees (truncation, tampering, reorder, splice,
 * suite mismatch) propagate through TransformStream boundaries — same
 * coverage as streams-aes-gcm-v1, adapted for the KEM-driven key path.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  createPqHybridV1DecryptStream,
  createPqHybridV1EncryptStream,
  decryptStreamPqHybridV1,
  encryptStreamPqHybridV1,
  type PqHybridV1DecryptStreamOptions,
} from '../../src/streams/pq-hybrid-v1.js'
import * as pq from '../../src/suites/pq-hybrid-v1/api.js'
import {
  PQ_HYBRID_V1_TAG_BYTES,
  encapsulateForRecipient,
  generateMlKemKeypair,
} from '../../src/suites/pq-hybrid-v1/index.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

/**
 * Generate large pseudo-random plaintext. `randomBytes` in this package is
 * limited to 65536 bytes per call (Web Crypto getRandomValues spec); this
 * helper concatenates many calls to produce a multi-MiB buffer for the
 * chunk-boundary round-trip tests.
 */
function largeRandom(totalBytes: number): Uint8Array {
  const out = new Uint8Array(totalBytes)
  const blockSize = 65536
  for (let offset = 0; offset < totalBytes; offset += blockSize) {
    const slice = randomBytes(Math.min(blockSize, totalBytes - offset))
    out.set(slice, offset)
  }
  return out
}

/** Drain a ReadableStream<Uint8Array> into a single Uint8Array. */
async function drain(s: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = s.getReader()
  const parts: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    parts.push(value)
    total += value.length
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

/** Make a ReadableStream from a Uint8Array, optionally fragmenting it. */
function streamFrom(
  bytes: Uint8Array,
  fragmentSize?: number,
): ReadableStream<Uint8Array> {
  const size = fragmentSize ?? bytes.length
  let offset = 0
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close()
        return
      }
      const end = Math.min(offset + size, bytes.length)
      controller.enqueue(bytes.slice(offset, end))
      offset = end
    },
  })
}

test('pq-hybrid stream encrypt: empty file produces decryptable header-only output', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(new Uint8Array(0)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 0,
      chunkSize: 1024,
    },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(
    decryptStreamPqHybridV1(streamFrom(ct), {
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
  assert.equal(pt.length, 0)
})

test('pq-hybrid stream encrypt: single full chunk', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(1024)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 1024,
  })
  const ct = await drain(ciphertext)
  const pt = await drain(
    decryptStreamPqHybridV1(streamFrom(ct), {
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
  assert.ok(bytesEqual(plaintext, pt))
})

test('pq-hybrid stream encrypt: many chunks, partial final', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(4096 * 5 + 23)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 4096,
  })
  const ct = await drain(ciphertext)
  const pt = await drain(
    decryptStreamPqHybridV1(streamFrom(ct), {
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
  assert.ok(bytesEqual(plaintext, pt))
})

test('pq-hybrid stream encrypt: round trip across several chunk sizes', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  for (const chunkSize of [1 << 20, 1 << 22]) {
    const plaintext = largeRandom(chunkSize * 2 + 137)
    const { ciphertext } = await encryptStreamPqHybridV1(
      streamFrom(plaintext),
      {
        recipientPublicKey: publicKey,
        envelopeKey,
        plaintextSize: plaintext.length,
        chunkSize,
      },
    )
    const ct = await drain(ciphertext)
    const pt = await drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        recipientSecretKey: secretKey,
        envelopeKey,
      }),
    )
    assert.ok(bytesEqual(plaintext, pt), `chunk size ${chunkSize} mismatch`)
  }
})

test('pq-hybrid stream encrypt: input fragmented into tiny pieces still produces correct ciphertext', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(8192)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(plaintext, 17),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: plaintext.length,
      chunkSize: 1024,
    },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(
    decryptStreamPqHybridV1(streamFrom(ct, 17), {
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
  assert.ok(bytesEqual(plaintext, pt))
})

test('pq-hybrid stream encrypt: with explicit fileId, round-trip ciphertext is decryptable via the whole-blob API', async () => {
  // The PQ suite cannot reproduce bit-identical ciphertext across the
  // streaming and whole-blob paths because both paths internally generate
  // fresh randomness (classical share + nonce) inside encapsulation. So
  // we instead assert that streaming output decrypts via the whole-blob
  // decryptor when given the same recipient secret + envelope key.
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const fileId = randomBytes(16)
  const plaintext = randomBytes(2048 * 3 + 11)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    fileId,
    plaintextSize: plaintext.length,
    chunkSize: 2048,
  })
  const ct = await drain(ciphertext)
  const decrypted = await pq.decryptToBytes({
    blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
    recipientSecretKey: secretKey,
    envelopeKey,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('pq-hybrid stream encrypt: rejects input larger than declared plaintextSize', async () => {
  const { publicKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(2000)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 1000,
      chunkSize: 512,
    },
  )
  await assert.rejects(() => drain(ciphertext))
})

test('pq-hybrid stream encrypt: rejects input smaller than declared plaintextSize', async () => {
  const { publicKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(500)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 1000,
      chunkSize: 512,
    },
  )
  await assert.rejects(() => drain(ciphertext))
})

test('pq-hybrid stream decrypt: detects truncation (dropped last chunk)', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(8192)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 1024,
  })
  const ct = await drain(ciphertext)
  // Drop the last chunk + length prefix
  const truncated = ct.slice(
    0,
    ct.length - (4 + 1024 + PQ_HYBRID_V1_TAG_BYTES),
  )
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(truncated), {
        recipientSecretKey: secretKey,
        envelopeKey,
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: detects per-chunk tampering', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(2048)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 1024,
  })
  const ct = await drain(ciphertext)
  ct[ct.length - 50] ^= 0x01
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        recipientSecretKey: secretKey,
        envelopeKey,
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: detects chunk reordering', async () => {
  // Encrypt three full chunks, swap chunks #0 and #1 (with their length
  // prefixes), expect decrypt failure at the AEAD layer.
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const chunkSize = 1024
  const plaintext = randomBytes(chunkSize * 3)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize,
  })
  const ct = await drain(ciphertext)

  const wireChunkSize = 4 + chunkSize + PQ_HYBRID_V1_TAG_BYTES
  const headerLen = ct.length - 3 * wireChunkSize
  const c0Start = headerLen
  const c1Start = headerLen + wireChunkSize

  const swapped = new Uint8Array(ct.length)
  swapped.set(ct.subarray(0, headerLen), 0)
  swapped.set(ct.subarray(c1Start, c1Start + wireChunkSize), c0Start)
  swapped.set(ct.subarray(c0Start, c0Start + wireChunkSize), c1Start)
  swapped.set(
    ct.subarray(c1Start + wireChunkSize),
    c1Start + wireChunkSize,
  )

  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(swapped), {
        recipientSecretKey: secretKey,
        envelopeKey,
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: rejects wrong envelope key', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(1000)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 1000,
      chunkSize: 512,
    },
  )
  const ct = await drain(ciphertext)
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        recipientSecretKey: secretKey,
        envelopeKey: randomBytes(32), // wrong
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: rejects wrong PQ secret key', async () => {
  const { publicKey } = generateMlKemKeypair()
  const { secretKey: wrongSecret } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(1000)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 1000,
      chunkSize: 512,
    },
  )
  const ct = await drain(ciphertext)
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        recipientSecretKey: wrongSecret,
        envelopeKey,
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: detects header tampering', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(500)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 500,
      chunkSize: 512,
    },
  )
  const ct = await drain(ciphertext)
  ct[10] ^= 0x40 // file_id byte
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        recipientSecretKey: secretKey,
        envelopeKey,
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: rejects suite mismatch (suite byte mutated to 0x01)', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(500)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 500,
      chunkSize: 512,
    },
  )
  const ct = await drain(ciphertext)
  // Suite byte sits right after the 5-byte magic.
  assert.equal(ct[5], 0x03)
  ct[5] = 0x01
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        recipientSecretKey: secretKey,
        envelopeKey,
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: rejects empty input', async () => {
  const { secretKey } = generateMlKemKeypair()
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(new Uint8Array(0)), {
        recipientSecretKey: secretKey,
        envelopeKey: randomBytes(32),
      }),
    ),
  )
})

test('pq-hybrid low-level factory: accepts pre-computed encapsulation materials', async () => {
  // Exercises createPqHybridV1EncryptStream directly with externally-run
  // encapsulation, mirroring how a caller that wants to choose its own
  // file_id and persist the suite payload separately would use it.
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const fileId = randomBytes(16)
  const { suitePayload, combinedKey } = await encapsulateForRecipient({
    recipientPublicKey: publicKey,
    envelopeKey,
    fileId,
  })
  const plaintext = randomBytes(3000)
  const { stream } = createPqHybridV1EncryptStream({
    plaintextSize: plaintext.length,
    chunkSize: 1024,
    combinedKey,
    fileId,
    suitePayload,
  })
  const ct = await drain(streamFrom(plaintext).pipeThrough(stream))
  const pt = await drain(
    decryptStreamPqHybridV1(streamFrom(ct), {
      recipientSecretKey: secretKey,
      envelopeKey,
    }),
  )
  assert.ok(bytesEqual(plaintext, pt))
})

test('pq-hybrid stream decrypt: produces output progressively (not buffered to end)', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(4096)
  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 1024,
  })
  const ct = await drain(ciphertext)

  const transform = createPqHybridV1DecryptStream({
    recipientSecretKey: secretKey,
    envelopeKey,
  })
  const writer = transform.writable.getWriter()
  const reader = transform.readable.getReader()

  // Total wire bytes per chunk = 4 + chunkSize + tag.
  const wireChunkSize = 4 + 1024 + PQ_HYBRID_V1_TAG_BYTES
  const headerEnd = ct.length - 4 * wireChunkSize

  const writes: Array<Promise<void>> = []
  ;(async () => {
    writes.push(writer.write(ct.slice(0, headerEnd + wireChunkSize)))
    let cursor = headerEnd + wireChunkSize
    while (cursor < ct.length) {
      const next = cursor + wireChunkSize
      writes.push(writer.write(ct.slice(cursor, next)))
      cursor = next
    }
    await Promise.all(writes)
    await writer.close()
  })()

  const first = await reader.read()
  assert.equal(first.done, false)
  assert.equal(first.value!.length, 1024)
  assert.ok(bytesEqual(first.value!, plaintext.slice(0, 1024)))

  for (;;) {
    const { done } = await reader.read()
    if (done) break
  }
})

// ─────────────────────────────────────────────────────────────────────
// combinedKey-only decrypt mode (share-recipient path, Suite 0x03)
// ─────────────────────────────────────────────────────────────────────

test('pq-hybrid stream decrypt: combinedKey-only mode round-trips without ML-KEM secret', async () => {
  const { publicKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(4096 * 3 + 17)
  const { ciphertext, combinedKey } = await encryptStreamPqHybridV1(
    streamFrom(plaintext),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: plaintext.length,
      chunkSize: 4096,
    },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(
    decryptStreamPqHybridV1(streamFrom(ct), { combinedKey }),
  )
  assert.ok(bytesEqual(plaintext, pt))
})

test('pq-hybrid stream decrypt: combinedKey-only mode rejects wrong K', async () => {
  const { publicKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const { ciphertext } = await encryptStreamPqHybridV1(
    streamFrom(randomBytes(2048)),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: 2048,
      chunkSize: 1024,
    },
  )
  const ct = await drain(ciphertext)
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(ct), {
        combinedKey: randomBytes(32),
      }),
    ),
  )
})

test('pq-hybrid stream decrypt: combinedKey-only mode detects truncated ciphertext', async () => {
  const { publicKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(8192)
  const { ciphertext, combinedKey } = await encryptStreamPqHybridV1(
    streamFrom(plaintext),
    {
      recipientPublicKey: publicKey,
      envelopeKey,
      plaintextSize: plaintext.length,
      chunkSize: 1024,
    },
  )
  const ct = await drain(ciphertext)
  const truncated = ct.slice(
    0,
    ct.length - (4 + 1024 + PQ_HYBRID_V1_TAG_BYTES),
  )
  await assert.rejects(() =>
    drain(
      decryptStreamPqHybridV1(streamFrom(truncated), { combinedKey }),
    ),
  )
})

test('pq-hybrid stream decrypt: combinedKey-only mode rejects 31-byte K (length check)', () => {
  assert.throws(() =>
    createPqHybridV1DecryptStream({ combinedKey: new Uint8Array(31) }),
  )
})

test('pq-hybrid stream decrypt: missing both KEM secret and combinedKey throws', () => {
  // Casting around the type union: the runtime guard must reject this too,
  // for callers who reach the factory via a less-typed path (e.g., across
  // a worker postMessage boundary).
  assert.throws(() =>
    createPqHybridV1DecryptStream({} as PqHybridV1DecryptStreamOptions),
  )
})
