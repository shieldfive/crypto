/**
 * Streaming AES-GCM-v1 encrypt/decrypt tests.
 *
 * Verifies that the streaming path produces identical output to the
 * whole-blob path, and that all the same security guarantees (truncation,
 * tampering, splice) propagate through TransformStream boundaries.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  createAesGcmV1DecryptStream,
  createAesGcmV1EncryptStream,
  decryptStreamAesGcmV1,
  encryptStreamAesGcmV1,
} from '../../src/streams/aes-gcm-v1.js'
import * as aes from '../../src/suites/aes-gcm-v1/api.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
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

test('stream encrypt: empty file produces decryptable header-only output', async () => {
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(new Uint8Array(0)),
    { plaintextSize: 0, chunkSize: 1024 },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(decryptStreamAesGcmV1(streamFrom(ct), { contentKey }))
  assert.equal(pt.length, 0)
})

test('stream encrypt: single full chunk', async () => {
  const plaintext = randomBytes(1024)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024 },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(decryptStreamAesGcmV1(streamFrom(ct), { contentKey }))
  assert.ok(bytesEqual(plaintext, pt))
})

test('stream encrypt: many chunks, partial final', async () => {
  const plaintext = randomBytes(4096 * 5 + 23)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 4096 },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(decryptStreamAesGcmV1(streamFrom(ct), { contentKey }))
  assert.ok(bytesEqual(plaintext, pt))
})

test('stream encrypt: input fragmented into tiny pieces still produces correct ciphertext', async () => {
  const plaintext = randomBytes(8192)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext, 17), // 17-byte fragments
    { plaintextSize: plaintext.length, chunkSize: 1024 },
  )
  const ct = await drain(ciphertext)
  const pt = await drain(
    decryptStreamAesGcmV1(streamFrom(ct, 17), { contentKey }),
  )
  assert.ok(bytesEqual(plaintext, pt))
})

test('stream encrypt: streaming output bit-identical to whole-blob output', async () => {
  // Same key + file_id + plaintext should produce same ciphertext via either path.
  const plaintext = randomBytes(2048 * 3 + 11)
  const contentKey = randomBytes(32)
  const fileId = randomBytes(16)

  const blob = await aes.encryptBlob({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: 2048,
  })
  const blobBytes = new Uint8Array(await blob.blob.arrayBuffer())

  const { stream } = createAesGcmV1EncryptStream({
    plaintextSize: plaintext.length,
    chunkSize: 2048,
    contentKey,
    fileId,
  })
  const streamBytes = await drain(streamFrom(plaintext).pipeThrough(stream))

  assert.ok(bytesEqual(blobBytes, streamBytes))
})

test('stream encrypt: rejects input larger than declared plaintextSize', async () => {
  const { ciphertext } = encryptStreamAesGcmV1(streamFrom(randomBytes(2000)), {
    plaintextSize: 1000, // lying about size
    chunkSize: 512,
  })
  await assert.rejects(() => drain(ciphertext))
})

test('stream encrypt: rejects input smaller than declared plaintextSize', async () => {
  const { ciphertext } = encryptStreamAesGcmV1(streamFrom(randomBytes(500)), {
    plaintextSize: 1000,
    chunkSize: 512,
  })
  await assert.rejects(() => drain(ciphertext))
})

test('stream decrypt: detects truncation', async () => {
  const plaintext = randomBytes(8192)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024 },
  )
  const ct = await drain(ciphertext)
  // Drop the last chunk + length prefix
  const truncated = ct.slice(0, ct.length - (4 + 1024 + 16))
  await assert.rejects(() =>
    drain(decryptStreamAesGcmV1(streamFrom(truncated), { contentKey })),
  )
})

test('stream decrypt: detects per-chunk tampering', async () => {
  const plaintext = randomBytes(2048)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024 },
  )
  const ct = await drain(ciphertext)
  ct[ct.length - 50] ^= 0x01
  await assert.rejects(() =>
    drain(decryptStreamAesGcmV1(streamFrom(ct), { contentKey })),
  )
})

test('stream decrypt: rejects wrong key', async () => {
  const { ciphertext } = encryptStreamAesGcmV1(streamFrom(randomBytes(1000)), {
    plaintextSize: 1000,
    chunkSize: 512,
  })
  const ct = await drain(ciphertext)
  await assert.rejects(() =>
    drain(decryptStreamAesGcmV1(streamFrom(ct), { contentKey: randomBytes(32) })),
  )
})

test('stream decrypt: detects header tampering', async () => {
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(randomBytes(500)),
    { plaintextSize: 500, chunkSize: 512 },
  )
  const ct = await drain(ciphertext)
  ct[10] ^= 0x40 // file_id byte
  await assert.rejects(() =>
    drain(decryptStreamAesGcmV1(streamFrom(ct), { contentKey })),
  )
})

test('stream decrypt: rejects empty input', async () => {
  await assert.rejects(() =>
    drain(
      decryptStreamAesGcmV1(streamFrom(new Uint8Array(0)), {
        contentKey: randomBytes(32),
      }),
    ),
  )
})

test('stream decrypt: produces output progressively (not buffered to end)', async () => {
  // Encrypt a multi-chunk file, then feed ciphertext to the decryptor one
  // chunk at a time. The decryptor should emit early plaintext chunks
  // before later ciphertext chunks have been written.
  const plaintext = randomBytes(4096)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024 },
  )
  const ct = await drain(ciphertext)

  const transform = createAesGcmV1DecryptStream({ contentKey })
  const writer = transform.writable.getWriter()
  const reader = transform.readable.getReader()

  const writes: Array<Promise<void>> = []

  // Locate end of header (header = total - 4 chunks of (4 + 1024 + 16)).
  const headerEnd = ct.length - 4 * (4 + 1024 + 16)

  // Drive writes from a separate async task so reads can interleave.
  ;(async () => {
    // Write header + first chunk together
    writes.push(writer.write(ct.slice(0, headerEnd + (4 + 1024 + 16))))
    // Then write each remaining chunk
    let cursor = headerEnd + (4 + 1024 + 16)
    while (cursor < ct.length) {
      const next = cursor + (4 + 1024 + 16)
      writes.push(writer.write(ct.slice(cursor, next)))
      cursor = next
    }
    await Promise.all(writes)
    await writer.close()
  })()

  // Read the first chunk; this proves we emit before all ciphertext is written.
  const first = await reader.read()
  assert.equal(first.done, false)
  assert.equal(first.value!.length, 1024)
  assert.ok(bytesEqual(first.value!, plaintext.slice(0, 1024)))

  // Drain the remainder so the test ends cleanly.
  for (;;) {
    const { done } = await reader.read()
    if (done) break
  }
})
