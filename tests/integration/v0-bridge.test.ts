/**
 * Tests for the Phase 1 migration bridge.
 *
 * The acceptance criteria:
 *   1. encryptV0 must produce ciphertext that decryptV0 can decrypt.
 *   2. encryptV0's output must be byte-identical to the production worker's
 *      output for the same inputs (proven by hand-rolling the production
 *      algorithm and comparing).
 *   3. installV0WorkerHandler must respond to the production message
 *      contract correctly.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  encryptV0,
  decryptV0ToBytes,
  installV0WorkerHandler,
  V0_KEY_BYTES,
  V0_TAG_BYTES,
  V0_NONCE_PREFIX_BYTES,
  type WorkerLike,
} from '../../src/migration/v0-bridge.js'
import { uint64BE } from '../../src/internal/encoding.js'
import { getSubtle, randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

/** Hand-rolled production-style encrypt for byte-identity comparison. */
async function productionStyleEncryptV0(
  plaintext: Uint8Array,
  contentKey: Uint8Array,
  noncePrefix: Uint8Array,
  chunkSize: number,
): Promise<Uint8Array> {
  const key = await getSubtle().importKey(
    'raw',
    contentKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const totalChunks = Math.ceil(plaintext.length / chunkSize)
  let total = 0
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
    total += ct.length
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

// ─────────────────────────────────────────────────────────────────────
// Round trip
// ─────────────────────────────────────────────────────────────────────

test('v0 bridge: round trip empty file', async () => {
  const r = await encryptV0({
    blob: new Blob([]),
    contentKey: randomBytes(V0_KEY_BYTES),
    chunkSize: 1024,
  })
  assert.equal(r.totalChunks, 0)
  assert.equal(r.plaintextSize, 0)
  assert.equal(r.blob.size, 0)
})

test('v0 bridge: round trip single chunk', async () => {
  const contentKey = randomBytes(V0_KEY_BYTES)
  const plaintext = new TextEncoder().encode('hello legacy v0')
  const r = await encryptV0({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    chunkSize: 1024,
  })
  const decrypted = await decryptV0ToBytes({
    blob: r.blob,
    contentKey,
    noncePrefix: r.noncePrefix,
    chunkSize: 1024,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

test('v0 bridge: round trip many chunks with partial final', async () => {
  const contentKey = randomBytes(V0_KEY_BYTES)
  const plaintext = randomBytes(2048 * 5 + 33)
  const r = await encryptV0({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    chunkSize: 2048,
  })
  assert.equal(r.totalChunks, 6)
  assert.equal(r.plaintextSize, plaintext.length)
  const decrypted = await decryptV0ToBytes({
    blob: r.blob,
    contentKey,
    noncePrefix: r.noncePrefix,
    chunkSize: 2048,
  })
  assert.ok(bytesEqual(plaintext, decrypted))
})

// ─────────────────────────────────────────────────────────────────────
// Byte-for-byte production compatibility
// ─────────────────────────────────────────────────────────────────────

test('v0 bridge: byte-identical to production-style encrypt', async () => {
  const contentKey = randomBytes(V0_KEY_BYTES)
  const noncePrefix = randomBytes(V0_NONCE_PREFIX_BYTES)
  const plaintext = randomBytes(2048 * 3 + 17)

  const bridgeResult = await encryptV0({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 2048,
  })
  const bridgeBytes = new Uint8Array(await bridgeResult.blob.arrayBuffer())

  const productionBytes = await productionStyleEncryptV0(
    plaintext,
    contentKey,
    noncePrefix,
    2048,
  )

  assert.ok(
    bytesEqual(bridgeBytes, productionBytes),
    'bridge output must be byte-identical to production',
  )
})

test('v0 bridge: 5 MiB chunk size matches production layout', async () => {
  const contentKey = randomBytes(V0_KEY_BYTES)
  const noncePrefix = randomBytes(V0_NONCE_PREFIX_BYTES)
  // Stand-in for "5 MiB-style" production chunk; we use 32 KiB here so we
  // can fit within the 64 KiB randomBytes budget while still exercising
  // multi-chunk + partial-final layout.
  const chunkSize = 32 * 1024
  // Build plaintext from concatenated random buffers to stay under the
  // randomBytes call-size cap.
  const plain1 = randomBytes(chunkSize)
  const plain2 = randomBytes(chunkSize)
  const tail = randomBytes(100)
  const plaintext = new Uint8Array(plain1.length + plain2.length + tail.length)
  plaintext.set(plain1, 0)
  plaintext.set(plain2, plain1.length)
  plaintext.set(tail, plain1.length + plain2.length)

  const r = await encryptV0({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize,
  })

  // Layout: 2 full chunks of (chunkSize + 16) + 1 partial chunk of (100 + 16)
  assert.equal(r.blob.size, 2 * (chunkSize + V0_TAG_BYTES) + (100 + V0_TAG_BYTES))
})

test('v0 bridge: chunk hashes computed when requested', async () => {
  const contentKey = randomBytes(V0_KEY_BYTES)
  const r = await encryptV0({
    blob: new Blob([randomBytes(4096) as Uint8Array<ArrayBuffer>]),
    contentKey,
    chunkSize: 1024,
    computeChunkHashes: true,
  })
  assert.equal(r.totalChunks, 4)
  assert.ok(r.chunkHashes)
  assert.equal(r.chunkHashes!.length, 4)
  for (const h of r.chunkHashes!) {
    assert.match(h, /^[0-9a-f]{40}$/, 'each chunk hash must be 40 hex chars')
  }
})

test('v0 bridge: progress callback fires monotonically and ends at 1', async () => {
  const reports: number[] = []
  await encryptV0({
    blob: new Blob([randomBytes(8192) as Uint8Array<ArrayBuffer>]),
    contentKey: randomBytes(V0_KEY_BYTES),
    chunkSize: 1024,
    onProgress: (p) => reports.push(p),
  })
  assert.equal(reports.length, 8)
  for (let i = 1; i < reports.length; i += 1) {
    assert.ok(reports[i]! >= reports[i - 1]!)
  }
  assert.equal(reports[reports.length - 1], 1)
})

test('v0 bridge: rejects bad inputs', async () => {
  await assert.rejects(
    () =>
      encryptV0({
        blob: new Blob([]),
        contentKey: randomBytes(31), // wrong length
        chunkSize: 1024,
      }),
    /32 bytes/,
  )
  await assert.rejects(
    () =>
      encryptV0({
        blob: new Blob([]),
        contentKey: randomBytes(V0_KEY_BYTES),
        chunkSize: 0,
      }),
    /positive integer/,
  )
  await assert.rejects(
    () =>
      encryptV0({
        blob: new Blob([]),
        contentKey: randomBytes(V0_KEY_BYTES),
        noncePrefix: randomBytes(3),
        chunkSize: 1024,
      }),
    /4 bytes/,
  )
})

// ─────────────────────────────────────────────────────────────────────
// Worker handler shape
// ─────────────────────────────────────────────────────────────────────

class MockWorker implements WorkerLike {
  onmessage: WorkerLike['onmessage'] = null
  outbox: unknown[] = []
  postMessage(msg: unknown): void {
    this.outbox.push(msg)
  }
  async dispatch(data: unknown): Promise<void> {
    if (!this.onmessage) throw new Error('no onmessage installed')
    await this.onmessage({ data })
  }
}

test('v0 worker: init + chunk_request + clear flow (encrypt mode)', async () => {
  const worker = new MockWorker()
  installV0WorkerHandler(worker)

  const contentKey = randomBytes(V0_KEY_BYTES)
  const noncePrefix = randomBytes(V0_NONCE_PREFIX_BYTES)
  const plaintext = randomBytes(2048)

  // init
  await worker.dispatch({
    type: 'init',
    mode: 'encrypt',
    key: contentKey.buffer.slice(
      contentKey.byteOffset,
      contentKey.byteOffset + contentKey.byteLength,
    ),
    noncePrefix: noncePrefix.buffer.slice(
      noncePrefix.byteOffset,
      noncePrefix.byteOffset + noncePrefix.byteLength,
    ),
    chunkSize: 1024,
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
  })

  const inited = worker.outbox.shift() as { type: string; totalChunks: number }
  assert.equal(inited.type, 'inited')
  assert.equal(inited.totalChunks, 2)

  // chunk_request 0
  await worker.dispatch({ type: 'chunk_request', index: 0 })
  const chunk0 = worker.outbox.shift() as {
    type: string
    mode: string
    index: number
    data: ArrayBuffer
    sha1: string
  }
  assert.equal(chunk0.type, 'chunk')
  assert.equal(chunk0.mode, 'encrypt')
  assert.equal(chunk0.index, 0)
  assert.equal(chunk0.data.byteLength, 1024 + V0_TAG_BYTES)
  assert.match(chunk0.sha1, /^[0-9a-f]{40}$/)

  // chunk_request 1
  await worker.dispatch({ type: 'chunk_request', index: 1 })
  const chunk1 = worker.outbox.shift() as {
    type: string
    data: ArrayBuffer
  }
  assert.equal(chunk1.data.byteLength, 1024 + V0_TAG_BYTES)

  // Reassemble and verify it round-trips through the public reader.
  const ct = new Uint8Array(chunk0.data.byteLength + chunk1.data.byteLength)
  ct.set(new Uint8Array(chunk0.data), 0)
  ct.set(new Uint8Array(chunk1.data), chunk0.data.byteLength)

  const plaintextRecovered = await decryptV0ToBytes({
    blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  assert.ok(bytesEqual(plaintext, plaintextRecovered))

  // clear
  await worker.dispatch({ type: 'clear' })
  const cleared = worker.outbox.shift() as { type: string }
  assert.equal(cleared.type, 'cleared')
})

test('v0 worker: errors surface via error message', async () => {
  const worker = new MockWorker()
  installV0WorkerHandler(worker)
  await worker.dispatch({ type: 'unknown_type' })
  const err = worker.outbox.shift() as { type: string; error: string }
  assert.equal(err.type, 'error')
  assert.match(err.error, /unknown_message_type/)
})

test('v0 worker: rejects out-of-range chunk index', async () => {
  const worker = new MockWorker()
  installV0WorkerHandler(worker)
  const contentKey = randomBytes(V0_KEY_BYTES)
  const noncePrefix = randomBytes(V0_NONCE_PREFIX_BYTES)
  await worker.dispatch({
    type: 'init',
    mode: 'encrypt',
    key: contentKey.buffer.slice(
      contentKey.byteOffset,
      contentKey.byteOffset + contentKey.byteLength,
    ),
    noncePrefix: noncePrefix.buffer.slice(
      noncePrefix.byteOffset,
      noncePrefix.byteOffset + noncePrefix.byteLength,
    ),
    chunkSize: 1024,
    blob: new Blob([randomBytes(2048) as Uint8Array<ArrayBuffer>]),
  })
  worker.outbox.shift() // discard inited
  await worker.dispatch({ type: 'chunk_request', index: 5 })
  const err = worker.outbox.shift() as { type: string; error: string }
  assert.equal(err.type, 'error')
  assert.match(err.error, /chunk_index_invalid/)
})

test('v0 worker: accepts production wire name `process` (not just `chunk_request`)', async () => {
  // The current ShieldFive production worker uses `process` as the
  // chunk-request message type. The bridge MUST accept this because
  // Phase 1 of the migration is wire-compatible with the existing
  // wrapper at utils/sfCryptoWorker.ts. A regression here breaks
  // production.
  const worker = new MockWorker()
  installV0WorkerHandler(worker)

  const contentKey = randomBytes(V0_KEY_BYTES)
  const noncePrefix = randomBytes(V0_NONCE_PREFIX_BYTES)
  const plaintext = randomBytes(2048)

  await worker.dispatch({
    type: 'init',
    mode: 'encrypt',
    key: contentKey.buffer.slice(
      contentKey.byteOffset,
      contentKey.byteOffset + contentKey.byteLength,
    ),
    noncePrefix: noncePrefix.buffer.slice(
      noncePrefix.byteOffset,
      noncePrefix.byteOffset + noncePrefix.byteLength,
    ),
    chunkSize: 1024,
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
  })
  const inited = worker.outbox.shift() as { type: string; totalChunks: number }
  assert.equal(inited.type, 'inited')
  assert.equal(inited.totalChunks, 2)

  // Use { type: 'process', index } — the production wire name.
  await worker.dispatch({ type: 'process', index: 0 })
  const chunk0 = worker.outbox.shift() as {
    type: string
    mode: string
    index: number
    data: ArrayBuffer
    sha1: string
  }
  assert.equal(chunk0.type, 'chunk')
  assert.equal(chunk0.mode, 'encrypt')
  assert.equal(chunk0.index, 0)
  assert.equal(chunk0.data.byteLength, 1024 + V0_TAG_BYTES)
  assert.match(chunk0.sha1, /^[0-9a-f]{40}$/)

  await worker.dispatch({ type: 'process', index: 1 })
  const chunk1 = worker.outbox.shift() as {
    type: string
    data: ArrayBuffer
  }
  assert.equal(chunk1.data.byteLength, 1024 + V0_TAG_BYTES)

  // Roundtrip the recovered ciphertext through the public reader to
  // confirm bytes are correct.
  const ct = new Uint8Array(chunk0.data.byteLength + chunk1.data.byteLength)
  ct.set(new Uint8Array(chunk0.data), 0)
  ct.set(new Uint8Array(chunk1.data), chunk0.data.byteLength)
  const recovered = await decryptV0ToBytes({
    blob: new Blob([ct as Uint8Array<ArrayBuffer>]),
    contentKey,
    noncePrefix,
    chunkSize: 1024,
  })
  assert.ok(bytesEqual(plaintext, recovered))
})
