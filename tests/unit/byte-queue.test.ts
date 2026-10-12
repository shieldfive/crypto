import { strict as assert } from 'node:assert'
import test from 'node:test'

import { ByteQueue } from '../../src/internal/byte-queue.js'
import { encryptStreamAesGcmV1, createAesGcmV1DecryptStream } from '../../src/streams/aes-gcm-v1.js'
import { randomBytes } from '../../src/internal/runtime.js'

test('ByteQueue: FIFO order across appends, takes, growth and compaction', () => {
  const q = new ByteQueue()
  const ref: number[] = []
  let next = 0
  for (let round = 0; round < 500; round += 1) {
    const n = (round * 37) % 300
    const piece = new Uint8Array(n)
    for (let i = 0; i < n; i += 1) piece[i] = next++ & 0xff
    q.append(piece)
    ref.push(...piece)
    const t = Math.min(q.length, (round * 53) % 280)
    const got = q.take(t)
    assert.deepEqual([...got], ref.splice(0, t))
    assert.equal(q.length, ref.length)
    if (ref.length > 1) assert.equal(q.byteAt(1), ref[1])
  }
  assert.deepEqual([...q.takeAll()], ref)
  assert.equal(q.length, 0)
})

test('ByteQueue: take returns an independent copy', () => {
  const q = new ByteQueue()
  q.append(Uint8Array.from([1, 2, 3, 4]))
  const a = q.take(2)
  q.append(Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9]))
  assert.deepEqual([...a], [1, 2])
  assert.throws(() => q.take(100), RangeError)
  assert.throws(() => q.byteAt(-1), RangeError)
})

test('streams: byte-at-a-time input and output round-trips (no quadratic path needed)', async () => {
  const plaintext = randomBytes(5000)
  let i = 0
  const tiny = new ReadableStream<Uint8Array>({
    pull(c) {
      if (i >= plaintext.length) return c.close()
      c.enqueue(plaintext.subarray(i, i + 7))
      i += 7
    },
  })
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(tiny, {
    plaintextSize: plaintext.length,
    chunkSize: 1024,
  })
  const parts: Uint8Array[] = []
  const r = ciphertext.getReader()
  for (;;) {
    const { done, value } = await r.read()
    if (done) break
    parts.push(value)
  }
  const total = parts.reduce((n, p) => n + p.length, 0)
  const ct = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    ct.set(p, o)
    o += p.length
  }
  let j = 0
  const drip = new ReadableStream<Uint8Array>({
    pull(c) {
      if (j >= ct.length) return c.close()
      c.enqueue(ct.subarray(j, j + 1))
      j += 1
    },
  })
  const { stream } = createAesGcmV1DecryptStream({ contentKey })
  const out: number[] = []
  const rr = drip.pipeThrough(stream).getReader()
  for (;;) {
    const { done, value } = await rr.read()
    if (done) break
    out.push(...value)
  }
  assert.deepEqual(Uint8Array.from(out), plaintext)
})
