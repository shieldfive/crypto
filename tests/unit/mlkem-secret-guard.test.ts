import { test } from 'node:test'
import assert from 'node:assert/strict'
import { deriveMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.ts'

test('deriveMlKemKeypair rejects an empty master secret', async () => {
  await assert.rejects(deriveMlKemKeypair(new Uint8Array(0)), RangeError)
})

test('deriveMlKemKeypair rejects a 15-byte master secret', async () => {
  await assert.rejects(deriveMlKemKeypair(new Uint8Array(15)), RangeError)
})

test('deriveMlKemKeypair accepts a 32-byte master secret deterministically', async () => {
  const s = new Uint8Array(32).fill(7)
  const a = await deriveMlKemKeypair(s)
  const b = await deriveMlKemKeypair(s)
  assert.deepEqual(a.publicKey, b.publicKey)
})
