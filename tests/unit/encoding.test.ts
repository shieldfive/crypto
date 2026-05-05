/**
 * Unit tests for the encoding helpers in src/internal/encoding.ts.
 * These are the primitives every other layer depends on; they need to be
 * boringly correct.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  hexToBytes,
  readUint16BE,
  readUint32BE,
  readUint64BE,
  uint16BE,
  uint32BE,
  uint64BE,
} from '../../src/internal/encoding.js'

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('base64 round trips empty', () => {
  assert.equal(bytesToBase64(new Uint8Array(0)), '')
  assert.ok(eq(base64ToBytes(''), new Uint8Array(0)))
})

test('base64 round trips known vectors', () => {
  // RFC 4648 test vectors
  assert.equal(bytesToBase64(new TextEncoder().encode('f')), 'Zg==')
  assert.equal(bytesToBase64(new TextEncoder().encode('fo')), 'Zm8=')
  assert.equal(bytesToBase64(new TextEncoder().encode('foo')), 'Zm9v')
  assert.equal(bytesToBase64(new TextEncoder().encode('foob')), 'Zm9vYg==')
  assert.equal(bytesToBase64(new TextEncoder().encode('fooba')), 'Zm9vYmE=')
  assert.equal(bytesToBase64(new TextEncoder().encode('foobar')), 'Zm9vYmFy')

  for (const s of ['f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
    const enc = bytesToBase64(new TextEncoder().encode(s))
    assert.equal(new TextDecoder().decode(base64ToBytes(enc)), s)
  }
})

test('hex round trips', () => {
  assert.equal(bytesToHex(new Uint8Array([0, 1, 15, 16, 254, 255])), '00010f10feff')
  assert.ok(eq(hexToBytes('00010f10feff'), new Uint8Array([0, 1, 15, 16, 254, 255])))
})

test('hex rejects bad input', () => {
  assert.throws(() => hexToBytes('a'), /even-length/)
  assert.throws(() => hexToBytes('zz'), /hexadecimal/)
})

test('concatBytes empty + non-empty', () => {
  assert.ok(eq(concatBytes([]), new Uint8Array(0)))
  assert.ok(
    eq(
      concatBytes([new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5])]),
      new Uint8Array([1, 2, 3, 4, 5]),
    ),
  )
})

test('uint32BE round trips boundaries', () => {
  for (const value of [0, 1, 255, 256, 65535, 65536, 0xffff_ffff]) {
    assert.equal(readUint32BE(uint32BE(value)), value)
  }
})

test('uint32BE rejects out-of-range', () => {
  assert.throws(() => uint32BE(-1), /out of range/)
  assert.throws(() => uint32BE(0x1_0000_0000), /out of range/)
  assert.throws(() => uint32BE(1.5), /out of range/)
})

test('uint16BE round trips', () => {
  for (const value of [0, 1, 255, 256, 0xffff]) {
    assert.equal(readUint16BE(uint16BE(value)), value)
  }
})

test('uint64BE round trips boundaries within safe-integer range', () => {
  for (const value of [0, 1, 255, 256, 0xffff_ffff, 0x1_0000_0000, Number.MAX_SAFE_INTEGER]) {
    assert.equal(readUint64BE(uint64BE(value)), value)
  }
})

test('uint64BE writes big-endian byte order', () => {
  // Value 1 should be at the LAST byte
  const buf = uint64BE(1)
  assert.deepEqual(Array.from(buf), [0, 0, 0, 0, 0, 0, 0, 1])

  // Value 256 at second-to-last
  const buf2 = uint64BE(256)
  assert.deepEqual(Array.from(buf2), [0, 0, 0, 0, 0, 0, 1, 0])

  // Value 2^32 at byte index 3
  const buf3 = uint64BE(0x1_0000_0000)
  assert.deepEqual(Array.from(buf3), [0, 0, 0, 1, 0, 0, 0, 0])
})

test('readUint64BE rejects values exceeding MAX_SAFE_INTEGER', () => {
  // High bits all 1 — would overflow a JS Number safely.
  const evil = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
  assert.throws(() => readUint64BE(evil), /MAX_SAFE_INTEGER/)
})

test('read functions reject insufficient bytes', () => {
  assert.throws(() => readUint16BE(new Uint8Array([1])), /insufficient/)
  assert.throws(() => readUint32BE(new Uint8Array([1, 2, 3])), /insufficient/)
  assert.throws(() => readUint64BE(new Uint8Array(7)), /insufficient/)
})
