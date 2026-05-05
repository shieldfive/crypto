/**
 * Unit tests for the header parser. The parser is the first line of
 * defense against malformed/malicious blobs; every error code it can
 * emit must be covered.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  buildAuthenticatedHeader,
  buildHeaderUnauthenticated,
  HeaderError,
  parseHeader,
} from '../../src/format/header.js'
import { FORMAT_MAGIC, SUITE } from '../../src/internal/types.js'
import { randomBytes } from '../../src/internal/runtime.js'

const VALID_INPUTS = {
  suite: SUITE.AES_256_GCM_V1,
  fileId: new Uint8Array(16),
  chunkSize: 1024,
  totalChunks: 4,
  plaintextSize: 4 * 1024,
  suitePayload: new Uint8Array(72),
} as const

test('parseHeader rejects truncated input', () => {
  assert.throws(
    () => parseHeader(new Uint8Array(10)),
    (err: unknown) =>
      err instanceof HeaderError && err.code === 'header_too_short',
  )
})

test('parseHeader rejects bad magic', () => {
  const valid = buildHeaderUnauthenticated(VALID_INPUTS)
  const macAppended = new Uint8Array(valid.length + 32)
  macAppended.set(valid)
  // Corrupt the magic
  macAppended[0] = 0xff
  assert.throws(
    () => parseHeader(macAppended),
    (err: unknown) => err instanceof HeaderError && err.code === 'bad_magic',
  )
})

test('parseHeader rejects unknown suite', () => {
  const valid = buildHeaderUnauthenticated(VALID_INPUTS)
  const munged = new Uint8Array(valid.length + 32)
  munged.set(valid)
  // Suite byte is at offset 5 (after the 5-byte magic)
  munged[5] = 0xfe
  assert.throws(
    () => parseHeader(munged),
    (err: unknown) =>
      err instanceof HeaderError && err.code === 'unknown_suite',
  )
})

test('parseHeader rejects reserved flags set', () => {
  const valid = buildHeaderUnauthenticated(VALID_INPUTS)
  const munged = new Uint8Array(valid.length + 32)
  munged.set(valid)
  // Flags byte is at offset 6
  munged[6] = 0x01
  assert.throws(
    () => parseHeader(munged),
    (err: unknown) =>
      err instanceof HeaderError && err.code === 'reserved_flags_set',
  )
})

test('parseHeader rejects inconsistent plaintext_size', async () => {
  // total_chunks=2, chunk_size=1024 means plaintext must be in [1025, 2048].
  // We'll set it to 4096 — exceeds bound.
  const inputs = {
    ...VALID_INPUTS,
    totalChunks: 2,
    plaintextSize: 4096,
  }
  // buildHeaderUnauthenticated does NOT validate cross-field consistency
  // for plaintext_size — that's the parser's job. Build it manually.
  const built = buildHeaderUnauthenticated(inputs)
  const macAppended = new Uint8Array(built.length + 32)
  macAppended.set(built)
  assert.throws(
    () => parseHeader(macAppended),
    (err: unknown) =>
      err instanceof HeaderError && err.code === 'plaintext_size_inconsistent',
  )
})

test('parseHeader rejects total_chunks=0 with plaintext>0', () => {
  const built = buildHeaderUnauthenticated({
    ...VALID_INPUTS,
    totalChunks: 0,
    plaintextSize: 100,
  })
  const macAppended = new Uint8Array(built.length + 32)
  macAppended.set(built)
  assert.throws(
    () => parseHeader(macAppended),
    (err: unknown) =>
      err instanceof HeaderError && err.code === 'total_chunks_zero_with_plaintext',
  )
})

test('parseHeader returns expected fields on valid input', async () => {
  const fileId = randomBytes(16)
  const built = await buildAuthenticatedHeader(
    {
      suite: SUITE.AES_256_GCM_V1,
      fileId,
      chunkSize: 4096,
      totalChunks: 3,
      plaintextSize: 4096 * 2 + 17,
      suitePayload: new Uint8Array(72),
    },
    new Uint8Array(32), // any 32-byte key for MAC
  )
  const parsed = parseHeader(built)
  assert.equal(parsed.suite, SUITE.AES_256_GCM_V1)
  assert.equal(parsed.flags, 0)
  assert.equal(parsed.chunkSize, 4096)
  assert.equal(parsed.totalChunks, 3)
  assert.equal(parsed.plaintextSize, 4096 * 2 + 17)
  assert.equal(parsed.suitePayload.length, 72)
  assert.equal(parsed.headerLength, built.length)
})

test('FORMAT_MAGIC is the documented byte sequence', () => {
  assert.deepEqual(Array.from(FORMAT_MAGIC), [0x53, 0x46, 0x35, 0x01, 0x00])
})
