// Writers must run the same suite_payload check as their readers: a
// suitePayloadOverride with the right length but a non-zero reserved pad used
// to produce a file the library's own decoder refused. Each encoder now
// rejects it up front; a zero-pad override still round-trips.
import { strict as assert } from 'node:assert'
import test from 'node:test'

import * as aesV1 from '../../src/suites/aes-gcm-v1/api.js'
import * as aesV2 from '../../src/suites/aes-gcm-v2/api.js'
import * as xchacha from '../../src/suites/xchacha-v1/api.js'
import { createAesGcmV1EncryptStream } from '../../src/streams/aes-gcm-v1.js'
import { randomBytes } from '../../src/internal/runtime.js'

const blob = () => new Blob([new Uint8Array([1, 2, 3, 4, 5])])

// Byte 48 is the first reserved pad byte in all three payload layouts.
function payload(length: number, padByte: number): Uint8Array {
  const bytes = new Uint8Array(length)
  bytes.set(randomBytes(48), 0)
  bytes[48] = padByte
  return bytes
}

const suites = [
  { name: 'aes-gcm-v1', api: aesV1, length: 72, pad: /aes-gcm-v1: reserved wrapped_key pad must be zero/ },
  { name: 'aes-gcm-v2', api: aesV2, length: 72, pad: /aes-gcm-v2: reserved wrapped_key pad must be zero/ },
  { name: 'xchacha-v1', api: xchacha, length: 96, pad: /xchacha-v1: reserved wrapped_key pad must be zero/ },
] as const

for (const { name, api, length, pad } of suites) {
  test(`${name} encryptBlob: rejects a suitePayloadOverride with a non-zero reserved pad`, async () => {
    await assert.rejects(
      () => api.encryptBlob({ blob: blob(), suitePayloadOverride: payload(length, 1) }),
      pad,
    )
  })

  test(`${name} encryptBlob: a zero-pad suitePayloadOverride still round-trips`, async () => {
    const result = await api.encryptBlob({
      blob: blob(),
      suitePayloadOverride: payload(length, 0),
    })
    const plaintext = await api.decryptToBytes({
      blob: result.blob,
      contentKey: result.contentKey,
    })
    assert.deepEqual(plaintext, new Uint8Array([1, 2, 3, 4, 5]))
  })
}

test('aes-gcm-v1 stream encrypt: rejects a suitePayloadOverride with a non-zero reserved pad', () => {
  assert.throws(
    () =>
      createAesGcmV1EncryptStream({
        plaintextSize: 10,
        contentKey: randomBytes(32),
        suitePayloadOverride: payload(72, 1),
      }),
    /aes-gcm-v1: reserved wrapped_key pad must be zero/,
  )
})
