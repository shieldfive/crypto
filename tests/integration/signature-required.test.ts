/**
 * `signatureRequired`: callers that rely on sender attribution can make
 * decryption fail on an unsigned, stripped, wrongly-signed or unverifiable
 * file instead of checking `signature.verified` themselves.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import { decryptToBytes as decryptToBytesV1 } from '../../src/suites/aes-gcm-v1/api.js'
import { decryptToBytes as decryptToBytesPq } from '../../src/suites/pq-hybrid-v1/api.js'
import {
  createAesGcmV1DecryptStream,
  encryptStreamAesGcmV1,
} from '../../src/streams/aes-gcm-v1.js'
import {
  createPqHybridV1DecryptStream,
  encryptStreamPqHybridV1,
} from '../../src/streams/pq-hybrid-v1.js'
import { deriveEd25519PublicKey } from '../../src/identity/sign.js'
import { generateMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'
import { randomBytes } from '../../src/internal/runtime.js'

const ED25519_BLOCK_BYTES = 101

async function drain(s: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const parts: Uint8Array[] = []
  let total = 0
  const reader = s.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    parts.push(value)
    total += value.length
  }
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function streamFrom(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    pull(c) {
      c.enqueue(bytes)
      c.close()
    },
  })
}

async function signedV1(ed25519SecretKey?: Uint8Array) {
  const plaintext = randomBytes(2500)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(streamFrom(plaintext), {
    plaintextSize: plaintext.length,
    chunkSize: 1024,
    ...(ed25519SecretKey ? { ed25519SecretKey } : {}),
  })
  return { plaintext, ct: await drain(ciphertext), contentKey }
}

function codeOf(err: unknown): string | undefined {
  return (err as { code?: string }).code
}

test('signatureRequired (blob v1): verified signature decrypts', async () => {
  const sk = randomBytes(32)
  const { plaintext, ct, contentKey } = await signedV1(sk)
  const pt = await decryptToBytesV1({
    blob: new Blob([ct]),
    contentKey,
    expectedSignerPublicKey: deriveEd25519PublicKey(sk),
    signatureRequired: true,
  })
  assert.deepEqual(pt, plaintext)
})

test('signatureRequired (blob v1): unsigned file is rejected', async () => {
  const { ct, contentKey } = await signedV1()
  await assert.rejects(
    decryptToBytesV1({
      blob: new Blob([ct]),
      contentKey,
      expectedSignerPublicKey: deriveEd25519PublicKey(randomBytes(32)),
      signatureRequired: true,
    }),
    (err) => codeOf(err) === 'signature_required_missing',
  )
})

test('signatureRequired (blob v1): stripped signature is rejected, but decrypts without the flag', async () => {
  const sk = randomBytes(32)
  const { ct, contentKey } = await signedV1(sk)
  const stripped = ct.subarray(0, ct.length - ED25519_BLOCK_BYTES)
  // Backward compatible default: still decrypts.
  await decryptToBytesV1({ blob: new Blob([stripped]), contentKey })
  await assert.rejects(
    decryptToBytesV1({
      blob: new Blob([stripped]),
      contentKey,
      expectedSignerPublicKey: deriveEd25519PublicKey(sk),
      signatureRequired: true,
    }),
    (err) => codeOf(err) === 'signature_required_missing',
  )
})

test('signatureRequired (blob v1): wrong signer is rejected', async () => {
  const { ct, contentKey } = await signedV1(randomBytes(32))
  await assert.rejects(
    decryptToBytesV1({
      blob: new Blob([ct]),
      contentKey,
      expectedSignerPublicKey: deriveEd25519PublicKey(randomBytes(32)),
      signatureRequired: true,
    }),
    (err) => codeOf(err) === 'signature_required_invalid',
  )
})

test('signatureRequired without expectedSignerPublicKey is a caller error', async () => {
  const { ct, contentKey } = await signedV1(randomBytes(32))
  await assert.rejects(
    decryptToBytesV1({ blob: new Blob([ct]), contentKey, signatureRequired: true }),
    RangeError,
  )
  assert.throws(
    () => createAesGcmV1DecryptStream({ contentKey, signatureRequired: true }),
    RangeError,
  )
})

test('signatureRequired (stream v1): wrong signer errors the stream and metadata', async () => {
  const { ct, contentKey } = await signedV1(randomBytes(32))
  const { stream, metadata } = createAesGcmV1DecryptStream({
    contentKey,
    expectedSignerPublicKey: deriveEd25519PublicKey(randomBytes(32)),
    signatureRequired: true,
  })
  await assert.rejects(drain(streamFrom(ct).pipeThrough(stream)))
  await assert.rejects(metadata, (err) => codeOf(err) === 'signature_required_invalid')
})

test('signatureRequired (stream + blob pq-hybrid): signed passes, unsigned fails', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const sk = randomBytes(32)
  const plaintext = randomBytes(3000)
  const enc = async (signer?: Uint8Array) =>
    drain(
      (
        await encryptStreamPqHybridV1(streamFrom(plaintext), {
          recipientPublicKey: publicKey,
          envelopeKey,
          plaintextSize: plaintext.length,
          chunkSize: 1024,
          ...(signer ? { ed25519SecretKey: signer } : {}),
        })
      ).ciphertext,
    )
  const signed = await enc(sk)
  const unsigned = await enc()
  const opts = {
    recipientSecretKey: secretKey,
    envelopeKey,
    expectedSignerPublicKey: deriveEd25519PublicKey(sk),
    signatureRequired: true,
  }

  const ok = createPqHybridV1DecryptStream(opts)
  assert.deepEqual(await drain(streamFrom(signed).pipeThrough(ok.stream)), plaintext)
  assert.equal((await ok.metadata).signature?.verified, true)

  const bad = createPqHybridV1DecryptStream(opts)
  await assert.rejects(drain(streamFrom(unsigned).pipeThrough(bad.stream)))
  await assert.rejects(bad.metadata, (err) => codeOf(err) === 'signature_required_missing')

  await assert.rejects(
    decryptToBytesPq({ blob: new Blob([unsigned]), ...opts }),
    (err) => codeOf(err) === 'signature_required_missing',
  )
  assert.deepEqual(await decryptToBytesPq({ blob: new Blob([signed]), ...opts }), plaintext)
})
