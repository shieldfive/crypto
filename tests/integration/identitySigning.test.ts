/**
 * Sender-identity signature tests.
 *
 * Covers four cases per the v1 signature-block spec:
 *
 *   1. happy path: signed encrypt -> verifying decrypt, signature present
 *      and `verified` is true.
 *   2. missing-signature path: legacy encrypt (no signing key) -> decrypt
 *      surfaces `signature: null` and plaintext round-trips intact.
 *   3. tampered-MAC path: `verifyHeaderAndMacs` over a flipped chunk MAC
 *      returns false (the AEAD layer already prevents the runtime from
 *      ever reaching that state on a real stream — this is a unit check
 *      of the signature primitive's binding to the chunk MACs).
 *   4. tampered-header path: `verifyHeaderAndMacs` over a flipped header
 *      returns false (likewise, a real stream's header MAC catches this
 *      first; we exercise the signature primitive directly here).
 *
 * Both stream suites (aes-256-gcm-v1 and pq-hybrid-xchacha-mlkem1024-v1)
 * are covered.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptStreamAesGcmV1,
  encryptStreamAesGcmV1,
} from '../../src/streams/aes-gcm-v1.js'
import {
  decryptStreamPqHybridV1,
  encryptStreamPqHybridV1,
} from '../../src/streams/pq-hybrid-v1.js'
import {
  deriveEd25519PublicKey,
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_SIGNATURE_LENGTH,
  signHeaderAndMacs,
  SIGNATURE_ALGO_ED25519,
  verifyHeaderAndMacs,
} from '../../src/identity/sign.js'
import { generateMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

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

function streamFrom(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
}

// ─────────────────────────────────────────────────────────────────────
// 1. Happy path
// ─────────────────────────────────────────────────────────────────────

test('identity signing (aes-gcm-v1): happy-path roundtrip with verifying key', async () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)

  const plaintext = randomBytes(4096 + 137)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    {
      plaintextSize: plaintext.length,
      chunkSize: 1024,
      ed25519SecretKey,
    },
  )
  const ct = await drain(ciphertext)

  const { plaintext: ptStream, metadata } = decryptStreamAesGcmV1(
    streamFrom(ct),
    {
      contentKey,
      expectedSignerPublicKey: ed25519PublicKey,
    },
  )
  const pt = await drain(ptStream)
  assert.ok(bytesEqual(plaintext, pt))

  const m = await metadata
  assert.ok(m.signature, 'signature metadata present')
  assert.equal(m.signature.algorithm, SIGNATURE_ALGO_ED25519)
  assert.equal(m.signature.publicKey.length, ED25519_PUBLIC_KEY_LENGTH)
  assert.equal(m.signature.signature.length, ED25519_SIGNATURE_LENGTH)
  assert.ok(bytesEqual(m.signature.publicKey, ed25519PublicKey))
  assert.equal(m.signature.verified, true)
})

test('identity signing (pq-hybrid-v1): happy-path roundtrip with verifying key', async () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)

  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(2048 * 3 + 11)

  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 2048,
    ed25519SecretKey,
  })
  const ct = await drain(ciphertext)

  const { plaintext: ptStream, metadata } = decryptStreamPqHybridV1(
    streamFrom(ct),
    {
      recipientSecretKey: secretKey,
      envelopeKey,
      expectedSignerPublicKey: ed25519PublicKey,
    },
  )
  const pt = await drain(ptStream)
  assert.ok(bytesEqual(plaintext, pt))

  const m = await metadata
  assert.ok(m.signature)
  assert.equal(m.signature.algorithm, SIGNATURE_ALGO_ED25519)
  assert.ok(bytesEqual(m.signature.publicKey, ed25519PublicKey))
  assert.equal(m.signature.verified, true)
})

test('identity signing (aes-gcm-v1): signature parsed but not verified when expectedSignerPublicKey omitted', async () => {
  const ed25519SecretKey = randomBytes(32)
  const plaintext = randomBytes(700)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 512, ed25519SecretKey },
  )
  const ct = await drain(ciphertext)

  const { plaintext: ptStream, metadata } = decryptStreamAesGcmV1(
    streamFrom(ct),
    { contentKey },
  )
  await drain(ptStream)
  const m = await metadata
  assert.ok(m.signature)
  assert.equal(m.signature.verified, null)
  assert.equal(m.signature.algorithm, SIGNATURE_ALGO_ED25519)
})

// ─────────────────────────────────────────────────────────────────────
// 2. Missing-signature path
// ─────────────────────────────────────────────────────────────────────

test('identity signing (aes-gcm-v1): legacy (unsigned) file decrypts with signature: null', async () => {
  // No ed25519SecretKey passed to encrypt: no signature block is appended.
  const plaintext = randomBytes(1500)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 512 },
  )
  const ct = await drain(ciphertext)

  const { plaintext: ptStream, metadata } = decryptStreamAesGcmV1(
    streamFrom(ct),
    { contentKey, expectedSignerPublicKey: randomBytes(32) },
  )
  const pt = await drain(ptStream)
  assert.ok(bytesEqual(plaintext, pt))

  const m = await metadata
  assert.equal(m.signature, null)
})

test('identity signing (pq-hybrid-v1): legacy (unsigned) file decrypts with signature: null', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(1500)

  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 512,
  })
  const ct = await drain(ciphertext)

  const { plaintext: ptStream, metadata } = decryptStreamPqHybridV1(
    streamFrom(ct),
    { recipientSecretKey: secretKey, envelopeKey },
  )
  const pt = await drain(ptStream)
  assert.ok(bytesEqual(plaintext, pt))

  const m = await metadata
  assert.equal(m.signature, null)
})

// ─────────────────────────────────────────────────────────────────────
// 3. Tampered-MAC path
// ─────────────────────────────────────────────────────────────────────

test('identity signing: verifyHeaderAndMacs rejects flipped chunk MAC', () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)

  const header = randomBytes(120)
  const chunkMacs = [randomBytes(16), randomBytes(16), randomBytes(16)]
  const signature = signHeaderAndMacs({
    ed25519SecretKey,
    header,
    chunkMacs,
  })
  // Sanity: untampered verifies.
  assert.equal(
    verifyHeaderAndMacs({
      ed25519PublicKey,
      header,
      chunkMacs,
      signature,
    }),
    true,
  )
  // Flip a single bit in chunk index 1's MAC.
  const tamperedMac = new Uint8Array(chunkMacs[1]!)
  tamperedMac[0] ^= 0x01
  const tampered = [chunkMacs[0]!, tamperedMac, chunkMacs[2]!]
  assert.equal(
    verifyHeaderAndMacs({
      ed25519PublicKey,
      header,
      chunkMacs: tampered,
      signature,
    }),
    false,
  )
})

// ─────────────────────────────────────────────────────────────────────
// 4. Tampered-header path
// ─────────────────────────────────────────────────────────────────────

test('identity signing: verifyHeaderAndMacs rejects flipped header byte', () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)

  const header = randomBytes(96)
  const chunkMacs = [randomBytes(16), randomBytes(16)]
  const signature = signHeaderAndMacs({
    ed25519SecretKey,
    header,
    chunkMacs,
  })
  assert.equal(
    verifyHeaderAndMacs({
      ed25519PublicKey,
      header,
      chunkMacs,
      signature,
    }),
    true,
  )
  const tamperedHeader = new Uint8Array(header)
  tamperedHeader[10] ^= 0x80
  assert.equal(
    verifyHeaderAndMacs({
      ed25519PublicKey,
      header: tamperedHeader,
      chunkMacs,
      signature,
    }),
    false,
  )
})

// ─────────────────────────────────────────────────────────────────────
// End-to-end verification failure
// ─────────────────────────────────────────────────────────────────────

test('identity signing (aes-gcm-v1): verify against wrong public key sets verified=false', async () => {
  const ed25519SecretKey = randomBytes(32)
  const otherPublicKey = deriveEd25519PublicKey(randomBytes(32))

  const plaintext = randomBytes(900)
  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 512, ed25519SecretKey },
  )
  const ct = await drain(ciphertext)

  const { plaintext: ptStream, metadata } = decryptStreamAesGcmV1(
    streamFrom(ct),
    { contentKey, expectedSignerPublicKey: otherPublicKey },
  )
  // Plaintext still round-trips: the AEAD + header MAC are independent
  // of the signature layer. Only `verified` reflects the failed identity
  // check.
  const pt = await drain(ptStream)
  assert.ok(bytesEqual(plaintext, pt))

  const m = await metadata
  assert.ok(m.signature)
  assert.equal(m.signature.verified, false)
})
