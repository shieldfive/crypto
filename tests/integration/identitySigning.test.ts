/**
 * Sender-identity signature tests.
 *
 * Covers, per the v1 signature-block spec:
 *
 *   1. happy path: signed encrypt -> verifying decrypt, signature present
 *      and `verified` is true.
 *   2. missing-signature path: legacy encrypt (no signing key) -> decrypt
 *      surfaces `signature: null` and plaintext round-trips intact.
 *   3. wrong-key path: a signed file verified against the wrong public key
 *      surfaces `verified: false`.
 *   4. transcript binding (unit): `SenderSigTranscript` commits to the
 *      ciphertext bytes, and `verifySenderTranscript` rejects a modified
 *      digest.
 *   5. forgery regression: a content-key holder who performs a
 *      tag-preserving GHASH forgery on the ciphertext (changing the
 *      plaintext while leaving every AEAD tag and the signature block
 *      byte-identical) is caught — `verified` is false, not true. This is
 *      the bug the ciphertext-committing transcript fixes.
 *
 * Both stream suites (aes-256-gcm-v1 and pq-hybrid-xchacha-mlkem1024-v1)
 * are covered.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'
import { createCipheriv } from 'node:crypto'

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
  SenderSigTranscript,
  signSenderTranscript,
  SIGNATURE_ALGO_ED25519,
  verifySenderTranscript,
} from '../../src/identity/sign.js'
import { generateMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'
import { AES_GCM_V1_SUITE_PAYLOAD_LENGTH as AES_SUITE_PAYLOAD_LEN } from '../../src/suites/aes-gcm-v1/index.js'
import { hkdfSha256 } from '../../src/internal/hkdf.js'
import { HEADER_SIZES, HKDF_INFO } from '../../src/internal/types.js'
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
// 3. Wrong-key path
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

// ─────────────────────────────────────────────────────────────────────
// 4. Transcript binding (unit)
// ─────────────────────────────────────────────────────────────────────

test('SenderSigTranscript commits to ciphertext body, not just the tag', () => {
  const header = randomBytes(120)
  const ct = new Uint8Array(64) // 48-byte body + 16-byte tag
  ct.set(randomBytes(64), 0)

  const build = (chunk: Uint8Array): Uint8Array => {
    const t = new SenderSigTranscript()
    t.absorbHeader(header, 1)
    t.absorbChunk(0, chunk)
    return t.digest()
  }

  const d1 = build(ct)

  // Flip a single ciphertext BODY byte; keep the 16-byte tag identical.
  const ct2 = new Uint8Array(ct)
  ct2[0] ^= 0x01
  const d2 = build(ct2)

  assert.ok(!bytesEqual(d1, d2), 'a body-only change must change the digest')
})

test('verifySenderTranscript rejects a modified transcript digest', () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)

  const digest = randomBytes(32)
  const signature = signSenderTranscript({
    ed25519SecretKey,
    transcriptDigest: digest,
  })
  assert.equal(
    verifySenderTranscript({
      ed25519PublicKey,
      transcriptDigest: digest,
      signature,
    }),
    true,
  )

  const tampered = new Uint8Array(digest)
  tampered[0] ^= 0x01
  assert.equal(
    verifySenderTranscript({
      ed25519PublicKey,
      transcriptDigest: tampered,
      signature,
    }),
    false,
  )
})

// ─────────────────────────────────────────────────────────────────────
// 5. Forgery regression: tag-preserving ciphertext modification
// ─────────────────────────────────────────────────────────────────────

// GF(2^128) multiply in the GCM bit convention (right-shift, R = 0xe1).
function gfmul(x: Uint8Array, y: Uint8Array): Uint8Array {
  const z = new Uint8Array(16)
  const v = new Uint8Array(y)
  for (let i = 0; i < 128; i += 1) {
    const bit = (x[i >> 3]! >> (7 - (i & 7))) & 1
    if (bit) for (let j = 0; j < 16; j += 1) z[j]! ^= v[j]!
    const lsb = v[15]! & 1
    for (let j = 15; j > 0; j -= 1) {
      v[j] = ((v[j]! >> 1) | ((v[j - 1]! & 1) << 7)) & 0xff
    }
    v[0] = v[0]! >> 1
    if (lsb) v[0]! ^= 0xe1
  }
  return z
}

test('identity signing (aes-gcm-v1): tag-preserving ciphertext forgery does NOT verify', async () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)

  // Single chunk, 48-byte plaintext = 3 full AES blocks.
  const plaintext = new Uint8Array(48)
  for (let i = 0; i < plaintext.length; i += 1) plaintext[i] = i
  const { ciphertext, contentKey, fileId } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024, ed25519SecretKey },
  )
  const wire = await drain(ciphertext)

  // Wire layout: header, then a 4-byte length prefix, then the single
  // chunk's ciphertext (48-byte body + 16-byte tag), then the sig block.
  const headerLen =
    HEADER_SIZES.MAGIC +
    HEADER_SIZES.SUITE +
    HEADER_SIZES.FLAGS +
    HEADER_SIZES.FILE_ID +
    HEADER_SIZES.CHUNK_SIZE +
    HEADER_SIZES.TOTAL_CHUNKS +
    HEADER_SIZES.PLAINTEXT_SIZE +
    HEADER_SIZES.SUITE_PAYLOAD_LEN +
    AES_SUITE_PAYLOAD_LEN +
    HEADER_SIZES.HEADER_MAC
  const ctStart = headerLen + 4 // skip the 4-byte length prefix
  const tagStart = ctStart + 48
  const originalTag = wire.slice(tagStart, tagStart + 16)
  const originalSigBlock = wire.slice(tagStart + 16)

  // Attacker holds contentKey + fileId (NOT the Ed25519 signing key).
  // Re-derive the per-chunk AES key exactly as the library does, then
  // compute the GHASH subkey H = AES-256-ECB(chunkKey, 0^16).
  const chunkKey = await hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.AES_GCM_CHUNK_KEY,
    length: 32,
  })
  const ecb = createCipheriv('aes-256-ecb', chunkKey, null)
  ecb.setAutoPadding(false)
  const H = new Uint8Array(ecb.update(new Uint8Array(16)))
  ecb.final()

  // Tag-preserving forgery: XOR a chosen delta into ciphertext block 0 and
  // the GF compensator delta*H into block 1. Adjacent GHASH blocks differ
  // by exactly one power of H, so this leaves the 16-byte GCM tag identical
  // while turning block 0's plaintext into attacker-chosen bytes.
  const delta0 = new Uint8Array(16).fill(0xaa)
  const delta1 = gfmul(delta0, H)
  const forged = new Uint8Array(wire)
  for (let j = 0; j < 16; j += 1) {
    forged[ctStart + j]! ^= delta0[j]!
    forged[ctStart + 16 + j]! ^= delta1[j]!
  }

  const { plaintext: ptStream, metadata } = decryptStreamAesGcmV1(
    streamFrom(forged),
    { contentKey, expectedSignerPublicKey: ed25519PublicKey },
  )
  const pt = await drain(ptStream)

  // The forgery kept the AEAD tag valid, so decrypt still succeeds and both
  // the tag and the whole signature block are byte-identical to the
  // original...
  assert.ok(
    bytesEqual(originalTag, forged.slice(tagStart, tagStart + 16)),
    'AEAD tag unchanged by the forgery',
  )
  assert.ok(
    bytesEqual(originalSigBlock, forged.slice(tagStart + 16)),
    'signature block unchanged by the forgery',
  )
  assert.ok(!bytesEqual(plaintext, pt), 'plaintext was actually modified')

  // ...but the signature now commits to the ciphertext, so the rebuilt
  // transcript no longer matches the signed one: attribution fails.
  const m = await metadata
  assert.ok(m.signature)
  assert.equal(m.signature.verified, false)
})
