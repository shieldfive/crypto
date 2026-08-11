/**
 * Regression: the whole-blob decryptors must agree with the streaming
 * decoders about a trailing signature block.
 *
 * Before this fix the blob decryptors (`decryptBlob` / `decryptToBytes`
 * for all four suites, and `autoDecryptBlob`) threw
 * `trailing_bytes_after_last_chunk` on ANY trailing byte, so a file the
 * library's own streaming encoder signed (spec/format-v1.md § "Signature
 * block") could not be decrypted through the primary blob API at all,
 * while a signature-stripped file was silently accepted with no signal.
 *
 * These tests lock the fixed behavior:
 *   - a stream-signed file decrypts through the blob API, and the block is
 *     surfaced (and verified against a pinned key) — suites 0x01 and 0x03,
 *     the two with signing encoders;
 *   - a well-formed appended block is accepted and surfaced on the other
 *     two suites (0x02, 0x04) too;
 *   - a signature-stripped file still decrypts, with `signature: null`;
 *   - malformed trailing garbage is still rejected (the spec MUST).
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptToBytes as decryptToBytesV1,
  encryptBytes as encryptBytesV1,
} from '../../src/suites/aes-gcm-v1/api.js'
import {
  decryptToBytes as decryptToBytesV2,
  encryptBytes as encryptBytesV2,
} from '../../src/suites/aes-gcm-v2/api.js'
import {
  decryptToBytes as decryptToBytesXChaCha,
  encryptBytes as encryptBytesXChaCha,
} from '../../src/suites/xchacha-v1/api.js'
import { decryptToBytes as decryptToBytesPq } from '../../src/suites/pq-hybrid-v1/api.js'
import { encryptStreamAesGcmV1 } from '../../src/streams/aes-gcm-v1.js'
import { encryptStreamPqHybridV1 } from '../../src/streams/pq-hybrid-v1.js'
import type { VerifiedSignature } from '../../src/format/signature-tail.js'
import {
  buildSignatureBlock,
  deriveEd25519PublicKey,
  ED25519_PUBLIC_KEY_LENGTH,
  SIGNATURE_ALGO_ED25519,
} from '../../src/identity/sign.js'
import { generateMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'
import { concatBytes } from '../../src/internal/encoding.js'
import { randomBytes } from '../../src/internal/runtime.js'

/** Serialized length of an Ed25519 signature block: 1 + 2 + 32 + 2 + 64. */
const ED25519_BLOCK_BYTES = 101

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
// Suite 0x01 — signing encoder exists, so we get a real signed file.
// ─────────────────────────────────────────────────────────────────────

test('blob parity (aes-gcm-v1): stream-signed file decrypts via blob API and verifies', async () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)
  const plaintext = randomBytes(1024 * 3 + 57)

  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024, ed25519SecretKey },
  )
  const signedBlob = new Blob([await drain(ciphertext)])

  let surfaced: VerifiedSignature | null = null
  const pt = await decryptToBytesV1({
    blob: signedBlob,
    contentKey,
    expectedSignerPublicKey: ed25519PublicKey,
    onSignature: (s) => {
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt), 'signed file decrypts via blob API')
  const sig = surfaced as VerifiedSignature | null
  assert.ok(sig, 'signature surfaced')
  assert.equal(sig!.algorithm, SIGNATURE_ALGO_ED25519)
  assert.equal(sig!.publicKey.length, ED25519_PUBLIC_KEY_LENGTH)
  assert.ok(bytesEqual(sig!.publicKey, ed25519PublicKey))
  assert.equal(sig!.verified, true)
})

test('blob parity (aes-gcm-v1): signed file surfaces block with verified:null when no expected key', async () => {
  const ed25519SecretKey = randomBytes(32)
  const plaintext = randomBytes(700)

  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 512, ed25519SecretKey },
  )
  const signedBlob = new Blob([await drain(ciphertext)])

  let surfaced: VerifiedSignature | null = null
  const pt = await decryptToBytesV1({
    blob: signedBlob,
    contentKey,
    onSignature: (s) => {
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt))
  const sig = surfaced as VerifiedSignature | null
  assert.ok(sig, 'block parsed and surfaced')
  assert.equal(sig!.verified, null)
  assert.equal(sig!.algorithm, SIGNATURE_ALGO_ED25519)
})

test('blob parity (aes-gcm-v1): signature-stripped file still decrypts with signature:null', async () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)
  const plaintext = randomBytes(1024 + 3)

  const { ciphertext, contentKey } = encryptStreamAesGcmV1(
    streamFrom(plaintext),
    { plaintextSize: plaintext.length, chunkSize: 1024, ed25519SecretKey },
  )
  const signed = await drain(ciphertext)
  const stripped = new Blob([signed.slice(0, signed.length - ED25519_BLOCK_BYTES)])

  let surfaced: VerifiedSignature | null = { algorithm: 0, publicKey: new Uint8Array(), signature: new Uint8Array(), verified: null }
  const pt = await decryptToBytesV1({
    blob: stripped,
    contentKey,
    expectedSignerPublicKey: ed25519PublicKey,
    onSignature: (s) => {
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt), 'stripped file still decrypts')
  assert.equal(surfaced, null, 'no signature after strip — caller can detect it')
})

test('blob parity (aes-gcm-v1): malformed trailing bytes are still rejected', async () => {
  const plaintext = randomBytes(512)
  const { blob, contentKey } = await encryptBytesV1(plaintext, { chunkSize: 1024 })
  const unsigned = new Uint8Array(await blob.arrayBuffer())

  // algorithm=0x01 (Ed25519), pubkey_len=0x0020=32, then truncated → the
  // block cannot parse → the reader must reject (spec MUST), not accept.
  const garbage = concatBytes([unsigned, new Uint8Array([0x01, 0x00, 0x20, 0x00])])

  await assert.rejects(
    () => decryptToBytesV1({ blob: new Blob([garbage]), contentKey }),
    /signature_block_|trailing_bytes_after_signature_block|header error/,
  )
})

// ─────────────────────────────────────────────────────────────────────
// Suite 0x03 — signing encoder exists.
// ─────────────────────────────────────────────────────────────────────

test('blob parity (pq-hybrid-v1): stream-signed file decrypts via blob API and verifies', async () => {
  const ed25519SecretKey = randomBytes(32)
  const ed25519PublicKey = deriveEd25519PublicKey(ed25519SecretKey)
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const plaintext = randomBytes(2048 * 2 + 19)

  const { ciphertext } = await encryptStreamPqHybridV1(streamFrom(plaintext), {
    recipientPublicKey: publicKey,
    envelopeKey,
    plaintextSize: plaintext.length,
    chunkSize: 2048,
    ed25519SecretKey,
  })
  const signedBlob = new Blob([await drain(ciphertext)])

  let surfaced: VerifiedSignature | null = null
  const pt = await decryptToBytesPq({
    blob: signedBlob,
    recipientSecretKey: secretKey,
    envelopeKey,
    expectedSignerPublicKey: ed25519PublicKey,
    onSignature: (s) => {
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt), 'signed pq-hybrid file decrypts via blob API')
  const sig = surfaced as VerifiedSignature | null
  assert.ok(sig)
  assert.ok(bytesEqual(sig!.publicKey, ed25519PublicKey))
  assert.equal(sig!.verified, true)
})

// ─────────────────────────────────────────────────────────────────────
// Suites 0x02 / 0x04 — no signing encoder, so append a well-formed block
// by hand to prove the shared tail-parser accepts + surfaces it there too.
// ─────────────────────────────────────────────────────────────────────

function wellFormedBlock(): Uint8Array {
  return buildSignatureBlock({
    algorithm: SIGNATURE_ALGO_ED25519,
    publicKey: deriveEd25519PublicKey(randomBytes(32)),
    signature: randomBytes(64),
  })
}

test('blob parity (xchacha-v1): a well-formed appended block is accepted and surfaced', async () => {
  const plaintext = randomBytes(777)
  const { blob, contentKey } = await encryptBytesXChaCha(plaintext, { chunkSize: 256 })
  const withBlock = new Blob([
    concatBytes([new Uint8Array(await blob.arrayBuffer()), wellFormedBlock()]),
  ])

  let surfaced: VerifiedSignature | null = null
  const pt = await decryptToBytesXChaCha({
    blob: withBlock,
    contentKey,
    onSignature: (s) => {
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt))
  const sig = surfaced as VerifiedSignature | null
  assert.ok(sig, 'block surfaced instead of throwing')
  assert.equal(sig!.algorithm, SIGNATURE_ALGO_ED25519)
  assert.equal(sig!.verified, null)
})

test('blob parity (aes-gcm-v2): a well-formed appended block is accepted and surfaced', async () => {
  const plaintext = randomBytes(999)
  const { blob, contentKey } = await encryptBytesV2(plaintext, { chunkSize: 256 })
  const withBlock = new Blob([
    concatBytes([new Uint8Array(await blob.arrayBuffer()), wellFormedBlock()]),
  ])

  let surfaced: VerifiedSignature | null = null
  const pt = await decryptToBytesV2({
    blob: withBlock,
    contentKey,
    onSignature: (s) => {
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt))
  const sig = surfaced as VerifiedSignature | null
  assert.ok(sig)
  assert.equal(sig!.verified, null)
})

test('blob parity (aes-gcm-v1): unsigned file surfaces signature:null', async () => {
  const plaintext = randomBytes(2048)
  const { blob, contentKey } = await encryptBytesV1(plaintext, { chunkSize: 512 })

  let called = false
  let surfaced: VerifiedSignature | null = { algorithm: 0, publicKey: new Uint8Array(), signature: new Uint8Array(), verified: null }
  const pt = await decryptToBytesV1({
    blob,
    contentKey,
    onSignature: (s) => {
      called = true
      surfaced = s
    },
  })

  assert.ok(bytesEqual(plaintext, pt))
  assert.ok(called, 'onSignature is always called')
  assert.equal(surfaced, null, 'unsigned file surfaces null')
})
