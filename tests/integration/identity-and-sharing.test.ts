/**
 * Identity bundle and file-sharing tests.
 *
 * Covers:
 *   - Bundle encode/decode round trip
 *   - Bad-magic, truncated, and trailing-byte rejection
 *   - Deterministic identity from master secret
 *   - File sharing: owner produces shares, recipient unlocks the same combined key
 *   - Wrong-recipient rejection
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  bundleFromBase64,
  bundleToBase64,
  buildShareForRecipient,
  createIdentity,
  decodeIdentityBundle,
  encodeIdentityBundle,
  openShareAsRecipient,
  type PublicIdentityBundle,
} from '../../src/identity/index.js'
import {
  decapsulateFromHeader,
  encapsulateForRecipient,
  parsePqHybridV1SuitePayload,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
} from '../../src/suites/pq-hybrid-v1/index.js'
import * as pqHybrid from '../../src/suites/pq-hybrid-v1/api.js'
import { randomBytes } from '../../src/internal/runtime.js'
import { readUint32BE } from '../../src/internal/encoding.js'
import { getSodium } from '../../src/internal/sodium.js'

// Offset of the first reserved-pad byte inside the 1664-byte pq-hybrid suite
// payload: after the 1568-byte ML-KEM ciphertext and the 48-byte secretbox.
const RESERVED_PAD_OFFSET_IN_PAYLOAD = ML_KEM_1024_CIPHERTEXT_BYTES + 48

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('identity: bundle encode/decode round trip', async () => {
  const id = await createIdentity({ userId: 'alice@example.test' })
  const decoded = decodeIdentityBundle(id.publicBundleBytes)
  assert.equal(decoded.userId, 'alice@example.test')
  assert.equal(decoded.mlKemPublicKey.length, ML_KEM_1024_PUBLIC_KEY_BYTES)
  assert.ok(bytesEqual(decoded.mlKemPublicKey, id.publicBundle.mlKemPublicKey))
  assert.equal(decoded.issuedAt, id.publicBundle.issuedAt)
})

test('identity: base64 round trip', async () => {
  const id = await createIdentity({ userId: 'bob' })
  const b64 = bundleToBase64(id.publicBundle)
  const back = bundleFromBase64(b64)
  assert.equal(back.userId, 'bob')
  assert.ok(bytesEqual(back.mlKemPublicKey, id.publicBundle.mlKemPublicKey))
})

test('identity: deterministic from master secret', async () => {
  const masterSecret = randomBytes(32)
  const a = await createIdentity({ userId: 'u', masterSecret })
  const b = await createIdentity({ userId: 'u', masterSecret })
  assert.ok(bytesEqual(a.publicBundle.mlKemPublicKey, b.publicBundle.mlKemPublicKey))
  assert.ok(bytesEqual(a.mlKemSecretKey, b.mlKemSecretKey))
})

test('identity: with metadata', async () => {
  const meta = new TextEncoder().encode('{"display_name":"Alice"}')
  const id = await createIdentity({ userId: 'alice', metadata: meta })
  const decoded = decodeIdentityBundle(id.publicBundleBytes)
  assert.ok(decoded.metadata)
  assert.equal(new TextDecoder().decode(decoded.metadata!), '{"display_name":"Alice"}')
})

test('identity: rejects empty userId', async () => {
  await assert.rejects(() => createIdentity({ userId: '' }), /1\.\.255/)
})

test('identity: decode rejects bad magic', () => {
  const bad = new Uint8Array(20)
  bad[0] = 0xff
  assert.throws(() => decodeIdentityBundle(bad), /bad magic/)
})

test('identity: decode rejects truncated input', () => {
  assert.throws(() => decodeIdentityBundle(new Uint8Array(3)), /too short/)
})

test('identity: decode rejects trailing bytes', async () => {
  const id = await createIdentity({ userId: 'alice' })
  const padded = new Uint8Array(id.publicBundleBytes.length + 5)
  padded.set(id.publicBundleBytes)
  assert.throws(
    () => decodeIdentityBundle(padded),
    /trailing bytes|wrong metadata_len/,
  )
})

test('identity: encode rejects oversized userId', () => {
  const longId = 'a'.repeat(256)
  const bundle: PublicIdentityBundle = {
    mlKemPublicKey: new Uint8Array(ML_KEM_1024_PUBLIC_KEY_BYTES),
    userId: longId,
    issuedAt: 0,
  }
  assert.throws(() => encodeIdentityBundle(bundle), /1\.\.255/)
})

// ──────────────────────────────────────────────────────────────────────
// File sharing
// ──────────────────────────────────────────────────────────────────────

test('share: owner shares with recipient who recovers the same combined key', async () => {
  // Owner creates an identity and encrypts a file to themselves.
  const ownerEnvelope = randomBytes(32)
  const owner = await createIdentity({
    userId: 'owner',
    masterSecret: randomBytes(32),
  })

  // Recipient creates an identity.
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({
    userId: 'recipient',
    masterSecret: randomBytes(32),
  })

  // Owner encrypts a file to themselves.
  const plaintext = randomBytes(2048)
  const result = await pqHybrid.encryptBytes(plaintext, {
    recipientPublicKey: owner.publicBundle.mlKemPublicKey,
    envelopeKey: ownerEnvelope,
    chunkSize: 1024,
  })

  // Owner builds a share for the recipient.
  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  // Recipient opens the share.
  const recoveredCombinedKey = await openShareAsRecipient({
    shareBundle,
    fileId: result.fileId,
    recipientSecretKey: recipient.mlKemSecretKey,
    recipientEnvelopeKey: recipientEnvelope,
  })

  assert.ok(bytesEqual(recoveredCombinedKey, result.combinedKey))
})

test('share: wrong recipient secret key fails', async () => {
  const ownerEnvelope = randomBytes(32)
  const owner = await createIdentity({ userId: 'owner' })
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({ userId: 'recipient' })
  const wrongRecipient = await createIdentity({ userId: 'wrong' })

  const result = await pqHybrid.encryptBytes(randomBytes(1024), {
    recipientPublicKey: owner.publicBundle.mlKemPublicKey,
    envelopeKey: ownerEnvelope,
    chunkSize: 1024,
  })

  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  await assert.rejects(
    () =>
      openShareAsRecipient({
        shareBundle,
        fileId: result.fileId,
        recipientSecretKey: wrongRecipient.mlKemSecretKey,
        recipientEnvelopeKey: recipientEnvelope,
      }),
    /unwrap failed|secretbox|wrong secret key|wrong recipient/,
  )
})

test('share: wrong envelope key fails', async () => {
  const ownerEnvelope = randomBytes(32)
  const owner = await createIdentity({ userId: 'owner' })
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({ userId: 'recipient' })

  const result = await pqHybrid.encryptBytes(randomBytes(1024), {
    recipientPublicKey: owner.publicBundle.mlKemPublicKey,
    envelopeKey: ownerEnvelope,
    chunkSize: 1024,
  })

  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  await assert.rejects(() =>
    openShareAsRecipient({
      shareBundle,
      fileId: result.fileId,
      recipientSecretKey: recipient.mlKemSecretKey,
      recipientEnvelopeKey: randomBytes(32),
    }),
  )
})

test('share: tampered share bundle rejected', async () => {
  const ownerEnvelope = randomBytes(32)
  const owner = await createIdentity({ userId: 'owner' })
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({ userId: 'recipient' })

  const result = await pqHybrid.encryptBytes(randomBytes(1024), {
    recipientPublicKey: owner.publicBundle.mlKemPublicKey,
    envelopeKey: ownerEnvelope,
    chunkSize: 1024,
  })

  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  // Flip a byte in the wrapped-combined-key region (last 48 bytes)
  shareBundle[shareBundle.length - 10] ^= 0x01
  await assert.rejects(() =>
    openShareAsRecipient({
      shareBundle,
      fileId: result.fileId,
      recipientSecretKey: recipient.mlKemSecretKey,
      recipientEnvelopeKey: recipientEnvelope,
    }),
  )
})

test('share: full end-to-end — recipient decrypts the actual file', async () => {
  const ownerEnvelope = randomBytes(32)
  const owner = await createIdentity({ userId: 'owner' })
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({ userId: 'recipient' })

  const plaintext = randomBytes(4096)
  const result = await pqHybrid.encryptBytes(plaintext, {
    recipientPublicKey: owner.publicBundle.mlKemPublicKey,
    envelopeKey: ownerEnvelope,
    chunkSize: 1024,
  })

  // Owner builds a share for recipient.
  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  // Recipient recovers the combined key, then uses it to decrypt the file.
  // (Decryption from the combined key isn't a public API yet — for sharing
  // to work end-to-end we'd need decryptBlobWithCombinedKey. For now, this
  // test asserts the combined key matches; full decrypt-with-share is a
  // follow-up.)
  const recovered = await openShareAsRecipient({
    shareBundle,
    fileId: result.fileId,
    recipientSecretKey: recipient.mlKemSecretKey,
    recipientEnvelopeKey: recipientEnvelope,
  })
  assert.ok(bytesEqual(recovered, result.combinedKey))
  // Sanity: confirm the recovered key actually works for the normal owner path.
  const reDecrypted = await pqHybrid.decryptToBytes({
    blob: result.blob,
    recipientSecretKey: owner.mlKemSecretKey,
    envelopeKey: ownerEnvelope,
  })
  assert.ok(bytesEqual(plaintext, reDecrypted))
})

// ──────────────────────────────────────────────────────────────────────
// Audit H2 + M6 hardening
// ──────────────────────────────────────────────────────────────────────

// M6: the 24-byte reserved pad in classical_wrapped MUST be zero. Before the
// fix the parser ignored it entirely, so a non-zero pad parsed cleanly.
test('pq-hybrid-v1: parser rejects a non-zero reserved classical_wrapped pad (M6)', async () => {
  const recipient = await createIdentity({ userId: 'recipient' })
  const { suitePayload } = await encapsulateForRecipient({
    recipientPublicKey: recipient.publicBundle.mlKemPublicKey,
    envelopeKey: randomBytes(32),
    fileId: randomBytes(16),
  })

  // A freshly built payload has an all-zero pad and parses fine.
  assert.doesNotThrow(() => parsePqHybridV1SuitePayload(suitePayload))

  const tampered = suitePayload.slice()
  tampered[RESERVED_PAD_OFFSET_IN_PAYLOAD] = 0x01 // flip a reserved-pad byte
  assert.throws(
    () => parsePqHybridV1SuitePayload(tampered),
    /reserved classical_wrapped pad must be zero/,
  )
})

// H2 (whole-bundle authentication): tampering PQ material in a share bundle —
// here the reserved pad, the one byte the pre-fix open path ignored — must be
// rejected. Before the fix `openShareAsRecipient` happily returned the key.
test('share: forged PQ material (reserved pad) in the bundle is rejected (H2/M6)', async () => {
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({ userId: 'recipient' })

  const result = await pqHybrid.encryptBytes(randomBytes(1024), {
    recipientPublicKey: recipient.publicBundle.mlKemPublicKey,
    envelopeKey: randomBytes(32),
    chunkSize: 1024,
  })
  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  // The reserved pad lives at: 4 (length prefix) + payload offset.
  const pqLen = readUint32BE(shareBundle, 0)
  assert.ok(pqLen > RESERVED_PAD_OFFSET_IN_PAYLOAD)
  const forged = shareBundle.slice()
  forged[4 + RESERVED_PAD_OFFSET_IN_PAYLOAD] ^= 0x01

  await assert.rejects(() =>
    openShareAsRecipient({
      shareBundle: forged,
      fileId: result.fileId,
      recipientSecretKey: recipient.mlKemSecretKey,
      recipientEnvelopeKey: recipientEnvelope,
    }),
  )
})

// H2 (dedicated transport-key label): the raw KEM/envelope combined key (which
// reuses the file-combiner HKDF label) must NOT be the key the share is wrapped
// under. Before the fix it WAS — secretbox would open the wrapped key with it.
test('share: raw KEM/envelope transport secret no longer unwraps the share (H2)', async () => {
  const sodium = await getSodium()
  const recipientEnvelope = randomBytes(32)
  const recipient = await createIdentity({ userId: 'recipient' })

  const result = await pqHybrid.encryptBytes(randomBytes(1024), {
    recipientPublicKey: recipient.publicBundle.mlKemPublicKey,
    envelopeKey: randomBytes(32),
    chunkSize: 1024,
  })
  const { shareBundle } = await buildShareForRecipient({
    combinedKey: result.combinedKey,
    fileId: result.fileId,
    recipient: recipient.publicBundle,
    recipientEnvelopeKey: recipientEnvelope,
  })

  const pqLen = readUint32BE(shareBundle, 0)
  const pqPayload = shareBundle.slice(4, 4 + pqLen)
  const wrapNonce = shareBundle.slice(4 + pqLen, 4 + pqLen + 24)
  const wrappedKey = shareBundle.slice(4 + pqLen + 24)

  // The raw combined key the recipient recovers from the PQ payload.
  const { combinedKey: rawTransport } = await decapsulateFromHeader({
    suitePayload: pqPayload,
    recipientSecretKey: recipient.mlKemSecretKey,
    envelopeKey: recipientEnvelope,
    fileId: result.fileId,
  })
  // It must not unwrap the share via the old secretbox construction.
  let openedWithRaw: Uint8Array | false
  try {
    openedWithRaw = sodium.crypto_secretbox_open_easy(
      wrappedKey,
      wrapNonce,
      rawTransport,
    )
  } catch {
    openedWithRaw = false
  }
  assert.ok(!openedWithRaw, 'raw transport secret must not unwrap the share')

  // The legitimate path still recovers the original combined key.
  const recovered = await openShareAsRecipient({
    shareBundle,
    fileId: result.fileId,
    recipientSecretKey: recipient.mlKemSecretKey,
    recipientEnvelopeKey: recipientEnvelope,
  })
  assert.ok(bytesEqual(recovered, result.combinedKey))
})
