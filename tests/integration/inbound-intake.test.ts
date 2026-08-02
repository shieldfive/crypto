/**
 * Zero-knowledge inbound intake round trip (the "Request documents" feature).
 *
 * An account-less sender encrypts a file to a firm's PUBLISHED keys (ML-KEM +
 * static X25519) with no firm secret; only the firm can decrypt. Validates:
 *   - the firm's static X25519 keypair is deterministic from its master secret
 *   - sealer and opener derive the identical envelope key
 *   - a full sender→firm encrypt/decrypt round trip over suite 0x03
 *   - the hybrid property: decryption needs BOTH the ML-KEM secret AND the
 *     X25519 secret — breaking either one alone fails closed
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import { decryptToBytes, encryptBytes } from '../../src/suites/pq-hybrid-v1/api.js'
import { deriveMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'
import {
  deriveInboundStaticKeypair,
  openInboundEnvelopeKey,
  sealInboundEnvelopeKey,
} from '../../src/identity/inbound.js'
import { randomBytes } from '../../src/internal/runtime.js'

test('firm static X25519 keypair is deterministic from the master secret', async () => {
  const masterSecret = randomBytes(32)
  const a = await deriveInboundStaticKeypair(masterSecret)
  const b = await deriveInboundStaticKeypair(masterSecret)
  assert.equal(a.x25519PublicKey.length, 32)
  assert.equal(a.x25519SecretKey.length, 32)
  assert.deepEqual(a.x25519PublicKey, b.x25519PublicKey)
  assert.deepEqual(a.x25519SecretKey, b.x25519SecretKey)

  const other = await deriveInboundStaticKeypair(randomBytes(32))
  assert.notDeepEqual(a.x25519PublicKey, other.x25519PublicKey)
})

test('sealer and opener derive the identical envelope key', async () => {
  const firm = await deriveInboundStaticKeypair(randomBytes(32))
  const fileId = randomBytes(16)

  const { envelopeKey, ephemeralPublicKey } = await sealInboundEnvelopeKey({
    recipientX25519PublicKey: firm.x25519PublicKey,
    fileId,
  })
  const opened = await openInboundEnvelopeKey({
    x25519SecretKey: firm.x25519SecretKey,
    ephemeralPublicKey,
    fileId,
  })
  assert.equal(envelopeKey.length, 32)
  assert.deepEqual(opened.envelopeKey, envelopeKey)
})

test('account-less sender → firm decrypt round trip (suite 0x03)', async () => {
  const masterSecret = randomBytes(32)
  const mlKem = await deriveMlKemKeypair(masterSecret)
  const firm = await deriveInboundStaticKeypair(masterSecret)

  const fileId = randomBytes(16)
  const plaintext = new TextEncoder().encode(
    'Modelo 303 Q4 — confidential client document',
  )

  // Sender: only PUBLIC keys, no firm secret.
  const { envelopeKey, ephemeralPublicKey } = await sealInboundEnvelopeKey({
    recipientX25519PublicKey: firm.x25519PublicKey,
    fileId,
  })
  const encrypted = await encryptBytes(plaintext, {
    recipientPublicKey: mlKem.publicKey,
    envelopeKey,
    fileId,
  })

  // Firm: recover the envelope key from its X25519 secret + the ephemeral pubkey,
  // then decrypt with the existing KEM-mode path.
  const opened = await openInboundEnvelopeKey({
    x25519SecretKey: firm.x25519SecretKey,
    ephemeralPublicKey,
    fileId,
  })
  const decrypted = await decryptToBytes({
    blob: encrypted.blob,
    recipientSecretKey: mlKem.secretKey,
    envelopeKey: opened.envelopeKey,
  })

  assert.deepEqual(decrypted, plaintext)
})

test('hybrid: breaking only X25519 (wrong static secret) fails closed', async () => {
  const masterSecret = randomBytes(32)
  const mlKem = await deriveMlKemKeypair(masterSecret)
  const firm = await deriveInboundStaticKeypair(masterSecret)
  const fileId = randomBytes(16)
  const plaintext = randomBytes(4096)

  const { envelopeKey, ephemeralPublicKey } = await sealInboundEnvelopeKey({
    recipientX25519PublicKey: firm.x25519PublicKey,
    fileId,
  })
  const encrypted = await encryptBytes(plaintext, {
    recipientPublicKey: mlKem.publicKey,
    envelopeKey,
    fileId,
  })

  // Attacker holds the ML-KEM secret but NOT the firm's X25519 secret.
  const attacker = await deriveInboundStaticKeypair(randomBytes(32))
  const openedWrong = await openInboundEnvelopeKey({
    x25519SecretKey: attacker.x25519SecretKey,
    ephemeralPublicKey,
    fileId,
  })
  assert.notDeepEqual(openedWrong.envelopeKey, envelopeKey)
  await assert.rejects(() =>
    decryptToBytes({
      blob: encrypted.blob,
      recipientSecretKey: mlKem.secretKey,
      envelopeKey: openedWrong.envelopeKey,
    }),
  )
})

test('hybrid: breaking only ML-KEM (wrong KEM secret) fails closed', async () => {
  const masterSecret = randomBytes(32)
  const mlKem = await deriveMlKemKeypair(masterSecret)
  const firm = await deriveInboundStaticKeypair(masterSecret)
  const fileId = randomBytes(16)
  const plaintext = randomBytes(4096)

  const { envelopeKey, ephemeralPublicKey } = await sealInboundEnvelopeKey({
    recipientX25519PublicKey: firm.x25519PublicKey,
    fileId,
  })
  const encrypted = await encryptBytes(plaintext, {
    recipientPublicKey: mlKem.publicKey,
    envelopeKey,
    fileId,
  })

  // Correct envelope key (X25519 half) but the wrong ML-KEM secret key.
  const opened = await openInboundEnvelopeKey({
    x25519SecretKey: firm.x25519SecretKey,
    ephemeralPublicKey,
    fileId,
  })
  const wrongMlKem = await deriveMlKemKeypair(randomBytes(32))
  await assert.rejects(() =>
    decryptToBytes({
      blob: encrypted.blob,
      recipientSecretKey: wrongMlKem.secretKey,
      envelopeKey: opened.envelopeKey,
    }),
  )
})

test('a substituted ephemeral public key cannot open the file', async () => {
  const masterSecret = randomBytes(32)
  const mlKem = await deriveMlKemKeypair(masterSecret)
  const firm = await deriveInboundStaticKeypair(masterSecret)
  const fileId = randomBytes(16)
  const plaintext = randomBytes(2048)

  const sealed = await sealInboundEnvelopeKey({
    recipientX25519PublicKey: firm.x25519PublicKey,
    fileId,
  })
  const encrypted = await encryptBytes(plaintext, {
    recipientPublicKey: mlKem.publicKey,
    envelopeKey: sealed.envelopeKey,
    fileId,
  })

  // A different upload's ephemeral key must not open this file.
  const other = await sealInboundEnvelopeKey({
    recipientX25519PublicKey: firm.x25519PublicKey,
    fileId,
  })
  const openedWrong = await openInboundEnvelopeKey({
    x25519SecretKey: firm.x25519SecretKey,
    ephemeralPublicKey: other.ephemeralPublicKey,
    fileId,
  })
  await assert.rejects(() =>
    decryptToBytes({
      blob: encrypted.blob,
      recipientSecretKey: mlKem.secretKey,
      envelopeKey: openedWrong.envelopeKey,
    }),
  )
})
