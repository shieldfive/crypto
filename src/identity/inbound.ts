/**
 * Zero-knowledge inbound intake.
 *
 * The PQ-hybrid suite (0x03) derives a file's content key from BOTH an ML-KEM
 * encapsulated share AND a classical share that is secret-box-wrapped under a
 * caller-supplied 32-byte `envelopeKey`. To decrypt, a recipient needs the
 * ML-KEM secret key AND that envelope key — the KEM does not deliver the
 * envelope key.
 *
 * For OUTBOUND files the owner is the recipient and already holds the envelope
 * key (it is the file's own content key). An INBOUND, account-less sender has
 * no firm secret, so it cannot produce an envelope key the firm can later
 * recover. Using a public constant would make the classical share public and
 * collapse the scheme to ML-KEM-only.
 *
 * This module closes that gap WITHOUT touching the frozen suite: the firm
 * publishes a static X25519 public key alongside its ML-KEM public key, and the
 * sender derives the envelope key from an ephemeral↔static X25519 ECDH. The
 * classical share is then confidential under X25519 while the PQ share is
 * confidential under ML-KEM, so an attacker must break BOTH primitives — a
 * genuine hybrid, with the bulk file still produced by the existing
 * `encryptStreamPqHybridV1` / `encryptBlob` path.
 *
 * Trust note: the recipient's published keys are only as trustworthy as the
 * channel that serves them. Browser-delivered code "trusts the served code each
 * load"; pair this with an out-of-band key fingerprint for the strong claim.
 * This module does the cryptography; it does not establish key authenticity.
 */

import { x25519 } from '@noble/curves/ed25519.js'

import { concatBytes } from '../internal/encoding.js'
import { hkdfSha256 } from '../internal/hkdf.js'
import { randomBytes } from '../internal/runtime.js'
import { HEADER_SIZES, HKDF_INFO } from '../internal/types.js'

/** X25519 public key length (Curve25519 u-coordinate). */
export const X25519_PUBLIC_KEY_LENGTH = 32
/** X25519 secret scalar length. */
export const X25519_SECRET_KEY_LENGTH = 32

const INBOUND_ENVELOPE_KEY_BYTES = 32

export interface InboundStaticKeypair {
  /** Static X25519 public key (32 bytes) — publish next to the ML-KEM public key. */
  x25519PublicKey: Uint8Array
  /** Static X25519 secret scalar (32 bytes) — treat as highly sensitive. */
  x25519SecretKey: Uint8Array
}

/**
 * Deterministically derive the firm's static X25519 keypair from its master
 * secret, mirroring how the ML-KEM keypair is derived. The same master secret
 * always yields the same keypair across devices, so losing a device does not
 * orphan received files (as long as the master secret is recoverable).
 */
export async function deriveInboundStaticKeypair(
  masterSecret: Uint8Array,
): Promise<InboundStaticKeypair> {
  if (masterSecret.length < 16) {
    throw new RangeError(
      'deriveInboundStaticKeypair: masterSecret must be at least 16 bytes',
    )
  }
  const seed = await hkdfSha256({
    ikm: masterSecret,
    info: HKDF_INFO.INBOUND_X25519_STATIC_SEED,
    length: X25519_SECRET_KEY_LENGTH,
  })
  const x25519PublicKey = x25519.getPublicKey(seed)
  return { x25519PublicKey, x25519SecretKey: seed }
}

/**
 * Derive the per-file envelope key from a shared secret. The full ECDH
 * transcript (shared secret, ephemeral public key, recipient static public key)
 * is bound into the HKDF input and the file_id into the salt, so a captured
 * ephemeral key cannot be replayed against a different recipient or file.
 */
async function deriveEnvelopeKey(
  sharedSecret: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  recipientStaticPublicKey: Uint8Array,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: concatBytes([
      sharedSecret,
      ephemeralPublicKey,
      recipientStaticPublicKey,
    ]),
    salt: fileId,
    info: HKDF_INFO.INBOUND_ENVELOPE,
    length: INBOUND_ENVELOPE_KEY_BYTES,
  })
}

/**
 * Sender side (account-less, in the browser). Given the firm's published static
 * X25519 public key and the file_id used for the upload, produce the classical
 * `envelopeKey` to pass to `encryptStreamPqHybridV1` / `encryptBlob`, plus the
 * ephemeral public key to store alongside the ciphertext so the firm can
 * recover the same envelope key. No firm secret is required.
 */
export async function sealInboundEnvelopeKey(options: {
  recipientX25519PublicKey: Uint8Array
  fileId: Uint8Array
}): Promise<{ envelopeKey: Uint8Array; ephemeralPublicKey: Uint8Array }> {
  const { recipientX25519PublicKey, fileId } = options
  if (recipientX25519PublicKey.length !== X25519_PUBLIC_KEY_LENGTH) {
    throw new RangeError(
      `sealInboundEnvelopeKey: recipientX25519PublicKey must be ${X25519_PUBLIC_KEY_LENGTH} bytes`,
    )
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError(
      `sealInboundEnvelopeKey: fileId must be ${HEADER_SIZES.FILE_ID} bytes`,
    )
  }
  const ephemeralSecret = randomBytes(X25519_SECRET_KEY_LENGTH)
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecret)
  // Throws on a low-order / all-zero shared secret (contributory behaviour).
  const sharedSecret = x25519.getSharedSecret(
    ephemeralSecret,
    recipientX25519PublicKey,
  )
  const envelopeKey = await deriveEnvelopeKey(
    sharedSecret,
    ephemeralPublicKey,
    recipientX25519PublicKey,
    fileId,
  )
  return { envelopeKey, ephemeralPublicKey }
}

/**
 * Recipient side (the firm). Recover the same `envelopeKey` from its static
 * X25519 secret key and the sender's ephemeral public key, then feed it (with
 * the ML-KEM secret key) to the standard KEM-mode decrypt path.
 */
export async function openInboundEnvelopeKey(options: {
  x25519SecretKey: Uint8Array
  ephemeralPublicKey: Uint8Array
  fileId: Uint8Array
}): Promise<{ envelopeKey: Uint8Array }> {
  const { x25519SecretKey, ephemeralPublicKey, fileId } = options
  if (x25519SecretKey.length !== X25519_SECRET_KEY_LENGTH) {
    throw new RangeError(
      `openInboundEnvelopeKey: x25519SecretKey must be ${X25519_SECRET_KEY_LENGTH} bytes`,
    )
  }
  if (ephemeralPublicKey.length !== X25519_PUBLIC_KEY_LENGTH) {
    throw new RangeError(
      `openInboundEnvelopeKey: ephemeralPublicKey must be ${X25519_PUBLIC_KEY_LENGTH} bytes`,
    )
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError(
      `openInboundEnvelopeKey: fileId must be ${HEADER_SIZES.FILE_ID} bytes`,
    )
  }
  // Recompute the static public key from the secret so the transcript binding
  // matches the sender's byte-for-byte.
  const recipientStaticPublicKey = x25519.getPublicKey(x25519SecretKey)
  const sharedSecret = x25519.getSharedSecret(x25519SecretKey, ephemeralPublicKey)
  const envelopeKey = await deriveEnvelopeKey(
    sharedSecret,
    ephemeralPublicKey,
    recipientStaticPublicKey,
    fileId,
  )
  return { envelopeKey }
}
