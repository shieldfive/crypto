/**
 * User identity & public-key directory helpers.
 *
 * In a multi-user system, the PQ-hybrid suite needs the recipient's public
 * key to encrypt to. This module provides:
 *
 *   - A canonical wire format for publishing a user's public-key bundle
 *     (ML-KEM-1024 public key + a self-signed-by-application identity tag).
 *   - Helpers for creating, parsing, and verifying public-key bundles.
 *   - Helpers for re-encrypting a file's content key to additional
 *     recipients (sharing) without re-uploading the file.
 *
 * Cryptographic identity beyond the application's own auth layer is
 * deliberately NOT in scope. The bundle format does not sign the public
 * key with any user-controlled key — the trust anchor is the application's
 * authenticated channel for publishing keys (TLS + auth token). If callers
 * want stronger identity (e.g. SAS verification, gossiped signatures),
 * they wrap this module rather than modify it.
 */

import {
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SECRET_KEY_BYTES,
  deriveMlKemKeypair,
  generateMlKemKeypair,
  encapsulateForRecipient,
  decapsulateFromHeader,
  parsePqHybridV1SuitePayload,
} from '../suites/pq-hybrid-v1/index.js'
export {
  SIGNATURE_ALGO_ED25519,
  SIGNATURE_ALGO_ML_DSA_65,
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_SECRET_KEY_LENGTH,
  ED25519_SIGNATURE_LENGTH,
  SignatureError,
  buildSignatureBlock,
  deriveEd25519PublicKey,
  parseSignatureBlock,
  SenderSigTranscript,
  signSenderTranscript,
  verifySenderTranscript,
} from './sign.js'
export type { SignatureBlock } from './sign.js'
import {
  bytesToBase64,
  base64ToBytes,
  concatBytes,
  uint16BE,
  uint32BE,
  readUint16BE,
  readUint32BE,
} from '../internal/encoding.js'
import { randomBytes } from '../internal/runtime.js'
import { getSodium } from '../internal/sodium.js'
import { hkdfSha256 } from '../internal/hkdf.js'
import { HKDF_INFO } from '../internal/types.js'

const IDENTITY_BUNDLE_MAGIC = new Uint8Array([0x53, 0x46, 0x35, 0x49, 0x01]) // "SF5I" + version

// Share-bundle magic: "SF5S" + version byte. Version 0x02 marks the hardened
// share construction (audit H2/M6): a domain-separated transport key and an
// AEAD wrap whose AAD authenticates the whole bundle. Earlier alpha builds
// emitted an unversioned bundle (an AAD-less secretbox under the raw transport
// secret); those are NOT readable here and are rejected by the magic check.
// No real shares exist pre-launch, so this is a deliberate clean break.
const SHARE_BUNDLE_MAGIC = new Uint8Array([0x53, 0x46, 0x35, 0x53, 0x02]) // "SF5S" + version 2

export interface PublicIdentityBundle {
  /** ML-KEM-1024 public key (1568 bytes) */
  mlKemPublicKey: Uint8Array
  /** Application-assigned user ID (UTF-8 string, ≤255 bytes) */
  userId: string
  /** Optional metadata blob (≤4 KiB), e.g. a profile JSON */
  metadata?: Uint8Array
  /** Issuance timestamp (UNIX seconds, uint32) */
  issuedAt: number
}

/**
 * Wire format for an identity bundle:
 *
 *   magic           5 bytes   "SF5I" + version
 *   issued_at       4 bytes   uint32 BE (UNIX seconds)
 *   user_id_len     1 byte
 *   user_id         variable  UTF-8
 *   ml_kem_pk       1568 bytes
 *   metadata_len    2 bytes   uint16 BE
 *   metadata        variable  opaque
 *
 * Unsigned. Trust comes from the channel that publishes it.
 */

export function encodeIdentityBundle(bundle: PublicIdentityBundle): Uint8Array {
  if (bundle.mlKemPublicKey.length !== ML_KEM_1024_PUBLIC_KEY_BYTES) {
    throw new RangeError(
      `encodeIdentityBundle: mlKemPublicKey must be ${ML_KEM_1024_PUBLIC_KEY_BYTES} bytes`,
    )
  }
  const userIdBytes = new TextEncoder().encode(bundle.userId)
  if (userIdBytes.length === 0 || userIdBytes.length > 255) {
    throw new RangeError(
      'encodeIdentityBundle: userId must be 1..255 UTF-8 bytes',
    )
  }
  if (
    !Number.isSafeInteger(bundle.issuedAt) ||
    bundle.issuedAt < 0 ||
    bundle.issuedAt > 0xffff_ffff
  ) {
    throw new RangeError('encodeIdentityBundle: issuedAt must fit in uint32')
  }
  const metadata = bundle.metadata ?? new Uint8Array(0)
  if (metadata.length > 4096) {
    throw new RangeError(
      'encodeIdentityBundle: metadata must be at most 4096 bytes',
    )
  }
  return concatBytes([
    IDENTITY_BUNDLE_MAGIC,
    uint32BE(bundle.issuedAt),
    new Uint8Array([userIdBytes.length]),
    userIdBytes,
    bundle.mlKemPublicKey,
    uint16BE(metadata.length),
    metadata,
  ])
}

export function decodeIdentityBundle(bytes: Uint8Array): PublicIdentityBundle {
  if (bytes.length < IDENTITY_BUNDLE_MAGIC.length + 4 + 1) {
    throw new RangeError('decodeIdentityBundle: input too short')
  }
  for (let i = 0; i < IDENTITY_BUNDLE_MAGIC.length; i += 1) {
    if (bytes[i] !== IDENTITY_BUNDLE_MAGIC[i]) {
      throw new Error('decodeIdentityBundle: bad magic / unknown bundle version')
    }
  }

  let offset = IDENTITY_BUNDLE_MAGIC.length
  const issuedAt = readUint32BE(bytes, offset)
  offset += 4

  const userIdLen = bytes[offset]!
  offset += 1
  if (userIdLen === 0) {
    throw new Error('decodeIdentityBundle: empty user_id')
  }
  if (offset + userIdLen + ML_KEM_1024_PUBLIC_KEY_BYTES + 2 > bytes.length) {
    throw new Error('decodeIdentityBundle: truncated')
  }

  const userId = new TextDecoder('utf-8', { fatal: true }).decode(
    bytes.slice(offset, offset + userIdLen),
  )
  offset += userIdLen

  const mlKemPublicKey = bytes.slice(
    offset,
    offset + ML_KEM_1024_PUBLIC_KEY_BYTES,
  )
  offset += ML_KEM_1024_PUBLIC_KEY_BYTES

  const metadataLen = readUint16BE(bytes, offset)
  offset += 2
  if (offset + metadataLen !== bytes.length) {
    throw new Error('decodeIdentityBundle: trailing bytes or wrong metadata_len')
  }
  const metadata = bytes.slice(offset, offset + metadataLen)

  const result: PublicIdentityBundle = {
    mlKemPublicKey,
    userId,
    issuedAt,
  }
  if (metadata.length > 0) result.metadata = metadata
  return result
}

/**
 * Serialize a bundle as a base64 string suitable for storing in a database
 * column or transmitting over a JSON API.
 */
export function bundleToBase64(bundle: PublicIdentityBundle): string {
  return bytesToBase64(encodeIdentityBundle(bundle))
}

export function bundleFromBase64(b64: string): PublicIdentityBundle {
  return decodeIdentityBundle(base64ToBytes(b64))
}

// ──────────────────────────────────────────────────────────────────────
// Identity creation
// ──────────────────────────────────────────────────────────────────────

export interface CreateIdentityOptions {
  userId: string
  metadata?: Uint8Array
  /**
   * If provided, the ML-KEM keypair is derived deterministically from
   * this master secret. Otherwise a fresh keypair is generated. Most
   * applications should pass the user's master secret here so that
   * loss of an ML-KEM secret key does not lock the user out.
   */
  masterSecret?: Uint8Array
  /** Defaults to current time. */
  issuedAt?: number
}

export interface IdentityKeypair {
  publicBundle: PublicIdentityBundle
  /** Encoded form of the public bundle for direct publishing. */
  publicBundleBytes: Uint8Array
  /** ML-KEM-1024 secret key. Treat as highly sensitive. */
  mlKemSecretKey: Uint8Array
}

export async function createIdentity(
  options: CreateIdentityOptions,
): Promise<IdentityKeypair> {
  const keypair = options.masterSecret
    ? await deriveMlKemKeypair(options.masterSecret)
    : generateMlKemKeypair()

  const bundle: PublicIdentityBundle = {
    mlKemPublicKey: keypair.publicKey,
    userId: options.userId,
    issuedAt: options.issuedAt ?? Math.floor(Date.now() / 1000),
  }
  if (options.metadata) bundle.metadata = options.metadata

  if (keypair.secretKey.length !== ML_KEM_1024_SECRET_KEY_BYTES) {
    throw new Error(
      `createIdentity: unexpected secret key length ${keypair.secretKey.length}`,
    )
  }

  return {
    publicBundle: bundle,
    publicBundleBytes: encodeIdentityBundle(bundle),
    mlKemSecretKey: keypair.secretKey,
  }
}

// ──────────────────────────────────────────────────────────────────────
// Sharing: re-encrypt a file's content key to additional recipients
// ──────────────────────────────────────────────────────────────────────

/**
 * The PQ-hybrid suite encrypts each file's combined key for exactly one
 * recipient (whoever owns the ML-KEM public key the encryptor used).
 * Sharing a file with N additional recipients means: recover the
 * original combined key (only the owner can do this), then produce N new
 * suite_payloads — one per recipient — that decrypt to the SAME combined
 * key. The chunks themselves are not re-encrypted.
 *
 * Each per-recipient suite_payload is stored alongside the file's chunks
 * in the application's database (one row per recipient). The on-disk
 * blob remains unchanged.
 */

export interface ShareFileInput {
  /** The file's combined key, recovered by the owner. */
  combinedKey: Uint8Array
  /** The file's 16-byte file_id. */
  fileId: Uint8Array
  /** The recipient's identity bundle (provides their ML-KEM public key). */
  recipient: PublicIdentityBundle
  /** Classical envelope key the recipient holds. */
  recipientEnvelopeKey: Uint8Array
}

/**
 * Build a new suite_payload that decrypts to `combinedKey` for the given
 * recipient. Stored alongside the file as a per-recipient share record.
 *
 * NOTE: the standard `encapsulateForRecipient` produces a NEW combined
 * key. To make sharing work, we use a different construction: we wrap
 * the existing combined key under (recipient PQ KEM ⊕ recipient
 * envelope) and emit only the wrapped form.
 *
 * Two properties this construction must hold (audit H2/M6):
 *   1. The wrapping key is NOT the raw KEM/envelope combined key (which
 *      reuses the file-combiner HKDF label). We run it through one more
 *      HKDF under the dedicated `SHARE_TRANSPORT` label so a share key is
 *      never equal to a file's combined key.
 *   2. The wrap authenticates the WHOLE bundle, not just the 32-byte
 *      combined key: the XChaCha20-Poly1305 AAD covers the version marker,
 *      the length prefix, the entire pqPayload (including its reserved pad)
 *      and the nonce, so PQ material cannot be substituted or stripped
 *      without breaking the tag.
 *
 * The bundle is prefixed with `SHARE_BUNDLE_MAGIC` ("SF5S" + version) so the
 * hardened format is distinguishable from the earlier unversioned one.
 */
export async function buildShareForRecipient(
  input: ShareFileInput,
): Promise<{ shareBundle: Uint8Array }> {
  const sodium = await getSodium()

  // Generate a fresh transport secret for this share.
  // ML-KEM encapsulation gives us the PQ-half of the transport secret.
  const { suitePayload: pqPayload, combinedKey: transportSecret } =
    await encapsulateForRecipient({
      recipientPublicKey: input.recipient.mlKemPublicKey,
      envelopeKey: input.recipientEnvelopeKey,
      fileId: input.fileId,
    })

  if (transportSecret.length !== 32) {
    throw new Error('buildShareForRecipient: transport key length wrong')
  }
  // (1) Domain-separate the share transport key from the file-combiner output.
  const shareTransportKey = await hkdfSha256({
    ikm: transportSecret,
    salt: input.fileId,
    info: HKDF_INFO.SHARE_TRANSPORT,
    length: 32,
  })

  // (2) Wrap the original combined key with an AEAD whose AAD authenticates
  // the whole bundle prefix (magic || length || pqPayload || nonce). Binding
  // the magic means the version marker cannot be stripped or downgraded
  // without breaking the tag.
  const wrapNonce = randomBytes(24)
  const aad = concatBytes([
    SHARE_BUNDLE_MAGIC,
    uint32BE(pqPayload.length),
    pqPayload,
    wrapNonce,
  ])
  const wrappedCombinedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    input.combinedKey,
    aad,
    null,
    wrapNonce,
    shareTransportKey,
  )
  if (wrappedCombinedKey.length !== 32 + 16) {
    throw new Error('buildShareForRecipient: AEAD produced unexpected length')
  }

  // Share record format:
  //   [5-byte magic][4 bytes BE length of pqPayload][pqPayload][24-byte wrap nonce][48-byte wrapped combined key]
  return {
    shareBundle: concatBytes([
      SHARE_BUNDLE_MAGIC,
      uint32BE(pqPayload.length),
      pqPayload,
      wrapNonce,
      wrappedCombinedKey,
    ]),
  }
}

/**
 * Recipient side: open a share bundle to recover the file's combined key.
 * The recipient then uses that combined key with the standard PQ-hybrid
 * decrypt path (via the original on-disk file).
 */
export async function openShareAsRecipient(input: {
  shareBundle: Uint8Array
  fileId: Uint8Array
  recipientSecretKey: Uint8Array
  recipientEnvelopeKey: Uint8Array
}): Promise<Uint8Array> {
  const sodium = await getSodium()
  if (input.shareBundle.length < SHARE_BUNDLE_MAGIC.length + 4) {
    throw new Error('openShareAsRecipient: share too short')
  }
  // Reject anything that isn't a current ("SF5S" + version) share bundle.
  // Earlier-alpha unversioned bundles fail here rather than producing an
  // opaque authentication error later.
  for (let i = 0; i < SHARE_BUNDLE_MAGIC.length; i += 1) {
    if (input.shareBundle[i] !== SHARE_BUNDLE_MAGIC[i]) {
      throw new Error(
        'openShareAsRecipient: bad magic / unsupported share bundle version',
      )
    }
  }
  let offset = SHARE_BUNDLE_MAGIC.length
  const pqLen = readUint32BE(input.shareBundle, offset)
  offset += 4
  if (offset + pqLen + 24 + 48 !== input.shareBundle.length) {
    throw new Error('openShareAsRecipient: malformed share')
  }
  const pqPayload = input.shareBundle.slice(offset, offset + pqLen)
  offset += pqLen
  const wrapNonce = input.shareBundle.slice(offset, offset + 24)
  offset += 24
  const wrappedCombinedKey = input.shareBundle.slice(offset, offset + 48)

  // Structurally validate the suite payload. This rejects a non-zero reserved
  // pad in classical_wrapped (M6) before any decapsulation work.
  parsePqHybridV1SuitePayload(pqPayload)

  const { combinedKey: transportSecret } = await decapsulateFromHeader({
    suitePayload: pqPayload,
    recipientSecretKey: input.recipientSecretKey,
    envelopeKey: input.recipientEnvelopeKey,
    fileId: input.fileId,
  })
  const shareTransportKey = await hkdfSha256({
    ikm: transportSecret,
    salt: input.fileId,
    info: HKDF_INFO.SHARE_TRANSPORT,
    length: 32,
  })

  // The AAD must reproduce exactly what the builder authenticated: it binds
  // the version marker, the length prefix, the whole pqPayload (incl. reserved
  // pad) and the nonce, so any substitution/stripping of PQ material breaks
  // the tag.
  const aad = concatBytes([
    SHARE_BUNDLE_MAGIC,
    uint32BE(pqPayload.length),
    pqPayload,
    wrapNonce,
  ])
  let unwrapped: Uint8Array
  try {
    unwrapped = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      wrappedCombinedKey,
      aad,
      wrapNonce,
      shareTransportKey,
    )
  } catch {
    throw new Error(
      'openShareAsRecipient: share authentication failed — wrong recipient or tampered share',
    )
  }
  if (unwrapped.length !== 32) {
    throw new Error('openShareAsRecipient: bad combined key length')
  }
  return new Uint8Array(unwrapped)
}
