/**
 * Cipher suite 0x03: PQ-hybrid XChaCha20-Poly1305 + ML-KEM-1024 v1.
 *
 * The default suite for new files. Combines a classical 32-byte secret with
 * an ML-KEM-1024 encapsulated 32-byte shared secret. The combined key is
 * derived via HKDF-SHA-256 with the file_id as salt.
 *
 * Security: an adversary must break BOTH ML-KEM-1024 AND the classical
 * KDF/wrap to recover plaintext. ML-KEM-1024 is FIPS 203, security level
 * 5 (≈AES-256 against quantum search).
 *
 * Implementation:
 *   - Classical share encrypted under envelope key with XSalsa20-Poly1305
 *     secretbox (libsodium).
 *   - PQ encapsulation via @noble/post-quantum's ML-KEM-1024.
 *   - Chunk AEAD identical to xchacha-v1 once the combined key is derived.
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'

import { buildChunkAad } from '../../format/header.js'
import {
  HKDF_INFO,
  HEADER_SIZES,
  type ParsedHeader,
} from '../../internal/types.js'
import { concatBytes, uint64BE } from '../../internal/encoding.js'
import { hkdfSha256 } from '../../internal/hkdf.js'
import { randomBytes } from '../../internal/runtime.js'
import { getSodium } from '../../internal/sodium.js'

export const PQ_HYBRID_V1_KEY_BYTES = 32
export const PQ_HYBRID_V1_NONCE_BYTES = 24
export const PQ_HYBRID_V1_TAG_BYTES = 16

/** ML-KEM-1024 ciphertext length per FIPS 203. */
export const ML_KEM_1024_CIPHERTEXT_BYTES = 1568
/** ML-KEM-1024 public key length per FIPS 203. */
export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1568
/** ML-KEM-1024 secret key length per FIPS 203. */
export const ML_KEM_1024_SECRET_KEY_BYTES = 3168

/**
 * Suite payload layout:
 *   mlkem_ciphertext    (1568 bytes)
 *   classical_wrapped   (72 bytes — 48 bytes secretbox + 24 bytes reserved zero pad)
 *   classical_nonce     (24 bytes)
 * Total: 1664 bytes
 *
 * The 24 reserved pad bytes (offsets 48..72 of classical_wrapped) MUST be
 * zero. The parser rejects a non-zero pad (audit M6) so the field cannot be
 * used as a malleable, unauthenticated side channel.
 */
export const PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH =
  ML_KEM_1024_CIPHERTEXT_BYTES + 72 + 24

/** Bytes of real secretbox at the start of the 72-byte classical_wrapped field. */
const CLASSICAL_WRAPPED_SECRETBOX_BYTES = 48

export interface PqHybridV1SuitePayload {
  mlkemCiphertext: Uint8Array // 1568 bytes
  classicalWrapped: Uint8Array // 72 bytes
  classicalNonce: Uint8Array // 24 bytes
}

export function buildPqHybridV1SuitePayload(
  payload: PqHybridV1SuitePayload,
): Uint8Array {
  if (payload.mlkemCiphertext.length !== ML_KEM_1024_CIPHERTEXT_BYTES) {
    throw new RangeError('pq-hybrid-v1: mlkemCiphertext must be 1568 bytes')
  }
  if (payload.classicalWrapped.length !== 72) {
    throw new RangeError('pq-hybrid-v1: classicalWrapped must be 72 bytes')
  }
  if (payload.classicalNonce.length !== 24) {
    throw new RangeError('pq-hybrid-v1: classicalNonce must be 24 bytes')
  }
  return concatBytes([
    payload.mlkemCiphertext,
    payload.classicalWrapped,
    payload.classicalNonce,
  ])
}

export function parsePqHybridV1SuitePayload(
  bytes: Uint8Array,
): PqHybridV1SuitePayload {
  if (bytes.length !== PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError(
      `pq-hybrid-v1: suite payload must be ${PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH} bytes`,
    )
  }
  const classicalWrapped = bytes.slice(
    ML_KEM_1024_CIPHERTEXT_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES + 72,
  )
  // M6: the 24-byte reserved pad after the 48-byte secretbox MUST be all
  // zero. Reject otherwise so the field cannot carry unauthenticated bytes.
  for (
    let i = CLASSICAL_WRAPPED_SECRETBOX_BYTES;
    i < classicalWrapped.length;
    i += 1
  ) {
    if (classicalWrapped[i] !== 0) {
      throw new RangeError(
        'pq-hybrid-v1: reserved classical_wrapped pad must be zero',
      )
    }
  }
  return {
    mlkemCiphertext: bytes.slice(0, ML_KEM_1024_CIPHERTEXT_BYTES),
    classicalWrapped,
    classicalNonce: bytes.slice(
      ML_KEM_1024_CIPHERTEXT_BYTES + 72,
      PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH,
    ),
  }
}

/**
 * Generate an ML-KEM-1024 keypair. In production the keypair is derived
 * deterministically from the user's master secret via HKDF; this function
 * is exposed for testing and advanced callers.
 */
export function generateMlKemKeypair(): {
  publicKey: Uint8Array
  secretKey: Uint8Array
} {
  const seed = randomBytes(64)
  return ml_kem1024.keygen(seed)
}

/**
 * Derive an ML-KEM-1024 keypair deterministically from a master secret.
 * The seed input is 64 bytes; we derive it via HKDF so the same master
 * secret always yields the same keypair across sessions and devices.
 */
export async function deriveMlKemKeypair(
  masterSecret: Uint8Array,
): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  const seed = await hkdfSha256({
    ikm: masterSecret,
    info: HKDF_INFO.ML_KEM_1024_SEED,
    length: 64,
  })
  return ml_kem1024.keygen(seed)
}

/**
 * Compute the combined content key from classical and PQ shares.
 *
 * K = HKDF-SHA-256(
 *   ikm  = classical_share || pq_share,
 *   salt = file_id,
 *   info = "shieldfive/v1/pq-hybrid/combine",
 *   L    = 32
 * )
 */
async function combineKeys(
  classicalShare: Uint8Array,
  pqShare: Uint8Array,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  if (classicalShare.length !== 32 || pqShare.length !== 32) {
    throw new RangeError('combineKeys: both shares must be 32 bytes')
  }
  return hkdfSha256({
    ikm: concatBytes([classicalShare, pqShare]),
    salt: fileId,
    info: HKDF_INFO.PQ_HYBRID_COMBINE,
    length: 32,
  })
}

export interface PqHybridV1ChunkContext {
  combinedKey: Uint8Array
  noncePrefix: Uint8Array
  totalChunks: number
}

async function deriveChunkContext(
  combinedKey: Uint8Array,
  fileId: Uint8Array,
  totalChunks: number,
): Promise<PqHybridV1ChunkContext> {
  // Reuse the xchacha derivation domain — semantically the same chunk-key role.
  const chunkKey = await hkdfSha256({
    ikm: combinedKey,
    salt: fileId,
    info: HKDF_INFO.XCHACHA_CHUNK_KEY,
    length: 32,
  })
  const noncePrefix = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.XCHACHA_NONCE_PREFIX,
    length: 16,
  })
  return { combinedKey: chunkKey, noncePrefix, totalChunks }
}

function buildNonce(noncePrefix: Uint8Array, chunkIndex: number): Uint8Array {
  const nonce = new Uint8Array(PQ_HYBRID_V1_NONCE_BYTES)
  nonce.set(noncePrefix, 0)
  nonce.set(uint64BE(chunkIndex), 16)
  return nonce
}

export async function encryptChunk(
  ctx: PqHybridV1ChunkContext,
  chunkIndex: number,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const isFinal = chunkIndex === ctx.totalChunks - 1
  const aad = buildChunkAad(chunkIndex, ctx.totalChunks, isFinal)
  const nonce = buildNonce(ctx.noncePrefix, chunkIndex)
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    ctx.combinedKey,
  )
}

export async function decryptChunk(
  ctx: PqHybridV1ChunkContext,
  chunkIndex: number,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const isFinal = chunkIndex === ctx.totalChunks - 1
  const aad = buildChunkAad(chunkIndex, ctx.totalChunks, isFinal)
  const nonce = buildNonce(ctx.noncePrefix, chunkIndex)
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    ctx.combinedKey,
  )
}

/**
 * Sender side: produce the suite payload and the combined key.
 *
 * Inputs:
 *   - recipient's ML-KEM public key
 *   - envelopeKey: classical key under which the classical share is wrapped
 *   - fileId: per-file ID used as HKDF salt
 *
 * Outputs:
 *   - the suite payload bytes
 *   - the combined content key (used for header MAC and chunk AEAD)
 */
export async function encapsulateForRecipient(options: {
  recipientPublicKey: Uint8Array
  envelopeKey: Uint8Array
  fileId: Uint8Array
}): Promise<{ suitePayload: Uint8Array; combinedKey: Uint8Array }> {
  const sodium = await getSodium()
  const { recipientPublicKey, envelopeKey, fileId } = options

  if (recipientPublicKey.length !== ML_KEM_1024_PUBLIC_KEY_BYTES) {
    throw new RangeError('encapsulate: public key must be 1568 bytes')
  }
  if (envelopeKey.length !== 32) {
    throw new RangeError('encapsulate: envelopeKey must be 32 bytes')
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('encapsulate: fileId must be 16 bytes')
  }

  // 1) ML-KEM encapsulation: produces (mlkem_ciphertext, S_pq).
  const { cipherText: mlkemCiphertext, sharedSecret: pqShare } =
    ml_kem1024.encapsulate(recipientPublicKey)

  // 2) Generate classical share and wrap it under the envelope key.
  const classicalShare = randomBytes(32)
  const classicalNonce = randomBytes(24)
  const classicalWrappedShort = sodium.crypto_secretbox_easy(
    classicalShare,
    classicalNonce,
    envelopeKey,
  )
  if (classicalWrappedShort.length !== 48) {
    throw new Error('encapsulate: unexpected secretbox length')
  }
  const classicalWrapped = new Uint8Array(72)
  classicalWrapped.set(classicalWrappedShort, 0)

  // 3) Combine.
  const combinedKey = await combineKeys(classicalShare, pqShare, fileId)

  // 4) Pack suite_payload.
  const suitePayload = buildPqHybridV1SuitePayload({
    mlkemCiphertext,
    classicalWrapped,
    classicalNonce,
  })

  return { suitePayload, combinedKey }
}

/**
 * Recipient side: recover the combined content key from the suite payload.
 */
export async function decapsulateFromHeader(options: {
  suitePayload: Uint8Array
  recipientSecretKey: Uint8Array
  envelopeKey: Uint8Array
  fileId: Uint8Array
}): Promise<{ combinedKey: Uint8Array }> {
  const sodium = await getSodium()
  const { suitePayload, recipientSecretKey, envelopeKey, fileId } = options

  if (recipientSecretKey.length !== ML_KEM_1024_SECRET_KEY_BYTES) {
    throw new RangeError('decapsulate: secret key must be 3168 bytes')
  }
  if (envelopeKey.length !== 32) {
    throw new RangeError('decapsulate: envelopeKey must be 32 bytes')
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('decapsulate: fileId must be 16 bytes')
  }

  const parsed = parsePqHybridV1SuitePayload(suitePayload)

  // 1) PQ decapsulation.
  const pqShare = ml_kem1024.decapsulate(
    parsed.mlkemCiphertext,
    recipientSecretKey,
  )

  // 2) Classical unwrap. libsodium-wrappers THROWS on Poly1305 MAC failure
  // (it does not return false), so the previous `if (!classicalShare)` guard
  // was unreachable dead code. Catch the throw and re-raise a single generic
  // error, folding the classical-unwrap failure into one message instead of
  // surfacing libsodium's internal "wrong secret key" string to the caller.
  const wrapped48 = parsed.classicalWrapped.slice(0, 48)
  let classicalShare: Uint8Array
  try {
    classicalShare = sodium.crypto_secretbox_open_easy(
      wrapped48,
      parsed.classicalNonce,
      envelopeKey,
    )
  } catch {
    throw new Error('decapsulate: unwrap failed')
  }

  // 3) Combine.
  const combinedKey = await combineKeys(classicalShare, pqShare, fileId)

  return { combinedKey }
}

export async function createChunkContext(
  combinedKey: Uint8Array,
  fileId: Uint8Array,
  totalChunks: number,
): Promise<PqHybridV1ChunkContext> {
  return deriveChunkContext(combinedKey, fileId, totalChunks)
}

export function getSuitePayloadFromHeader(
  header: ParsedHeader,
): PqHybridV1SuitePayload {
  return parsePqHybridV1SuitePayload(header.suitePayload)
}
