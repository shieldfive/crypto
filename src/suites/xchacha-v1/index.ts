/**
 * Cipher suite 0x02: XChaCha20-Poly1305 v1.
 *
 * 256-bit key, 192-bit nonce. Fresh per-file content key. Per-chunk AEAD
 * with the same file_id-bound AAD as the AES-GCM suite. Implementation via
 * libsodium-wrappers-sumo's `crypto_aead_xchacha20poly1305_ietf_*`.
 *
 * Why not secretstream? secretstream is a higher-level construction that
 * embeds its own state machine and chunk count. We want chunk-level random
 * access (for streaming downloads with range requests), so we use the AEAD
 * primitive directly with our own AAD-bound chunk indexing.
 */

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

export const XCHACHA_V1_KEY_BYTES = 32
export const XCHACHA_V1_NONCE_BYTES = 24
export const XCHACHA_V1_TAG_BYTES = 16

/** Suite payload layout: 72-byte secretbox-wrapped key + 24-byte nonce = 96 bytes. */
export const XCHACHA_V1_SUITE_PAYLOAD_LENGTH = 96

export interface XChaChaV1SuitePayload {
  wrappedKey: Uint8Array // 32-byte key + 16-byte secretbox tag = 48 bytes; padded to 72
  wrapNonce: Uint8Array // 24 bytes
}

export function buildXChaChaV1SuitePayload(
  payload: XChaChaV1SuitePayload,
): Uint8Array {
  if (payload.wrappedKey.length !== 72) {
    throw new RangeError('xchacha-v1: wrappedKey must be 72 bytes')
  }
  if (payload.wrapNonce.length !== XCHACHA_V1_NONCE_BYTES) {
    throw new RangeError('xchacha-v1: wrapNonce must be 24 bytes')
  }
  return concatBytes([payload.wrappedKey, payload.wrapNonce])
}

export function parseXChaChaV1SuitePayload(
  bytes: Uint8Array,
): XChaChaV1SuitePayload {
  if (bytes.length !== XCHACHA_V1_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError('xchacha-v1: suite payload must be 96 bytes')
  }
  return {
    wrappedKey: bytes.slice(0, 72),
    wrapNonce: bytes.slice(72, 96),
  }
}

async function deriveChunkKey(
  contentKey: Uint8Array,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.XCHACHA_CHUNK_KEY,
    length: XCHACHA_V1_KEY_BYTES,
  })
}

async function deriveNoncePrefix(fileId: Uint8Array): Promise<Uint8Array> {
  // XChaCha's 24-byte nonce: 16-byte file-derived prefix + 8-byte counter.
  return hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.XCHACHA_NONCE_PREFIX,
    length: 16,
  })
}

function buildNonce(noncePrefix: Uint8Array, chunkIndex: number): Uint8Array {
  const nonce = new Uint8Array(XCHACHA_V1_NONCE_BYTES)
  nonce.set(noncePrefix, 0)
  nonce.set(uint64BE(chunkIndex), 16)
  return nonce
}

export function generateContentMaterial(): {
  contentKey: Uint8Array
  fileId: Uint8Array
} {
  return {
    contentKey: randomBytes(XCHACHA_V1_KEY_BYTES),
    fileId: randomBytes(HEADER_SIZES.FILE_ID),
  }
}

export interface XChaChaV1ChunkContext {
  chunkKey: Uint8Array
  noncePrefix: Uint8Array
  totalChunks: number
}

export async function createChunkContext(
  contentKey: Uint8Array,
  fileId: Uint8Array,
  totalChunks: number,
): Promise<XChaChaV1ChunkContext> {
  const chunkKey = await deriveChunkKey(contentKey, fileId)
  const noncePrefix = await deriveNoncePrefix(fileId)
  return { chunkKey, noncePrefix, totalChunks }
}

export async function encryptChunk(
  ctx: XChaChaV1ChunkContext,
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
    ctx.chunkKey,
  )
}

export async function decryptChunk(
  ctx: XChaChaV1ChunkContext,
  chunkIndex: number,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const isFinal = chunkIndex === ctx.totalChunks - 1
  const aad = buildChunkAad(chunkIndex, ctx.totalChunks, isFinal)
  const nonce = buildNonce(ctx.noncePrefix, chunkIndex)
  const result = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    ctx.chunkKey,
  )
  return result
}

export async function wrapContentKey(options: {
  contentKey: Uint8Array
  envelopeKey: Uint8Array
}): Promise<{ wrapped: Uint8Array; wrapNonce: Uint8Array }> {
  const sodium = await getSodium()
  const { contentKey, envelopeKey } = options
  if (contentKey.length !== XCHACHA_V1_KEY_BYTES) {
    throw new RangeError('wrapContentKey: contentKey must be 32 bytes')
  }
  if (envelopeKey.length !== XCHACHA_V1_KEY_BYTES) {
    throw new RangeError('wrapContentKey: envelopeKey must be 32 bytes')
  }
  const wrapNonce = randomBytes(XCHACHA_V1_NONCE_BYTES)
  // crypto_secretbox_easy: outputs 16-byte poly1305 tag + ciphertext = 48 bytes
  const wrapped = sodium.crypto_secretbox_easy(
    contentKey,
    wrapNonce,
    envelopeKey,
  )
  if (wrapped.length !== 48) {
    throw new Error('wrapContentKey: unexpected wrapped length')
  }
  // Pad to 72 bytes for fixed suite_payload size
  const padded = new Uint8Array(72)
  padded.set(wrapped, 0)
  return { wrapped: padded, wrapNonce }
}

export async function unwrapContentKey(options: {
  envelopeKey: Uint8Array
  wrappedField: Uint8Array
  wrapNonce: Uint8Array
}): Promise<Uint8Array> {
  const sodium = await getSodium()
  const { envelopeKey, wrappedField, wrapNonce } = options
  if (envelopeKey.length !== XCHACHA_V1_KEY_BYTES) {
    throw new RangeError('unwrapContentKey: envelopeKey must be 32 bytes')
  }
  if (wrappedField.length !== 72) {
    throw new RangeError('unwrapContentKey: wrappedField must be 72 bytes')
  }
  if (wrapNonce.length !== XCHACHA_V1_NONCE_BYTES) {
    throw new RangeError('unwrapContentKey: wrapNonce must be 24 bytes')
  }
  // First 48 bytes are tag+key, the rest is reserved zeros.
  const wrapped = wrappedField.slice(0, 48)
  const unwrapped = sodium.crypto_secretbox_open_easy(
    wrapped,
    wrapNonce,
    envelopeKey,
  )
  if (!unwrapped) {
    throw new Error('unwrapContentKey: unwrap failed (wrong envelope key?)')
  }
  return unwrapped
}

export function getSuitePayloadFromHeader(
  header: ParsedHeader,
): XChaChaV1SuitePayload {
  return parseXChaChaV1SuitePayload(header.suitePayload)
}
