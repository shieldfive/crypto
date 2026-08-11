/**
 * Cipher suite 0x01: AES-256-GCM v1.
 *
 * Decrypt-only for legacy files created before 2026-05-21; new encrypts
 * use 0x04 aes-gcm-v2, which widens the file-derived nonce prefix.
 *
 * Per-file content key. Per-chunk AEAD with file_id-bound AAD that
 * authenticates chunk index, total chunks, and the is-final flag. The
 * 12-byte GCM IV is split into a 4-byte file-derived prefix and an 8-byte
 * big-endian counter.
 */

import { buildChunkAad } from '../../format/header.js'
import {
  HKDF_INFO,
  HEADER_SIZES,
  type ParsedHeader,
} from '../../internal/types.js'
import { concatBytes, uint64BE } from '../../internal/encoding.js'
import { hkdfSha256 } from '../../internal/hkdf.js'
import { getSubtle, randomBytes } from '../../internal/runtime.js'

export const AES_GCM_V1_TAG_BYTES = 16
export const AES_GCM_V1_IV_BYTES = 12
export const AES_GCM_V1_KEY_BYTES = 32

/** Suite payload layout: 60-byte wrapped key + 12-byte wrap IV = 72 bytes. */
export const AES_GCM_V1_SUITE_PAYLOAD_LENGTH = 72

export interface AesGcmV1SuitePayload {
  wrappedKey: Uint8Array // 60 bytes (32-byte key + 16-byte tag + 12-byte AAD-padded reserved zeros)
  wrapIv: Uint8Array // 12 bytes
}

export function buildAesGcmV1SuitePayload(
  payload: AesGcmV1SuitePayload,
): Uint8Array {
  if (payload.wrappedKey.length !== 60) {
    throw new RangeError('aes-gcm-v1: wrappedKey must be 60 bytes')
  }
  if (payload.wrapIv.length !== AES_GCM_V1_IV_BYTES) {
    throw new RangeError('aes-gcm-v1: wrapIv must be 12 bytes')
  }
  return concatBytes([payload.wrappedKey, payload.wrapIv])
}

export function parseAesGcmV1SuitePayload(
  bytes: Uint8Array,
): AesGcmV1SuitePayload {
  if (bytes.length !== AES_GCM_V1_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError(
      'aes-gcm-v1: suite payload must be 72 bytes',
    )
  }
  // The 48-byte AES-GCM wrap (32-byte key + 16-byte tag) is zero-padded to
  // 60 bytes; the reserved pad (bytes 48..60) MUST be all zero, mirroring
  // suite 0x03's M6 check (src/suites/pq-hybrid-v1/index.ts). Without it a
  // content-key holder could set arbitrary pad bytes, recompute the header
  // MAC, and ship a MAC-valid file no reader validates — a canonicalization
  // gap where two bit-distinct files decrypt identically.
  for (let i = 48; i < 60; i += 1) {
    if (bytes[i] !== 0) {
      throw new RangeError('aes-gcm-v1: reserved wrapped_key pad must be zero')
    }
  }
  return {
    wrappedKey: bytes.slice(0, 60),
    wrapIv: bytes.slice(60, 72),
  }
}

/**
 * Derive the per-file chunk key from the content key.
 * Even though the content key is fresh per file, we run it through HKDF
 * so that any future bug that recycles a content key cannot also recycle
 * the chunk key under the same file_id.
 */
async function deriveChunkKey(
  contentKey: Uint8Array,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.AES_GCM_CHUNK_KEY,
    length: AES_GCM_V1_KEY_BYTES,
  })
}

/**
 * Derive the 4-byte nonce prefix from file_id. Stable per file.
 */
async function deriveNoncePrefix(fileId: Uint8Array): Promise<Uint8Array> {
  const out = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.AES_GCM_NONCE_PREFIX,
    length: 4,
  })
  return out
}

function buildIv(noncePrefix: Uint8Array, chunkIndex: number): Uint8Array {
  const iv = new Uint8Array(AES_GCM_V1_IV_BYTES)
  iv.set(noncePrefix, 0)
  iv.set(uint64BE(chunkIndex), 4)
  return iv
}

async function importAesGcmKey(
  keyBytes: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  if (keyBytes.length !== AES_GCM_V1_KEY_BYTES) {
    throw new RangeError('aes-gcm-v1: key must be 32 bytes')
  }
  return getSubtle().importKey(
    'raw',
    keyBytes as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    usages,
  )
}

/** Generate a fresh per-file content key and file_id. */
export function generateContentMaterial(): {
  contentKey: Uint8Array
  fileId: Uint8Array
} {
  return {
    contentKey: randomBytes(AES_GCM_V1_KEY_BYTES),
    fileId: randomBytes(HEADER_SIZES.FILE_ID),
  }
}

export interface AesGcmV1ChunkContext {
  cryptoKey: CryptoKey
  noncePrefix: Uint8Array
  totalChunks: number
}

export async function createChunkContext(
  contentKey: Uint8Array,
  fileId: Uint8Array,
  totalChunks: number,
): Promise<AesGcmV1ChunkContext> {
  const chunkKeyBytes = await deriveChunkKey(contentKey, fileId)
  const noncePrefix = await deriveNoncePrefix(fileId)
  const cryptoKey = await importAesGcmKey(chunkKeyBytes, ['encrypt', 'decrypt'])
  return { cryptoKey, noncePrefix, totalChunks }
}

export async function encryptChunk(
  ctx: AesGcmV1ChunkContext,
  chunkIndex: number,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const isFinal = chunkIndex === ctx.totalChunks - 1
  const aad = buildChunkAad(chunkIndex, ctx.totalChunks, isFinal)
  const iv = buildIv(ctx.noncePrefix, chunkIndex)
  const ct = await getSubtle().encrypt(
    {
      name: 'AES-GCM',
      iv: iv as Uint8Array<ArrayBuffer>,
      additionalData: aad as Uint8Array<ArrayBuffer>,
      tagLength: 128,
    },
    ctx.cryptoKey,
    plaintext as Uint8Array<ArrayBuffer>,
  )
  return new Uint8Array(ct)
}

export async function decryptChunk(
  ctx: AesGcmV1ChunkContext,
  chunkIndex: number,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const isFinal = chunkIndex === ctx.totalChunks - 1
  const aad = buildChunkAad(chunkIndex, ctx.totalChunks, isFinal)
  const iv = buildIv(ctx.noncePrefix, chunkIndex)
  const pt = await getSubtle().decrypt(
    {
      name: 'AES-GCM',
      iv: iv as Uint8Array<ArrayBuffer>,
      additionalData: aad as Uint8Array<ArrayBuffer>,
      tagLength: 128,
    },
    ctx.cryptoKey,
    ciphertext as Uint8Array<ArrayBuffer>,
  )
  return new Uint8Array(pt)
}

/**
 * Wrap (encrypt) a content key under an envelope key (folder/vault key).
 * This is what the suite_payload's wrappedKey field carries when the
 * caller chooses to embed the wrapped key in the file rather than store
 * it in a database.
 */
export async function wrapContentKey(options: {
  contentKey: Uint8Array
  envelopeKey: Uint8Array
  envelopeAad?: Uint8Array
}): Promise<{ wrapped: Uint8Array; wrapIv: Uint8Array }> {
  const { contentKey, envelopeKey } = options
  if (contentKey.length !== AES_GCM_V1_KEY_BYTES) {
    throw new RangeError('wrapContentKey: contentKey must be 32 bytes')
  }
  if (envelopeKey.length !== AES_GCM_V1_KEY_BYTES) {
    throw new RangeError('wrapContentKey: envelopeKey must be 32 bytes')
  }
  const wrapIv = randomBytes(AES_GCM_V1_IV_BYTES)
  const wrapKey = await importAesGcmKey(envelopeKey, ['encrypt'])
  const wrapped = await getSubtle().encrypt(
    {
      name: 'AES-GCM',
      iv: wrapIv as Uint8Array<ArrayBuffer>,
      additionalData:
        (options.envelopeAad ?? new Uint8Array(0)) as Uint8Array<ArrayBuffer>,
      tagLength: 128,
    },
    wrapKey,
    contentKey as Uint8Array<ArrayBuffer>,
  )
  // wrapped = 32-byte key + 16-byte tag = 48 bytes; pad to 60 with zeros
  // so the suite_payload size is fixed regardless of whether the file
  // embeds an inline wrapped key or zero-fills the field.
  const wrappedBytes = new Uint8Array(wrapped)
  if (wrappedBytes.length !== 48) {
    throw new Error('wrapContentKey: unexpected wrapped length')
  }
  const padded = new Uint8Array(60)
  padded.set(wrappedBytes, 0)
  return { wrapped: padded, wrapIv }
}

export async function unwrapContentKey(options: {
  envelopeKey: Uint8Array
  wrappedField: Uint8Array
  wrapIv: Uint8Array
  envelopeAad?: Uint8Array
}): Promise<Uint8Array> {
  const { envelopeKey, wrappedField, wrapIv } = options
  if (envelopeKey.length !== AES_GCM_V1_KEY_BYTES) {
    throw new RangeError('unwrapContentKey: envelopeKey must be 32 bytes')
  }
  if (wrappedField.length !== 60) {
    throw new RangeError('unwrapContentKey: wrappedField must be 60 bytes')
  }
  if (wrapIv.length !== AES_GCM_V1_IV_BYTES) {
    throw new RangeError('unwrapContentKey: wrapIv must be 12 bytes')
  }
  // The first 48 bytes are key+tag; the last 12 are reserved zeros.
  const wrapped = wrappedField.slice(0, 48)
  const wrapKey = await importAesGcmKey(envelopeKey, ['decrypt'])
  const pt = await getSubtle().decrypt(
    {
      name: 'AES-GCM',
      iv: wrapIv as Uint8Array<ArrayBuffer>,
      additionalData:
        (options.envelopeAad ?? new Uint8Array(0)) as Uint8Array<ArrayBuffer>,
      tagLength: 128,
    },
    wrapKey,
    wrapped as Uint8Array<ArrayBuffer>,
  )
  const ptBytes = new Uint8Array(pt)
  if (ptBytes.length !== AES_GCM_V1_KEY_BYTES) {
    throw new Error('unwrapContentKey: bad plaintext length')
  }
  return ptBytes
}

/** Header parser hook — exposes ParsedHeader convenience for suite consumers. */
export function getSuitePayloadFromHeader(
  header: ParsedHeader,
): AesGcmV1SuitePayload {
  return parseAesGcmV1SuitePayload(header.suitePayload)
}
