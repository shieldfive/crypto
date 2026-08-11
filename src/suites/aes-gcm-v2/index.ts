/**
 * Cipher suite 0x04: AES-256-GCM v2.
 *
 * Per-file content key. Per-chunk AEAD with file_id-bound AAD that
 * authenticates chunk index, total chunks, and the is-final flag. The
 * 12-byte GCM IV is split into an 8-byte file-derived prefix and a 4-byte
 * big-endian counter — a wider prefix than v1 (0x01) so the cross-file
 * nonce-prefix space widens from 2^32 to 2^64, shrinking the chance of an
 * IV collision across files that share a content key. The per-file chunk
 * ceiling drops from 2^64 to 2^32 chunks, which is still well above any
 * practical bound the format permits (`MAX_TOTAL_CHUNKS` is 1e9 and
 * `chunkIndex` is a safe JS integer).
 */

import { buildChunkAad } from '../../format/header.js'
import {
  HKDF_INFO,
  HEADER_SIZES,
  type ParsedHeader,
} from '../../internal/types.js'
import { concatBytes, uint32BE } from '../../internal/encoding.js'
import { hkdfSha256 } from '../../internal/hkdf.js'
import { getSubtle, randomBytes } from '../../internal/runtime.js'

export const AES_GCM_V2_TAG_BYTES = 16
export const AES_GCM_V2_IV_BYTES = 12
export const AES_GCM_V2_KEY_BYTES = 32
export const AES_GCM_V2_NONCE_PREFIX_LENGTH = 8
export const AES_GCM_V2_MAX_CHUNK_INDEX = 0xffff_ffff

/** Suite payload layout: 60-byte wrapped key + 12-byte wrap IV = 72 bytes. */
export const AES_GCM_V2_SUITE_PAYLOAD_LENGTH = 72

export interface AesGcmV2SuitePayload {
  wrappedKey: Uint8Array // 60 bytes (32-byte key + 16-byte tag + 12-byte AAD-padded reserved zeros)
  wrapIv: Uint8Array // 12 bytes
}

export function buildAesGcmV2SuitePayload(
  payload: AesGcmV2SuitePayload,
): Uint8Array {
  if (payload.wrappedKey.length !== 60) {
    throw new RangeError('aes-gcm-v2: wrappedKey must be 60 bytes')
  }
  if (payload.wrapIv.length !== AES_GCM_V2_IV_BYTES) {
    throw new RangeError('aes-gcm-v2: wrapIv must be 12 bytes')
  }
  return concatBytes([payload.wrappedKey, payload.wrapIv])
}

export function parseAesGcmV2SuitePayload(
  bytes: Uint8Array,
): AesGcmV2SuitePayload {
  if (bytes.length !== AES_GCM_V2_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError('aes-gcm-v2: suite payload must be 72 bytes')
  }
  // Reserved pad after the 48-byte wrap (bytes 48..60) MUST be all zero —
  // same invariant suite 0x03 enforces (M6). See parseAesGcmV1SuitePayload.
  for (let i = 48; i < 60; i += 1) {
    if (bytes[i] !== 0) {
      throw new RangeError('aes-gcm-v2: reserved wrapped_key pad must be zero')
    }
  }
  return {
    wrappedKey: bytes.slice(0, 60),
    wrapIv: bytes.slice(60, 72),
  }
}

/**
 * Derive the per-file chunk key from the content key. The chunk-key HKDF
 * info matches v1 because the chunk-key derivation is unchanged across
 * versions; only the nonce-prefix derivation differs. Files of either
 * suite encrypted with the same content_key + file_id derive identical
 * chunk keys, but their `(prefix, counter)` spaces are disjoint because
 * the prefix info string differs.
 */
async function deriveChunkKey(
  contentKey: Uint8Array,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.AES_GCM_CHUNK_KEY,
    length: AES_GCM_V2_KEY_BYTES,
  })
}

/**
 * Derive the 8-byte nonce prefix from file_id. Stable per file. The wider
 * prefix is the entire point of the v2 suite — see this file's top
 * docstring.
 */
async function deriveNoncePrefix(fileId: Uint8Array): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.AES_GCM_V2_NONCE_PREFIX,
    length: AES_GCM_V2_NONCE_PREFIX_LENGTH,
  })
}

function buildIv(noncePrefix: Uint8Array, chunkIndex: number): Uint8Array {
  if (
    !Number.isSafeInteger(chunkIndex) ||
    chunkIndex < 0 ||
    chunkIndex > AES_GCM_V2_MAX_CHUNK_INDEX
  ) {
    throw new RangeError(
      'aes-gcm-v2: chunkIndex must be in [0, 2^32)',
    )
  }
  if (noncePrefix.length !== AES_GCM_V2_NONCE_PREFIX_LENGTH) {
    throw new RangeError('aes-gcm-v2: noncePrefix must be 8 bytes')
  }
  const iv = new Uint8Array(AES_GCM_V2_IV_BYTES)
  iv.set(noncePrefix, 0)
  iv.set(uint32BE(chunkIndex), AES_GCM_V2_NONCE_PREFIX_LENGTH)
  return iv
}

async function importAesGcmKey(
  keyBytes: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  if (keyBytes.length !== AES_GCM_V2_KEY_BYTES) {
    throw new RangeError('aes-gcm-v2: key must be 32 bytes')
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
    contentKey: randomBytes(AES_GCM_V2_KEY_BYTES),
    fileId: randomBytes(HEADER_SIZES.FILE_ID),
  }
}

export interface AesGcmV2ChunkContext {
  cryptoKey: CryptoKey
  noncePrefix: Uint8Array
  totalChunks: number
}

export async function createChunkContext(
  contentKey: Uint8Array,
  fileId: Uint8Array,
  totalChunks: number,
): Promise<AesGcmV2ChunkContext> {
  if (totalChunks > AES_GCM_V2_MAX_CHUNK_INDEX + 1) {
    // Defense in depth — header-layer MAX_TOTAL_CHUNKS already caps this
    // well below 2^32, but the suite enforces its own ceiling.
    throw new RangeError(
      'aes-gcm-v2: totalChunks exceeds 2^32 chunk-index space',
    )
  }
  const chunkKeyBytes = await deriveChunkKey(contentKey, fileId)
  const noncePrefix = await deriveNoncePrefix(fileId)
  const cryptoKey = await importAesGcmKey(chunkKeyBytes, ['encrypt', 'decrypt'])
  return { cryptoKey, noncePrefix, totalChunks }
}

export async function encryptChunk(
  ctx: AesGcmV2ChunkContext,
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
  ctx: AesGcmV2ChunkContext,
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
 * The wrap layer is identical to v1: it is a one-shot AES-GCM encryption
 * of a 32-byte key under a fresh 12-byte IV, which has no counter-mode
 * collision concern.
 */
export async function wrapContentKey(options: {
  contentKey: Uint8Array
  envelopeKey: Uint8Array
  envelopeAad?: Uint8Array
}): Promise<{ wrapped: Uint8Array; wrapIv: Uint8Array }> {
  const { contentKey, envelopeKey } = options
  if (contentKey.length !== AES_GCM_V2_KEY_BYTES) {
    throw new RangeError('wrapContentKey: contentKey must be 32 bytes')
  }
  if (envelopeKey.length !== AES_GCM_V2_KEY_BYTES) {
    throw new RangeError('wrapContentKey: envelopeKey must be 32 bytes')
  }
  const wrapIv = randomBytes(AES_GCM_V2_IV_BYTES)
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
  if (envelopeKey.length !== AES_GCM_V2_KEY_BYTES) {
    throw new RangeError('unwrapContentKey: envelopeKey must be 32 bytes')
  }
  if (wrappedField.length !== 60) {
    throw new RangeError('unwrapContentKey: wrappedField must be 60 bytes')
  }
  if (wrapIv.length !== AES_GCM_V2_IV_BYTES) {
    throw new RangeError('unwrapContentKey: wrapIv must be 12 bytes')
  }
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
  if (ptBytes.length !== AES_GCM_V2_KEY_BYTES) {
    throw new Error('unwrapContentKey: bad plaintext length')
  }
  return ptBytes
}

/** Header parser hook — exposes ParsedHeader convenience for suite consumers. */
export function getSuitePayloadFromHeader(
  header: ParsedHeader,
): AesGcmV2SuitePayload {
  return parseAesGcmV2SuitePayload(header.suitePayload)
}
