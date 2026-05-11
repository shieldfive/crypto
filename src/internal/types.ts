/**
 * Public type definitions for the shieldfive-crypto library.
 */

export type Crypto = {
  subtle: SubtleCrypto
  getRandomValues<T extends ArrayBufferView>(array: T): T
}

export type SubtleCrypto = globalThis.SubtleCrypto

/**
 * Suite identifiers as written to the on-disk format byte.
 * See `spec/format-v1.md` for the canonical assignment.
 */
export const SUITE = {
  AES_256_GCM_V1: 0x01,
  XCHACHA20_POLY1305_V1: 0x02,
  PQ_HYBRID_XCHACHA_MLKEM1024_V1: 0x03,
} as const

export type SuiteId = (typeof SUITE)[keyof typeof SUITE]

export type SuiteName =
  | 'aes-256-gcm-v1'
  | 'xchacha20-poly1305-v1'
  | 'pq-hybrid-xchacha-mlkem1024-v1'

export const SUITE_NAMES: Record<SuiteId, SuiteName> = {
  [SUITE.AES_256_GCM_V1]: 'aes-256-gcm-v1',
  [SUITE.XCHACHA20_POLY1305_V1]: 'xchacha20-poly1305-v1',
  [SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1]: 'pq-hybrid-xchacha-mlkem1024-v1',
}

/**
 * Magic bytes prefixing every v1-format file: "SF5" + major(1) + minor(0).
 * Treat as immutable; do not mutate.
 */
export const FORMAT_MAGIC: Uint8Array = new Uint8Array([
  0x53, 0x46, 0x35, 0x01, 0x00,
])

export const FORMAT_MAGIC_LENGTH = 5

/** Header field sizes — see spec/format-v1.md */
export const HEADER_SIZES = Object.freeze({
  MAGIC: 5,
  SUITE: 1,
  FLAGS: 1,
  FILE_ID: 16,
  CHUNK_SIZE: 4,
  TOTAL_CHUNKS: 8,
  PLAINTEXT_SIZE: 8,
  SUITE_PAYLOAD_LEN: 2,
  HEADER_MAC: 32,
})

/** Fixed bytes preceding the variable-length suite_payload */
export const HEADER_FIXED_PREFIX_LENGTH =
  HEADER_SIZES.MAGIC +
  HEADER_SIZES.SUITE +
  HEADER_SIZES.FLAGS +
  HEADER_SIZES.FILE_ID +
  HEADER_SIZES.CHUNK_SIZE +
  HEADER_SIZES.TOTAL_CHUNKS +
  HEADER_SIZES.PLAINTEXT_SIZE +
  HEADER_SIZES.SUITE_PAYLOAD_LEN

/** Default plaintext bytes per chunk for new uploads (4 MiB) */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024

/** Maximum permitted chunk_size in the format (uint32 max) */
export const MAX_CHUNK_SIZE = 0xffff_ffff

/** Maximum permitted total_chunks (sane upper bound, well below uint64 max) */
export const MAX_TOTAL_CHUNKS = 1_000_000_000

/** Domain separators for HKDF — never reuse a string here in another context */
export const HKDF_INFO = Object.freeze({
  HEADER_MAC: 'shieldfive/v1/header-mac',
  AES_GCM_CHUNK_KEY: 'shieldfive/v1/aes-gcm/chunk-key',
  AES_GCM_NONCE_PREFIX: 'shieldfive/v1/aes-gcm/nonce-prefix',
  XCHACHA_CHUNK_KEY: 'shieldfive/v1/xchacha/chunk-key',
  XCHACHA_NONCE_PREFIX: 'shieldfive/v1/xchacha/nonce-prefix',
  PQ_HYBRID_COMBINE: 'shieldfive/v1/pq-hybrid/combine',
  ML_KEM_1024_SEED: 'shieldfive/v1/pq-hybrid/ml-kem-1024-seed',
  ARGON2ID_SALT_COMPRESSION: 'shieldfive/v1/argon2id/salt-compression',
})

/** AAD domain string mixed into every chunk's authenticator */
export const CHUNK_AAD_DOMAIN = 'shieldfive/v1/chunk'
export const CHUNK_AAD_LENGTH = CHUNK_AAD_DOMAIN.length + 8 + 8 + 1

/**
 * Header values reflecting how a particular file was encrypted.
 * Returned by header parsers; consumed by chunk encrypt/decrypt loops.
 */
export interface ParsedHeader {
  suite: SuiteId
  flags: number
  fileId: Uint8Array
  chunkSize: number
  totalChunks: number
  plaintextSize: number
  suitePayload: Uint8Array
  /** Bytes consumed from the input — chunks start at this offset */
  headerLength: number
}

/**
 * Result of encrypting a file. The blob is the on-disk form (header +
 * concatenated chunks). Application metadata (file id, suite, chunk size)
 * is also returned so callers can stash it in their own database if they
 * want to look files up by id.
 */
export interface EncryptedFile {
  blob: Blob
  suite: SuiteId
  fileId: Uint8Array
  chunkSize: number
  totalChunks: number
  plaintextSize: number
}

/**
 * Progress callback shape, called after each chunk is processed. Progress
 * is reported as a float in [0, 1] inclusive. The final call is always
 * exactly 1.0.
 */
export type ProgressCallback = (progress: number) => void
