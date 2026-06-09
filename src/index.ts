/**
 * @shieldfive/crypto — open-source, post-quantum-hybrid client-side
 * encryption for cloud storage.
 *
 * Public entry point. Most callers should import from a specific suite
 * subpath instead of the bare module name:
 *
 *   import { encryptBlob, decryptBlob } from '@shieldfive/crypto/pq-hybrid-v1'
 *   import { encryptBlob, decryptBlob } from '@shieldfive/crypto/aes-gcm-v2'
 *   import { decryptBlob } from '@shieldfive/crypto/aes-gcm-v1' // decrypt-only
 *   import { encryptBlob, decryptBlob } from '@shieldfive/crypto/xchacha-v1'
 *   import { decryptV0 } from '@shieldfive/crypto/legacy-v0'
 *
 * The umbrella `import { ... } from '@shieldfive/crypto'` exposes shared
 * format primitives, type definitions, and an auto-routing decryptor that
 * dispatches by suite ID.
 */

// ──────────────────────────────────────────────────────────────────────
// Format primitives
// ──────────────────────────────────────────────────────────────────────
export {
  buildAuthenticatedHeader,
  buildChunkAad,
  buildHeaderUnauthenticated,
  deriveHeaderMacKey,
  HeaderError,
  parseHeader,
  verifyHeaderMac,
} from './format/header.js'

// ──────────────────────────────────────────────────────────────────────
// Type definitions and constants
// ──────────────────────────────────────────────────────────────────────
export {
  CHUNK_AAD_DOMAIN,
  CHUNK_AAD_LENGTH,
  DEFAULT_CHUNK_SIZE,
  FORMAT_MAGIC,
  FORMAT_MAGIC_LENGTH,
  HEADER_FIXED_PREFIX_LENGTH,
  HEADER_SIZES,
  HKDF_INFO,
  MAX_CHUNK_SIZE,
  MAX_TOTAL_CHUNKS,
  SUITE,
  SUITE_NAMES,
} from './internal/types.js'
export type {
  EncryptedFile,
  ParsedHeader,
  ProgressCallback,
  SuiteId,
  SuiteName,
} from './internal/types.js'

// ──────────────────────────────────────────────────────────────────────
// Encoding utilities (base64, hex, uint codecs)
// ──────────────────────────────────────────────────────────────────────
export {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  concatBytes,
} from './internal/encoding.js'

// ──────────────────────────────────────────────────────────────────────
// Runtime helpers
// ──────────────────────────────────────────────────────────────────────
export {
  constantTimeEqual,
  randomBytes,
  zeroize,
} from './internal/runtime.js'

// ──────────────────────────────────────────────────────────────────────
// Re-export suite namespaces for direct consumption.
// The aes-gcm encrypt path on the umbrella is v2 (0x04). v1 (0x01) is
// exposed decrypt-only here because new files should never be written
// with the narrow 4-byte nonce prefix. Callers that genuinely need to
// re-encrypt as v1 (e.g. migration tooling) can still import from the
// @shieldfive/crypto/aes-gcm-v1 subpath.
// ──────────────────────────────────────────────────────────────────────
import {
  decryptBlob as aesGcmV1DecryptBlob,
  decryptToBytes as aesGcmV1DecryptToBytes,
} from './suites/aes-gcm-v1/api.js'
export const aesGcmV1 = {
  decryptBlob: aesGcmV1DecryptBlob,
  decryptToBytes: aesGcmV1DecryptToBytes,
}
export * as aesGcmV2 from './suites/aes-gcm-v2/api.js'
export * as xchachaV1 from './suites/xchacha-v1/api.js'
export * as pqHybridV1 from './suites/pq-hybrid-v1/api.js'
export * as legacyV0 from './suites/aes-gcm-v0/api.js'
export * as streamsAesGcmV1 from './streams/aes-gcm-v1.js'
export * as kdfArgon2id from './kdf/argon2id.js'
export * as identity from './identity/index.js'
export * as migrationV0 from './migration/v0-bridge.js'

// ──────────────────────────────────────────────────────────────────────
// Auto-routing decryptor
// ──────────────────────────────────────────────────────────────────────
import { parseHeader, HeaderError } from './format/header.js'
import { SUITE, type SuiteId } from './internal/types.js'
import * as aes from './suites/aes-gcm-v1/api.js'
import * as aesV2 from './suites/aes-gcm-v2/api.js'
import * as xchacha from './suites/xchacha-v1/api.js'
import * as pqHybrid from './suites/pq-hybrid-v1/api.js'

export interface AutoDecryptOptions {
  blob: Blob
  /** Used for AES-GCM-v1/v2 and XChaCha-v1 (32-byte raw content key) */
  contentKey?: Uint8Array
  /** Required for PQ-hybrid: ML-KEM-1024 secret key (3168 bytes) */
  recipientSecretKey?: Uint8Array
  /** Required for PQ-hybrid: classical 32-byte envelope key */
  envelopeKey?: Uint8Array
  /** Optional progress callback (0..1) */
  onProgress?: (progress: number) => void
}

/**
 * Decrypt a v1-format blob, automatically dispatching to the correct suite
 * based on the header's suite byte. Throws if the suite requires inputs the
 * caller didn't provide. For v0 (legacy) files, use `legacyV0.decryptV0`
 * directly — v0 has no header, so the dispatcher cannot route to it.
 */
export async function autoDecryptBlob(
  options: AutoDecryptOptions,
): Promise<Blob> {
  const { blob } = options
  if (!(blob instanceof Blob)) {
    throw new TypeError('autoDecryptBlob: blob must be a Blob or File')
  }

  const headerProbe = new Uint8Array(
    await blob.slice(0, Math.min(blob.size, 4096)).arrayBuffer(),
  )

  let suite: SuiteId
  try {
    const parsed = parseHeader(headerProbe)
    suite = parsed.suite
  } catch (err) {
    // If parse fails because of a too-short probe, escalate. Suites with
    // larger suite_payloads (notably PQ hybrid at 1664 bytes) need more.
    if (err instanceof HeaderError && err.code === 'header_too_short') {
      const bigger = new Uint8Array(
        await blob
          .slice(0, Math.min(blob.size, 4 + 0xffff + 64))
          .arrayBuffer(),
      )
      const parsed = parseHeader(bigger)
      suite = parsed.suite
    } else {
      throw err
    }
  }

  switch (suite) {
    case SUITE.AES_256_GCM_V1: {
      if (!options.contentKey) {
        throw new Error(
          'autoDecryptBlob: contentKey required for aes-256-gcm-v1',
        )
      }
      return aes.decryptBlob({
        blob,
        contentKey: options.contentKey,
        ...(options.onProgress ? { onProgress: options.onProgress } : {}),
      })
    }
    case SUITE.AES_256_GCM_V2: {
      if (!options.contentKey) {
        throw new Error(
          'autoDecryptBlob: contentKey required for aes-256-gcm-v2',
        )
      }
      return aesV2.decryptBlob({
        blob,
        contentKey: options.contentKey,
        ...(options.onProgress ? { onProgress: options.onProgress } : {}),
      })
    }
    case SUITE.XCHACHA20_POLY1305_V1: {
      if (!options.contentKey) {
        throw new Error(
          'autoDecryptBlob: contentKey required for xchacha20-poly1305-v1',
        )
      }
      return xchacha.decryptBlob({
        blob,
        contentKey: options.contentKey,
        ...(options.onProgress ? { onProgress: options.onProgress } : {}),
      })
    }
    case SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1: {
      if (!options.recipientSecretKey || !options.envelopeKey) {
        throw new Error(
          'autoDecryptBlob: recipientSecretKey and envelopeKey required for pq-hybrid-v1',
        )
      }
      return pqHybrid.decryptBlob({
        blob,
        recipientSecretKey: options.recipientSecretKey,
        envelopeKey: options.envelopeKey,
        ...(options.onProgress ? { onProgress: options.onProgress } : {}),
      })
    }
    default: {
      throw new HeaderError(
        `autoDecryptBlob: unknown suite 0x${(suite as number).toString(16)}`,
      )
    }
  }
}

/** Library version, also written into format documentation. */
export const SHIELDFIVE_CRYPTO_VERSION = '1.0.0-alpha.14'

/** Default cipher suite for new files when not specified by the caller. */
export const DEFAULT_SUITE = SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1
