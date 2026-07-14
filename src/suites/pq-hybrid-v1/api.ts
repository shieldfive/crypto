/**
 * High-level encrypt/decrypt API for the PQ-hybrid v1 suite.
 *
 * Differs from aes-gcm-v1 / xchacha-v1 because content key derivation is
 * not a single random 32-byte buffer — instead, the combined key is
 * recovered from the on-disk suite payload (PQ ciphertext + wrapped
 * classical share) and the recipient's PQ secret key + envelope key.
 *
 * The header MAC is keyed by the *combined* key, so a successful header
 * MAC verification proves both the PQ KEM and the classical wrap were
 * recovered correctly.
 */

import {
  buildAuthenticatedHeader,
  parseHeader,
  verifyHeaderMac,
  HeaderError,
} from '../../format/header.js'
import {
  PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH,
  PQ_HYBRID_V1_TAG_BYTES,
  createChunkContext,
  decapsulateFromHeader,
  decryptChunk,
  encapsulateForRecipient,
  encryptChunk,
} from './index.js'
import {
  DEFAULT_CHUNK_SIZE,
  type EncryptedFile,
  HEADER_SIZES,
  MAX_TOTAL_CHUNKS,
  type ProgressCallback,
  SUITE,
} from '../../internal/types.js'
import {
  asBlobPart,
  readUint32BE,
  uint32BE,
} from '../../internal/encoding.js'
import { randomBytes } from '../../internal/runtime.js'

// Re-exports of suite primitives that are useful to callers outside the
// streaming/whole-blob API surfaces. `decapsulateFromHeader` lets a
// caller that already has the parsed suite_payload + KEM material
// recover the combined key K out-of-band (e.g., a share-link generator
// that wraps K under a separate password for recipients who never see
// ML-KEM secrets).
export {
  decapsulateFromHeader,
  deriveMlKemKeypair,
  encapsulateForRecipient,
  generateMlKemKeypair,
  PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH,
} from './index.js'

const LENGTH_PREFIX_BYTES = 4

export interface EncryptOptions {
  blob: Blob
  /** Recipient's ML-KEM-1024 public key (1568 bytes) */
  recipientPublicKey: Uint8Array
  /** Classical envelope key under which the classical share is wrapped */
  envelopeKey: Uint8Array
  fileId?: Uint8Array
  chunkSize?: number
  onProgress?: ProgressCallback
}

/**
 * Encrypt a Blob under suite 0x03 (PQ-hybrid XChaCha20-Poly1305 +
 * ML-KEM-1024). Returns the encrypted file alongside the combined
 * content key used to produce it.
 *
 * SECURITY: The returned `combinedKey` grants permanent decryption
 * capability for any file whose header was produced with it. Treat
 * as cryptographic secret material: hold only in memory for the
 * duration of the operation, do not persist to disk or storage, do
 * not log, do not transmit. The only safe way to reproduce it on
 * another machine is to re-encapsulate via the recipient's ML-KEM
 * public key.
 */
export async function encryptBlob(
  options: EncryptOptions,
): Promise<EncryptedFile & { combinedKey: Uint8Array }> {
  const { blob, recipientPublicKey, envelopeKey, onProgress } = options
  if (!(blob instanceof Blob)) {
    throw new TypeError('encryptBlob: blob must be a Blob or File')
  }

  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new RangeError('encryptBlob: chunkSize must be a positive integer')
  }

  const plaintextSize = blob.size
  const totalChunks =
    plaintextSize === 0 ? 0 : Math.ceil(plaintextSize / chunkSize)
  if (totalChunks > MAX_TOTAL_CHUNKS) {
    throw new RangeError('encryptBlob: file would exceed total_chunks limit')
  }

  const fileId = options.fileId ?? randomBytes(HEADER_SIZES.FILE_ID)
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('encryptBlob: fileId must be 16 bytes')
  }

  // PQ + classical encapsulation produces the suite payload AND the
  // combined key in one step. The combined key is what authenticates the
  // header and encrypts every chunk.
  const { suitePayload, combinedKey } = await encapsulateForRecipient({
    recipientPublicKey,
    envelopeKey,
    fileId,
  })

  const header = await buildAuthenticatedHeader(
    {
      suite: SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1,
      fileId,
      chunkSize,
      totalChunks,
      plaintextSize,
      suitePayload,
    },
    combinedKey,
  )

  const ctx = await createChunkContext(combinedKey, fileId, totalChunks)

  const parts: BlobPart[] = [asBlobPart(header)]
  for (let i = 0; i < totalChunks; i += 1) {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, plaintextSize)
    const plaintextBytes = new Uint8Array(
      await blob.slice(start, end).arrayBuffer(),
    )
    const ciphertext = await encryptChunk(ctx, i, plaintextBytes)
    parts.push(asBlobPart(uint32BE(ciphertext.length)))
    parts.push(asBlobPart(ciphertext))
    onProgress?.((i + 1) / Math.max(totalChunks, 1))
  }

  if (totalChunks === 0) onProgress?.(1)

  return {
    blob: new Blob(parts, { type: 'application/octet-stream' }),
    suite: SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1,
    fileId,
    chunkSize,
    totalChunks,
    plaintextSize,
    combinedKey,
  }
}

export interface DecryptOptions {
  blob: Blob
  /** Recipient's ML-KEM-1024 secret key (3168 bytes) */
  recipientSecretKey: Uint8Array
  /** Classical envelope key */
  envelopeKey: Uint8Array
  onProgress?: ProgressCallback
}

export async function decryptBlob(
  options: DecryptOptions,
): Promise<Blob> {
  const { blob, recipientSecretKey, envelopeKey, onProgress } = options
  if (!(blob instanceof Blob)) {
    throw new TypeError('decryptBlob: blob must be a Blob or File')
  }

  // The header for this suite is large because suite_payload is 1664 bytes.
  // Probe enough bytes to capture it.
  const headerProbeSize = Math.min(
    blob.size,
    HEADER_SIZES.MAGIC +
      HEADER_SIZES.SUITE +
      HEADER_SIZES.FLAGS +
      HEADER_SIZES.FILE_ID +
      HEADER_SIZES.CHUNK_SIZE +
      HEADER_SIZES.TOTAL_CHUNKS +
      HEADER_SIZES.PLAINTEXT_SIZE +
      HEADER_SIZES.SUITE_PAYLOAD_LEN +
      PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH +
      HEADER_SIZES.HEADER_MAC +
      32, // padding
  )
  const headerProbeBytes = new Uint8Array(
    await blob.slice(0, headerProbeSize).arrayBuffer(),
  )

  const parsed = parseHeader(headerProbeBytes)

  if (parsed.suite !== SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1) {
    throw new HeaderError(
      `decryptBlob: this entry point only supports pq-hybrid-xchacha-mlkem1024-v1; got suite 0x${parsed.suite.toString(16)}`,
    )
  }

  // Recover the combined key — this is where PQ decapsulation happens.
  const { combinedKey } = await decapsulateFromHeader({
    suitePayload: parsed.suitePayload,
    recipientSecretKey,
    envelopeKey,
    fileId: parsed.fileId,
  })

  // The header MAC implicitly verifies that the right combined key was
  // recovered (i.e., the PQ secret + envelope key match the file).
  await verifyHeaderMac(parsed, combinedKey)

  const ctx = await createChunkContext(
    combinedKey,
    parsed.fileId,
    parsed.totalChunks,
  )

  const plaintextParts: BlobPart[] = []
  let cursor = parsed.headerLength
  let bytesEmitted = 0

  for (let i = 0; i < parsed.totalChunks; i += 1) {
    if (cursor + LENGTH_PREFIX_BYTES > blob.size) {
      throw new HeaderError('chunk_length_truncated')
    }
    const lenBytes = new Uint8Array(
      await blob.slice(cursor, cursor + LENGTH_PREFIX_BYTES).arrayBuffer(),
    )
    cursor += LENGTH_PREFIX_BYTES
    const cipherLen = readUint32BE(lenBytes)

    const isFinal = i === parsed.totalChunks - 1
    const minCipher = 1 + PQ_HYBRID_V1_TAG_BYTES
    const maxCipher = parsed.chunkSize + PQ_HYBRID_V1_TAG_BYTES
    if (cipherLen < minCipher || cipherLen > maxCipher) {
      throw new HeaderError('chunk_length_out_of_range')
    }
    if (!isFinal && cipherLen !== maxCipher) {
      throw new HeaderError('non_final_chunk_wrong_size')
    }

    if (cursor + cipherLen > blob.size) {
      throw new HeaderError('chunk_truncated')
    }

    const cipherBytes = new Uint8Array(
      await blob.slice(cursor, cursor + cipherLen).arrayBuffer(),
    )
    cursor += cipherLen

    const plaintext = await decryptChunk(ctx, i, cipherBytes)
    bytesEmitted += plaintext.length
    plaintextParts.push(asBlobPart(plaintext))

    onProgress?.((i + 1) / Math.max(parsed.totalChunks, 1))
  }

  if (bytesEmitted !== parsed.plaintextSize) {
    throw new HeaderError('plaintext_size_mismatch')
  }
  if (cursor !== blob.size) {
    throw new HeaderError('trailing_bytes_after_last_chunk')
  }

  if (parsed.totalChunks === 0) onProgress?.(1)

  return new Blob(plaintextParts, { type: 'application/octet-stream' })
}

/**
 * Encrypt a Uint8Array under suite 0x03 (PQ-hybrid XChaCha20-Poly1305 +
 * ML-KEM-1024). Returns the encrypted file alongside the combined
 * content key used to produce it.
 *
 * SECURITY: The returned `combinedKey` grants permanent decryption
 * capability for any file whose header was produced with it. Treat
 * as cryptographic secret material: hold only in memory for the
 * duration of the operation, do not persist to disk or storage, do
 * not log, do not transmit. The only safe way to reproduce it on
 * another machine is to re-encapsulate via the recipient's ML-KEM
 * public key.
 */
export async function encryptBytes(
  bytes: Uint8Array | ArrayBuffer,
  options: Omit<EncryptOptions, 'blob'>,
): Promise<EncryptedFile & { combinedKey: Uint8Array }> {
  const part: BlobPart =
    bytes instanceof ArrayBuffer ? bytes : asBlobPart(bytes)
  const blob = new Blob([part])
  return encryptBlob({ blob, ...options })
}

export async function decryptToBytes(
  options: DecryptOptions,
): Promise<Uint8Array> {
  const blob = await decryptBlob(options)
  return new Uint8Array(await blob.arrayBuffer())
}
