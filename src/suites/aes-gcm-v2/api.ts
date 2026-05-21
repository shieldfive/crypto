/**
 * High-level encrypt/decrypt API for the AES-256-GCM v2 suite.
 *
 * Identical glue to the v1 API (header construction + chunked AEAD); the
 * difference is the suite ID and the underlying nonce-prefix width — see
 * `./index.ts` for the v2 rationale.
 */

import {
  buildAuthenticatedHeader,
  parseHeader,
  verifyHeaderMac,
  HeaderError,
} from '../../format/header.js'
import {
  AES_GCM_V2_SUITE_PAYLOAD_LENGTH,
  AES_GCM_V2_TAG_BYTES,
  createChunkContext,
  decryptChunk,
  encryptChunk,
  generateContentMaterial,
  parseAesGcmV2SuitePayload,
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

const LENGTH_PREFIX_BYTES = 4

export interface EncryptOptions {
  blob: Blob
  /** Optional pre-existing content key (32 bytes). If omitted, generated. */
  contentKey?: Uint8Array
  /** Optional pre-existing file_id (16 bytes). If omitted, generated. */
  fileId?: Uint8Array
  /** Optional embedded wrapped key + IV (60 + 12 bytes). Defaults to zeros. */
  suitePayloadOverride?: Uint8Array
  /** Plaintext bytes per chunk. Defaults to 4 MiB. */
  chunkSize?: number
  /** Progress callback (0..1). Called once per chunk and once at completion. */
  onProgress?: ProgressCallback
}

/**
 * Encrypt a Blob/File with the AES-256-GCM v2 suite.
 * Returns the encrypted blob (header + chunks), plus the content key and
 * file id so the caller can wrap/store them externally.
 */
export async function encryptBlob(
  options: EncryptOptions,
): Promise<EncryptedFile & { contentKey: Uint8Array }> {
  const { blob, onProgress } = options
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

  const generated = generateContentMaterial()
  const contentKey = options.contentKey ?? generated.contentKey
  const fileId = options.fileId ?? generated.fileId
  if (contentKey.length !== 32) {
    throw new RangeError('encryptBlob: contentKey must be 32 bytes')
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('encryptBlob: fileId must be 16 bytes')
  }

  const suitePayload =
    options.suitePayloadOverride ??
    new Uint8Array(AES_GCM_V2_SUITE_PAYLOAD_LENGTH)
  if (suitePayload.length !== AES_GCM_V2_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError(
      `encryptBlob: suitePayloadOverride must be ${AES_GCM_V2_SUITE_PAYLOAD_LENGTH} bytes`,
    )
  }

  const header = await buildAuthenticatedHeader(
    {
      suite: SUITE.AES_256_GCM_V2,
      fileId,
      chunkSize,
      totalChunks,
      plaintextSize,
      suitePayload,
    },
    contentKey,
  )

  const ctx = await createChunkContext(contentKey, fileId, totalChunks)

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
    suite: SUITE.AES_256_GCM_V2,
    fileId,
    chunkSize,
    totalChunks,
    plaintextSize,
    contentKey,
  }
}

export interface DecryptOptions {
  blob: Blob
  contentKey: Uint8Array
  onProgress?: ProgressCallback
  allowedSuites?: ReadonlyArray<number>
}

/**
 * Decrypt a v2 blob produced by `encryptBlob`.
 */
export async function decryptBlob(options: DecryptOptions): Promise<Blob> {
  const { blob, contentKey, onProgress } = options
  if (!(blob instanceof Blob)) {
    throw new TypeError('decryptBlob: blob must be a Blob or File')
  }
  if (contentKey.length !== 32) {
    throw new RangeError('decryptBlob: contentKey must be 32 bytes')
  }

  const headerProbeBytes = new Uint8Array(
    await blob.slice(0, Math.min(blob.size, 4096)).arrayBuffer(),
  )

  let parsed: ReturnType<typeof parseHeader>
  try {
    parsed = parseHeader(headerProbeBytes)
  } catch (err) {
    if (err instanceof HeaderError && err.code === 'header_too_short') {
      const allHeaderBytes = new Uint8Array(
        await blob
          .slice(0, Math.min(blob.size, 4 + 0xffff + 1024))
          .arrayBuffer(),
      )
      parsed = parseHeader(allHeaderBytes)
    } else {
      throw err
    }
  }

  if (
    options.allowedSuites &&
    !options.allowedSuites.includes(parsed.suite)
  ) {
    throw new HeaderError('suite_not_allowed')
  }

  if (parsed.suite !== SUITE.AES_256_GCM_V2) {
    throw new HeaderError(
      `decryptBlob: this entry point only supports aes-256-gcm-v2; got suite 0x${parsed.suite.toString(16)}`,
    )
  }

  await verifyHeaderMac(parsed, contentKey)

  parseAesGcmV2SuitePayload(parsed.suitePayload)

  const ctx = await createChunkContext(
    contentKey,
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
    const minCipher = 1 + AES_GCM_V2_TAG_BYTES
    const maxCipher = parsed.chunkSize + AES_GCM_V2_TAG_BYTES
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

export async function encryptBytes(
  bytes: Uint8Array | ArrayBuffer,
  options: Omit<EncryptOptions, 'blob'>,
): Promise<EncryptedFile & { contentKey: Uint8Array }> {
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
