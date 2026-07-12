/**
 * High-level encrypt/decrypt API for the XChaCha20-Poly1305 v1 suite.
 * Mirrors the shape of the AES-GCM v1 API; behavior is identical at the
 * format layer.
 */

import {
  buildAuthenticatedHeader,
  parseHeader,
  verifyHeaderMac,
  HeaderError,
} from '../../format/header.js'
import {
  XCHACHA_V1_SUITE_PAYLOAD_LENGTH,
  XCHACHA_V1_TAG_BYTES,
  createChunkContext,
  decryptChunk,
  encryptChunk,
  generateContentMaterial,
  parseXChaChaV1SuitePayload,
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

export interface XChaChaEncryptOptions {
  blob: Blob
  /**
   * SECURITY: `contentKey` and `fileId` together form a one-use AEAD nonce
   * namespace. Supplying BOTH overrides transfers the uniqueness obligation to
   * the caller — reusing the same (contentKey, fileId) pair across two
   * different plaintexts reuses the AEAD key and nonce and is catastrophic
   * (enables plaintext recovery and authenticated chunk substitution). Never
   * reuse a pair. Omitting both (the default) generates fresh material per file.
   */
  contentKey?: Uint8Array
  /** See the SECURITY note on `contentKey`. */
  fileId?: Uint8Array
  suitePayloadOverride?: Uint8Array
  chunkSize?: number
  onProgress?: ProgressCallback
}

export async function encryptBlob(
  options: XChaChaEncryptOptions,
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
    new Uint8Array(XCHACHA_V1_SUITE_PAYLOAD_LENGTH)
  if (suitePayload.length !== XCHACHA_V1_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError(
      `encryptBlob: suitePayloadOverride must be ${XCHACHA_V1_SUITE_PAYLOAD_LENGTH} bytes`,
    )
  }

  const header = await buildAuthenticatedHeader(
    {
      suite: SUITE.XCHACHA20_POLY1305_V1,
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
    suite: SUITE.XCHACHA20_POLY1305_V1,
    fileId,
    chunkSize,
    totalChunks,
    plaintextSize,
    contentKey,
  }
}

export interface XChaChaDecryptOptions {
  blob: Blob
  contentKey: Uint8Array
  onProgress?: ProgressCallback
  allowedSuites?: ReadonlyArray<number>
}

export async function decryptBlob(
  options: XChaChaDecryptOptions,
): Promise<Blob> {
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

  if (parsed.suite !== SUITE.XCHACHA20_POLY1305_V1) {
    throw new HeaderError(
      `decryptBlob: this entry point only supports xchacha20-poly1305-v1; got suite 0x${parsed.suite.toString(16)}`,
    )
  }

  // MUST verify the header MAC before reading or interpreting any
  // suite_payload bytes — see parseHeader docstring and
  // spec/format-v1.md § "verification order".
  await verifyHeaderMac(parsed, contentKey)
  parseXChaChaV1SuitePayload(parsed.suitePayload)

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
    const minCipher = 1 + XCHACHA_V1_TAG_BYTES
    const maxCipher = parsed.chunkSize + XCHACHA_V1_TAG_BYTES
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
  bytes: Uint8Array,
  options: Omit<XChaChaEncryptOptions, 'blob'>,
): Promise<EncryptedFile & { contentKey: Uint8Array }> {
  const blob = new Blob([asBlobPart(bytes)])
  return encryptBlob({ blob, ...options })
}

export async function decryptToBytes(
  options: XChaChaDecryptOptions,
): Promise<Uint8Array> {
  const blob = await decryptBlob(options)
  return new Uint8Array(await blob.arrayBuffer())
}
