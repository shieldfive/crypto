/**
 * Streaming encrypt/decrypt for the v1 wire format.
 *
 * The whole-blob APIs in `suites/<name>/api.ts` materialize entire files in
 * memory. That's fine for small files; for multi-gigabyte files on a
 * mobile device it isn't.
 *
 * This module exposes a WHATWG TransformStream factory that ingests
 * plaintext (or ciphertext) chunks from any ReadableStream and emits the
 * other side, without ever holding more than one chunk-plus-header in
 * memory at once.
 *
 * Currently implemented:
 *   - Suite 0x01 (aes-256-gcm-v1) encrypt
 *   - Suite 0x01 (aes-256-gcm-v1) decrypt
 *
 * The XChaCha and PQ-hybrid suites use the same chunk format and AAD;
 * adding them is a copy of the AES module with the suite primitive
 * swapped, but we ship one suite first to lock the streaming contract.
 */

import {
  buildAuthenticatedHeader,
  HeaderError,
  parseHeader,
} from '../format/header.js'
import {
  AES_GCM_V1_SUITE_PAYLOAD_LENGTH,
  AES_GCM_V1_TAG_BYTES,
  createChunkContext,
  decryptChunk,
  encryptChunk,
  generateContentMaterial,
} from '../suites/aes-gcm-v1/index.js'
import {
  DEFAULT_CHUNK_SIZE,
  HEADER_SIZES,
  MAX_TOTAL_CHUNKS,
  SUITE,
} from '../internal/types.js'
import { readUint32BE, uint32BE } from '../internal/encoding.js'

const LENGTH_PREFIX_BYTES = 4

// ─────────────────────────────────────────────────────────────────────
// Encrypting transform
// ─────────────────────────────────────────────────────────────────────

export interface AesGcmV1EncryptStreamOptions {
  /** Total plaintext byte count. Required because the header carries it. */
  plaintextSize: number
  /** Plaintext bytes per chunk. Default 4 MiB. */
  chunkSize?: number
  /** Pre-existing 32-byte content key, or generated if omitted. */
  contentKey?: Uint8Array
  /** Pre-existing 16-byte file_id, or generated if omitted. */
  fileId?: Uint8Array
  /** Optional embedded suite payload (60-byte wrapped key + 12-byte IV). */
  suitePayloadOverride?: Uint8Array
}

export interface AesGcmV1EncryptStreamResult {
  /** TransformStream<Uint8Array, Uint8Array> emitting the v1 wire format. */
  stream: TransformStream<Uint8Array, Uint8Array>
  /** The content key used (for envelope wrapping by the caller). */
  contentKey: Uint8Array
  /** The file_id used (for application-level metadata storage). */
  fileId: Uint8Array
}

/**
 * Build a TransformStream that encrypts plaintext into v1 wire-format
 * ciphertext on the fly. The stream emits the header first, then each
 * chunk as it arrives.
 *
 * The caller MUST pass `plaintextSize` because the header records it.
 * If the caller doesn't know the size up front, they must accumulate
 * the plaintext into a buffer first — there is no way to write a
 * self-describing header otherwise.
 */
export function createAesGcmV1EncryptStream(
  options: AesGcmV1EncryptStreamOptions,
): AesGcmV1EncryptStreamResult {
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new RangeError('encrypt stream: chunkSize must be positive integer')
  }
  if (
    !Number.isSafeInteger(options.plaintextSize) ||
    options.plaintextSize < 0
  ) {
    throw new RangeError('encrypt stream: plaintextSize must be a non-negative integer')
  }

  const totalChunks =
    options.plaintextSize === 0
      ? 0
      : Math.ceil(options.plaintextSize / chunkSize)
  if (totalChunks > MAX_TOTAL_CHUNKS) {
    throw new RangeError('encrypt stream: file would exceed total_chunks limit')
  }

  const generated = generateContentMaterial()
  const contentKey = options.contentKey ?? generated.contentKey
  const fileId = options.fileId ?? generated.fileId
  if (contentKey.length !== 32) {
    throw new RangeError('encrypt stream: contentKey must be 32 bytes')
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('encrypt stream: fileId must be 16 bytes')
  }

  const suitePayload =
    options.suitePayloadOverride ??
    new Uint8Array(AES_GCM_V1_SUITE_PAYLOAD_LENGTH)

  // State held across the lifetime of the stream:
  //   - pending plaintext buffer (collects until we have a full chunk)
  //   - chunk index counter
  //   - bytes consumed counter (for sanity check vs plaintextSize)
  //   - context (lazily initialized)
  let pending = new Uint8Array(0)
  let chunkIndex = 0
  let bytesConsumed = 0
  let contextPromise: ReturnType<typeof createChunkContext> | null = null
  let headerEmitted = false

  async function ensureHeader(
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (headerEmitted) return
    const header = await buildAuthenticatedHeader(
      {
        suite: SUITE.AES_256_GCM_V1,
        fileId,
        chunkSize,
        totalChunks,
        plaintextSize: options.plaintextSize,
        suitePayload,
      },
      contentKey,
    )
    controller.enqueue(header)
    headerEmitted = true
  }

  async function emitChunk(
    plaintext: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (!contextPromise) {
      contextPromise = createChunkContext(contentKey, fileId, totalChunks)
    }
    const ctx = await contextPromise
    const ct = await encryptChunk(ctx, chunkIndex, plaintext)
    controller.enqueue(uint32BE(ct.length))
    controller.enqueue(ct)
    chunkIndex += 1
  }

  const transformer: Transformer<Uint8Array, Uint8Array> = {
    async transform(chunk, controller) {
      await ensureHeader(controller)
      bytesConsumed += chunk.length
      if (bytesConsumed > options.plaintextSize) {
        controller.error(
          new RangeError('encrypt stream: input exceeded declared plaintextSize'),
        )
        return
      }
      // Append to pending buffer
      const merged = new Uint8Array(pending.length + chunk.length)
      merged.set(pending, 0)
      merged.set(chunk, pending.length)
      pending = merged

      // Drain whole chunks
      while (pending.length >= chunkSize && chunkIndex < totalChunks - 1) {
        const slice = pending.subarray(0, chunkSize)
        await emitChunk(slice, controller)
        pending = pending.subarray(chunkSize)
        // Subarray shares the buffer; copy out so we can drop the rest.
        pending = pending.slice(0)
      }
    },
    async flush(controller) {
      await ensureHeader(controller)
      if (bytesConsumed !== options.plaintextSize) {
        controller.error(
          new RangeError(
            `encrypt stream: input was ${bytesConsumed} bytes, declared ${options.plaintextSize}`,
          ),
        )
        return
      }
      // Emit any remaining whole chunks plus the final partial chunk.
      while (chunkIndex < totalChunks) {
        const isLastIteration = chunkIndex === totalChunks - 1
        const sliceSize = isLastIteration
          ? pending.length // final chunk: whatever's left
          : chunkSize
        const slice = pending.subarray(0, sliceSize)
        await emitChunk(slice, controller)
        pending = pending.subarray(sliceSize).slice(0)
      }
      if (pending.length !== 0) {
        controller.error(
          new RangeError('encrypt stream: residual bytes after final chunk'),
        )
      }
    },
  }

  return {
    stream: new TransformStream(transformer),
    contentKey,
    fileId,
  }
}

// ─────────────────────────────────────────────────────────────────────
// Decrypting transform
// ─────────────────────────────────────────────────────────────────────

export interface AesGcmV1DecryptStreamOptions {
  contentKey: Uint8Array
}

/**
 * Build a TransformStream that decrypts a v1 ciphertext stream into
 * plaintext. Unlike the whole-blob decryptor, this version processes
 * input incrementally — useful for very large files or when ciphertext
 * arrives chunked over the network.
 */
export function createAesGcmV1DecryptStream(
  options: AesGcmV1DecryptStreamOptions,
): TransformStream<Uint8Array, Uint8Array> {
  const { contentKey } = options
  if (contentKey.length !== 32) {
    throw new RangeError('decrypt stream: contentKey must be 32 bytes')
  }

  // Phases:
  //   0 = waiting for header bytes
  //   1 = streaming chunks: alternating length-prefix + ciphertext
  let phase: 0 | 1 = 0
  let buffer = new Uint8Array(0)
  let parsedHeader: ReturnType<typeof parseHeader> | null = null
  let chunkIndex = 0
  let bytesEmitted = 0
  let nextCipherLen = -1
  let contextPromise: ReturnType<typeof createChunkContext> | null = null

  function append(input: Uint8Array): void {
    const merged = new Uint8Array(buffer.length + input.length)
    merged.set(buffer, 0)
    merged.set(input, buffer.length)
    buffer = merged
  }

  function consume(n: number): Uint8Array {
    const out = buffer.subarray(0, n).slice(0)
    buffer = buffer.subarray(n).slice(0)
    return out
  }

  async function tryParseHeader(): Promise<boolean> {
    // Need at least the fixed prefix + MAC (no suite_payload).
    if (
      buffer.length <
      HEADER_SIZES.MAGIC +
        HEADER_SIZES.SUITE +
        HEADER_SIZES.FLAGS +
        HEADER_SIZES.FILE_ID +
        HEADER_SIZES.CHUNK_SIZE +
        HEADER_SIZES.TOTAL_CHUNKS +
        HEADER_SIZES.PLAINTEXT_SIZE +
        HEADER_SIZES.SUITE_PAYLOAD_LEN
    ) {
      return false
    }
    // Read suite_payload_len so we know how much more to wait for.
    const suitePayloadLenOffset =
      HEADER_SIZES.MAGIC +
      HEADER_SIZES.SUITE +
      HEADER_SIZES.FLAGS +
      HEADER_SIZES.FILE_ID +
      HEADER_SIZES.CHUNK_SIZE +
      HEADER_SIZES.TOTAL_CHUNKS +
      HEADER_SIZES.PLAINTEXT_SIZE
    const suitePayloadLen =
      (buffer[suitePayloadLenOffset]! << 8) |
      buffer[suitePayloadLenOffset + 1]!
    const fullHeaderLen =
      suitePayloadLenOffset +
      HEADER_SIZES.SUITE_PAYLOAD_LEN +
      suitePayloadLen +
      HEADER_SIZES.HEADER_MAC
    if (buffer.length < fullHeaderLen) return false

    const headerBytes = consume(fullHeaderLen)
    parsedHeader = parseHeader(headerBytes)

    if (parsedHeader.suite !== SUITE.AES_256_GCM_V1) {
      throw new HeaderError(
        `decrypt stream: this stream only supports aes-256-gcm-v1; got suite 0x${parsedHeader.suite.toString(16)}`,
      )
    }
    // Verify header MAC using parseHeader's exposed unauthenticated bytes
    // and mac fields.
    const { verifyHeaderMac } = await import('../format/header.js')
    await verifyHeaderMac(parsedHeader, contentKey)

    contextPromise = createChunkContext(
      contentKey,
      parsedHeader.fileId,
      parsedHeader.totalChunks,
    )

    phase = 1
    return true
  }

  async function tryEmitChunk(
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<boolean> {
    if (!parsedHeader) return false

    if (chunkIndex >= parsedHeader.totalChunks) {
      // Already consumed all expected chunks; anything remaining is trailing
      // garbage and must be flagged at flush time.
      return false
    }

    if (nextCipherLen < 0) {
      if (buffer.length < LENGTH_PREFIX_BYTES) return false
      const lenBytes = consume(LENGTH_PREFIX_BYTES)
      nextCipherLen = readUint32BE(lenBytes)

      const isFinal = chunkIndex === parsedHeader.totalChunks - 1
      const minCipher = 1 + AES_GCM_V1_TAG_BYTES
      const maxCipher = parsedHeader.chunkSize + AES_GCM_V1_TAG_BYTES
      if (nextCipherLen < minCipher || nextCipherLen > maxCipher) {
        throw new HeaderError('chunk_length_out_of_range')
      }
      if (!isFinal && nextCipherLen !== maxCipher) {
        throw new HeaderError('non_final_chunk_wrong_size')
      }
    }

    if (buffer.length < nextCipherLen) return false

    const ctBytes = consume(nextCipherLen)
    nextCipherLen = -1

    const ctx = await contextPromise!
    const pt = await decryptChunk(ctx, chunkIndex, ctBytes)
    bytesEmitted += pt.length
    controller.enqueue(pt)
    chunkIndex += 1
    return true
  }

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      append(chunk)
      try {
        if (phase === 0) {
          const ok = await tryParseHeader()
          if (!ok) return
        }
        // Drain as many chunks as we have data for.
        while (await tryEmitChunk(controller)) {
          /* loop */
        }
      } catch (err) {
        controller.error(err as Error)
      }
    },
    async flush(controller) {
      try {
        if (phase === 0) {
          throw new HeaderError('header_too_short')
        }
        // No header yet means truncated input.
        if (!parsedHeader) {
          throw new HeaderError('header_too_short')
        }
        // Try once more in case flush is called with everything queued.
        while (await tryEmitChunk(controller)) {
          /* loop */
        }
        if (chunkIndex !== parsedHeader.totalChunks) {
          throw new HeaderError('chunk_truncated')
        }
        if (bytesEmitted !== parsedHeader.plaintextSize) {
          throw new HeaderError('plaintext_size_mismatch')
        }
        if (buffer.length !== 0) {
          throw new HeaderError('trailing_bytes_after_last_chunk')
        }
      } catch (err) {
        controller.error(err as Error)
      }
    },
  })
}

// ─────────────────────────────────────────────────────────────────────
// Helpers for ergonomics
// ─────────────────────────────────────────────────────────────────────

/**
 * Pipe a ReadableStream<Uint8Array> through the AES-GCM-v1 encrypt
 * transform and return the resulting ReadableStream + key material.
 */
export function encryptStreamAesGcmV1(
  source: ReadableStream<Uint8Array>,
  options: AesGcmV1EncryptStreamOptions,
): {
  ciphertext: ReadableStream<Uint8Array>
  contentKey: Uint8Array
  fileId: Uint8Array
} {
  const { stream, contentKey, fileId } =
    createAesGcmV1EncryptStream(options)
  return {
    ciphertext: source.pipeThrough(stream),
    contentKey,
    fileId,
  }
}

/**
 * Pipe a ReadableStream<Uint8Array> through the AES-GCM-v1 decrypt
 * transform and return the resulting plaintext ReadableStream.
 */
export function decryptStreamAesGcmV1(
  source: ReadableStream<Uint8Array>,
  options: AesGcmV1DecryptStreamOptions,
): ReadableStream<Uint8Array> {
  return source.pipeThrough(createAesGcmV1DecryptStream(options))
}
