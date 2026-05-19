/**
 * Streaming encrypt/decrypt for the v1 wire format under suite 0x03
 * (PQ-hybrid XChaCha20-Poly1305 + ML-KEM-1024).
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
 *   - Suite 0x03 (pq-hybrid-xchacha-mlkem1024-v1) encrypt
 *   - Suite 0x03 (pq-hybrid-xchacha-mlkem1024-v1) decrypt
 *
 * Differences from the AES-GCM-v1 streaming module: the encrypt factory
 * requires the caller to pre-run `encapsulateForRecipient` and pass the
 * resulting `{combinedKey, suitePayload, fileId}` — the PQ suite cannot
 * fabricate its own content material the way AES can, because it depends
 * on the recipient's ML-KEM public key. The async helper
 * `encryptStreamPqHybridV1` bundles encapsulation + stream construction.
 * On the decrypt side, the stream itself performs PQ decapsulation as
 * soon as the header has been parsed, then proceeds identically to the
 * AES path.
 */

import {
  buildAuthenticatedHeader,
  HeaderError,
  parseHeader,
} from '../format/header.js'
import {
  PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH,
  PQ_HYBRID_V1_TAG_BYTES,
  createChunkContext,
  decapsulateFromHeader,
  decryptChunk,
  encapsulateForRecipient,
  encryptChunk,
} from '../suites/pq-hybrid-v1/index.js'
import {
  DEFAULT_CHUNK_SIZE,
  HEADER_SIZES,
  MAX_TOTAL_CHUNKS,
  SUITE,
} from '../internal/types.js'
import { readUint32BE, uint32BE } from '../internal/encoding.js'
import { randomBytes } from '../internal/runtime.js'

const LENGTH_PREFIX_BYTES = 4

// ─────────────────────────────────────────────────────────────────────
// Encrypting transform
// ─────────────────────────────────────────────────────────────────────

export interface PqHybridV1EncryptStreamOptions {
  /** Total plaintext byte count. Required because the header carries it. */
  plaintextSize: number
  /** Plaintext bytes per chunk. Default 4 MiB. */
  chunkSize?: number
  /**
   * Combined content key from `encapsulateForRecipient`. 32 bytes. Used
   * both for header MAC and for chunk AEAD.
   *
   * SECURITY: Possession of `combinedKey` grants permanent decryption
   * capability for any file whose header was produced with it. Treat
   * as cryptographic secret material: hold only in memory for the
   * duration of the operation, do not persist to disk or storage, do
   * not log, do not transmit. The only safe way to reproduce it on
   * another machine is to re-encapsulate via the recipient's ML-KEM
   * public key.
   */
  combinedKey: Uint8Array
  /** 16-byte file_id used as HKDF salt in encapsulation and key derivation. */
  fileId: Uint8Array
  /**
   * Suite payload produced by `encapsulateForRecipient` (1664 bytes —
   * 1568-byte ML-KEM ciphertext + 72-byte wrapped classical share + 24-byte
   * classical nonce).
   */
  suitePayload: Uint8Array
}

export interface PqHybridV1EncryptStreamResult {
  /** TransformStream<Uint8Array, Uint8Array> emitting the v1 wire format. */
  stream: TransformStream<Uint8Array, Uint8Array>
  /**
   * SECURITY: Possession of `combinedKey` grants permanent decryption
   * capability for any file whose header was produced with it. Treat
   * as cryptographic secret material: hold only in memory for the
   * duration of the operation, do not persist to disk or storage, do
   * not log, do not transmit. The only safe way to reproduce it on
   * another machine is to re-encapsulate via the recipient's ML-KEM
   * public key.
   *
   * Echoed back for caller convenience.
   */
  combinedKey: Uint8Array
  /** The file_id used (echoed back for caller convenience). */
  fileId: Uint8Array
}

/**
 * Build a TransformStream that encrypts plaintext into v1 wire-format
 * ciphertext on the fly under suite 0x03. The stream emits the header
 * first, then each chunk as it arrives.
 *
 * The caller MUST pass `plaintextSize` because the header records it.
 * If the caller doesn't know the size up front, they must accumulate
 * the plaintext into a buffer first — there is no way to write a
 * self-describing header otherwise.
 *
 * Unlike the AES-GCM-v1 factory, the PQ-hybrid factory cannot manufacture
 * its own key material — the combined key, file_id, and suite payload
 * are all outputs of `encapsulateForRecipient`. Use the
 * `encryptStreamPqHybridV1` helper when you'd rather pass a recipient
 * public key directly.
 */
export function createPqHybridV1EncryptStream(
  options: PqHybridV1EncryptStreamOptions,
): PqHybridV1EncryptStreamResult {
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

  const { combinedKey, fileId, suitePayload } = options
  if (combinedKey.length !== 32) {
    throw new RangeError('encrypt stream: combinedKey must be 32 bytes')
  }
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('encrypt stream: fileId must be 16 bytes')
  }
  if (suitePayload.length !== PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH) {
    throw new RangeError(
      `encrypt stream: suitePayload must be ${PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH} bytes`,
    )
  }

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
        suite: SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1,
        fileId,
        chunkSize,
        totalChunks,
        plaintextSize: options.plaintextSize,
        suitePayload,
      },
      combinedKey,
    )
    controller.enqueue(header)
    headerEmitted = true
  }

  async function emitChunk(
    plaintext: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (!contextPromise) {
      contextPromise = createChunkContext(combinedKey, fileId, totalChunks)
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
    combinedKey,
    fileId,
  }
}

// ─────────────────────────────────────────────────────────────────────
// Decrypting transform
// ─────────────────────────────────────────────────────────────────────

/**
 * Inputs for {@link createPqHybridV1DecryptStream}. Either provide the
 * KEM material (`recipientSecretKey` + `envelopeKey`) so the stream can
 * derive the combined key itself, OR provide the already-derived
 * `combinedKey` directly. The latter is what share-link recipients use:
 * they hold a 32-byte K (wrapped under the share-link password) and
 * never see the ML-KEM secret key.
 *
 * Mixing both modes is not supported — `combinedKey` always wins. The
 * caller is responsible for picking one path.
 */
export type PqHybridV1DecryptStreamOptions =
  | {
      /** Recipient's ML-KEM-1024 secret key (3168 bytes). */
      recipientSecretKey: Uint8Array
      /** Classical envelope key (32 bytes). */
      envelopeKey: Uint8Array
      combinedKey?: undefined
    }
  | {
      /**
       * Pre-derived 32-byte combined key K. When provided, the stream
       * skips ML-KEM decapsulation entirely and uses K for header MAC
       * verification + per-chunk AEAD. Header MAC validation still
       * cryptographically gates the rest of the stream, so a wrong K
       * fails fast.
       */
      combinedKey: Uint8Array
      recipientSecretKey?: undefined
      envelopeKey?: undefined
    }

/**
 * Build a TransformStream that decrypts a v1 ciphertext stream produced
 * under suite 0x03 into plaintext. Unlike the whole-blob decryptor, this
 * version processes input incrementally — useful for very large files or
 * when ciphertext arrives chunked over the network.
 *
 * Two key-input modes:
 *   - KEM mode (`recipientSecretKey` + `envelopeKey`): the stream runs
 *     ML-KEM decapsulation once, the moment the header has been
 *     buffered, then proceeds identically to the AES-GCM-v1 decrypt
 *     stream.
 *   - Combined-key mode (`combinedKey`): skips decapsulation entirely
 *     and uses the supplied K for header MAC verification + chunk AEAD.
 *     Intended for share-link recipients who hold a wrapped K but no
 *     ML-KEM secret.
 */
export function createPqHybridV1DecryptStream(
  options: PqHybridV1DecryptStreamOptions,
): TransformStream<Uint8Array, Uint8Array> {
  const combinedKeyOverride = options.combinedKey
  const recipientSecretKey = options.recipientSecretKey
  const envelopeKey = options.envelopeKey

  if (combinedKeyOverride) {
    if (combinedKeyOverride.length !== 32) {
      throw new RangeError('decrypt stream: combinedKey must be 32 bytes')
    }
  } else {
    if (!recipientSecretKey || !envelopeKey) {
      throw new RangeError(
        'decrypt stream: provide either combinedKey or recipientSecretKey + envelopeKey',
      )
    }
    if (envelopeKey.length !== 32) {
      throw new RangeError('decrypt stream: envelopeKey must be 32 bytes')
    }
    // Length of recipientSecretKey is checked inside decapsulateFromHeader.
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

    if (parsedHeader.suite !== SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1) {
      throw new HeaderError(
        `decrypt stream: this stream only supports pq-hybrid-xchacha-mlkem1024-v1; got suite 0x${parsedHeader.suite.toString(16)}`,
      )
    }

    // Recover the combined key. Two paths:
    //   - KEM mode: run ML-KEM decapsulation now.
    //   - Combined-key mode: trust the supplied K. The header MAC check
    //     below still cryptographically gates the rest of the stream, so
    //     a wrong K fails fast.
    let combinedKey: Uint8Array
    if (combinedKeyOverride) {
      combinedKey = combinedKeyOverride
    } else {
      ;({ combinedKey } = await decapsulateFromHeader({
        suitePayload: parsedHeader.suitePayload,
        recipientSecretKey: recipientSecretKey!,
        envelopeKey: envelopeKey!,
        fileId: parsedHeader.fileId,
      }))
    }

    const { verifyHeaderMac } = await import('../format/header.js')
    await verifyHeaderMac(parsedHeader, combinedKey)

    contextPromise = createChunkContext(
      combinedKey,
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
      const minCipher = 1 + PQ_HYBRID_V1_TAG_BYTES
      const maxCipher = parsedHeader.chunkSize + PQ_HYBRID_V1_TAG_BYTES
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

export interface EncryptStreamPqHybridV1Options {
  /** Recipient's ML-KEM-1024 public key (1568 bytes) */
  recipientPublicKey: Uint8Array
  /** Classical envelope key (32 bytes) */
  envelopeKey: Uint8Array
  /** Total plaintext byte count. Required because the header carries it. */
  plaintextSize: number
  /** Plaintext bytes per chunk. Default 4 MiB. */
  chunkSize?: number
  /** Pre-existing 16-byte file_id, or generated if omitted. */
  fileId?: Uint8Array
}

/**
 * Pipe a ReadableStream<Uint8Array> through the PQ-hybrid-v1 encrypt
 * transform and return the resulting ReadableStream + the materials the
 * caller will need to store alongside the file (file_id) or share back
 * to the sender's records (combined key, suite payload).
 *
 * This helper is async because PQ encapsulation requires libsodium init.
 */
export async function encryptStreamPqHybridV1(
  source: ReadableStream<Uint8Array>,
  options: EncryptStreamPqHybridV1Options,
): Promise<{
  ciphertext: ReadableStream<Uint8Array>
  combinedKey: Uint8Array
  fileId: Uint8Array
  suitePayload: Uint8Array
}> {
  const { recipientPublicKey, envelopeKey } = options
  const fileId = options.fileId ?? randomBytes(HEADER_SIZES.FILE_ID)
  if (fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new RangeError('encryptStreamPqHybridV1: fileId must be 16 bytes')
  }

  const { suitePayload, combinedKey } = await encapsulateForRecipient({
    recipientPublicKey,
    envelopeKey,
    fileId,
  })

  const streamOptions: PqHybridV1EncryptStreamOptions = {
    plaintextSize: options.plaintextSize,
    combinedKey,
    fileId,
    suitePayload,
  }
  if (options.chunkSize !== undefined) {
    streamOptions.chunkSize = options.chunkSize
  }
  const { stream } = createPqHybridV1EncryptStream(streamOptions)

  return {
    ciphertext: source.pipeThrough(stream),
    combinedKey,
    fileId,
    suitePayload,
  }
}

/**
 * Pipe a ReadableStream<Uint8Array> through the PQ-hybrid-v1 decrypt
 * transform and return the resulting plaintext ReadableStream. See
 * {@link PqHybridV1DecryptStreamOptions} for the two key-input modes
 * (KEM secret + envelope vs. pre-derived combined key K).
 */
export function decryptStreamPqHybridV1(
  source: ReadableStream<Uint8Array>,
  options: PqHybridV1DecryptStreamOptions,
): ReadableStream<Uint8Array> {
  return source.pipeThrough(createPqHybridV1DecryptStream(options))
}
