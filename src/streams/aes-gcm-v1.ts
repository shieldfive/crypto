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
  buildHeaderUnauthenticated,
  deriveHeaderMacKey,
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
import { concatBytes, readUint32BE, uint32BE } from '../internal/encoding.js'
import { hmacSha256 } from '../internal/hmac.js'
import {
  buildSignatureBlock,
  deriveEd25519PublicKey,
  ED25519_SECRET_KEY_LENGTH,
  parseSignatureBlock,
  SIGNATURE_ALGO_ED25519,
  signHeaderAndMacs,
  type SignatureBlock,
  SignatureError,
  verifyHeaderAndMacs,
} from '../identity/sign.js'

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
  /**
   * Optional 32-byte Ed25519 secret seed. When provided, the stream
   * appends a signature block over `header_unauthenticated_bytes ||
   * concat(chunk_macs)` after the final chunk. When omitted, no block
   * is emitted and the file decrypts as unsigned (legacy behavior).
   */
  ed25519SecretKey?: Uint8Array
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

  const ed25519SecretKey = options.ed25519SecretKey
  if (ed25519SecretKey && ed25519SecretKey.length !== ED25519_SECRET_KEY_LENGTH) {
    throw new RangeError(
      `encrypt stream: ed25519SecretKey must be ${ED25519_SECRET_KEY_LENGTH} bytes`,
    )
  }

  // State held across the lifetime of the stream:
  //   - pending plaintext buffer (collects until we have a full chunk)
  //   - chunk index counter
  //   - bytes consumed counter (for sanity check vs plaintextSize)
  //   - context (lazily initialized)
  //   - unauthenticated header bytes (kept for signing)
  //   - per-chunk MAC tags (last 16 bytes of each chunk ciphertext)
  let pending = new Uint8Array(0)
  let chunkIndex = 0
  let bytesConsumed = 0
  let contextPromise: ReturnType<typeof createChunkContext> | null = null
  let headerEmitted = false
  let unauthenticatedHeader: Uint8Array | null = null
  const chunkMacs: Uint8Array[] = []

  async function ensureHeader(
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (headerEmitted) return
    const unauth = buildHeaderUnauthenticated({
      suite: SUITE.AES_256_GCM_V1,
      fileId,
      chunkSize,
      totalChunks,
      plaintextSize: options.plaintextSize,
      suitePayload,
    })
    const macKey = await deriveHeaderMacKey(contentKey, fileId)
    const mac = await hmacSha256(macKey, unauth)
    unauthenticatedHeader = unauth
    controller.enqueue(concatBytes([unauth, mac]))
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
    if (ed25519SecretKey) {
      // AEAD tag is the trailing AES_GCM_V1_TAG_BYTES of the chunk ct.
      chunkMacs.push(ct.slice(ct.length - AES_GCM_V1_TAG_BYTES))
    }
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
        return
      }
      if (ed25519SecretKey) {
        if (!unauthenticatedHeader) {
          controller.error(
            new Error('encrypt stream: header not finalized before signing'),
          )
          return
        }
        const signature = signHeaderAndMacs({
          ed25519SecretKey,
          header: unauthenticatedHeader,
          chunkMacs,
        })
        const publicKey = deriveEd25519PublicKey(ed25519SecretKey)
        controller.enqueue(
          buildSignatureBlock({
            algorithm: SIGNATURE_ALGO_ED25519,
            publicKey,
            signature,
          }),
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
  /**
   * If provided, a trailing signature block (if present) is verified
   * against this Ed25519 public key, and the resolved metadata's
   * `signature.verified` reflects the outcome. If omitted, a present
   * block is parsed and surfaced but not verified; `verified` is null.
   */
  expectedSignerPublicKey?: Uint8Array
}

/**
 * Verified signature metadata surfaced by the decrypt stream.
 *
 * - `algorithm`, `publicKey`, `signature` come from the parsed block.
 * - `verified` is `true` if the caller passed `expectedSignerPublicKey`
 *   AND it matched the embedded pubkey AND the signature verifies; it
 *   is `false` if the check ran and failed; it is `null` if the caller
 *   passed no `expectedSignerPublicKey` (the application policy layer
 *   is expected to do its own verification using the surfaced bytes).
 */
export interface VerifiedSignature {
  algorithm: number
  publicKey: Uint8Array
  signature: Uint8Array
  verified: boolean | null
}

export interface DecryptionMetadata {
  /** Null when the file has no signature block (legacy / unsigned). */
  signature: VerifiedSignature | null
}

export interface AesGcmV1DecryptStreamResult {
  stream: TransformStream<Uint8Array, Uint8Array>
  /**
   * Resolves once the stream finishes flushing. Rejects if the stream
   * errored — callers awaiting metadata MUST handle rejection (or await
   * the plaintext drain first, which surfaces the same error).
   */
  metadata: Promise<DecryptionMetadata>
}

/**
 * Build a TransformStream that decrypts a v1 ciphertext stream into
 * plaintext. Unlike the whole-blob decryptor, this version processes
 * input incrementally — useful for very large files or when ciphertext
 * arrives chunked over the network.
 *
 * Files written by an older library version (no signature block) decrypt
 * unchanged: `metadata.signature` resolves to `null`. Files with a
 * trailing signature block are parsed; if `expectedSignerPublicKey` is
 * supplied, the signature is verified and `metadata.signature.verified`
 * reflects the outcome.
 */
export function createAesGcmV1DecryptStream(
  options: AesGcmV1DecryptStreamOptions,
): AesGcmV1DecryptStreamResult {
  const { contentKey } = options
  if (contentKey.length !== 32) {
    throw new RangeError('decrypt stream: contentKey must be 32 bytes')
  }
  const expectedSignerPublicKey = options.expectedSignerPublicKey

  let resolveMetadata!: (m: DecryptionMetadata) => void
  let rejectMetadata!: (err: unknown) => void
  const metadata = new Promise<DecryptionMetadata>((resolve, reject) => {
    resolveMetadata = resolve
    rejectMetadata = reject
  })
  // Pre-attach a no-op handler so the user-facing promise doesn't trigger
  // an unhandledRejection if the caller never awaits metadata (they
  // typically await the plaintext drain, which surfaces the same error).
  // This does NOT swallow the error for callers who DO await metadata —
  // .catch() returns a new promise; the original `metadata` still rejects.
  metadata.catch(() => {})

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
  const chunkMacs: Uint8Array[] = []

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
    // AEAD tag is the trailing AES_GCM_V1_TAG_BYTES of ctBytes. Kept
    // for optional signature verification at flush time.
    chunkMacs.push(ctBytes.slice(ctBytes.length - AES_GCM_V1_TAG_BYTES))
    chunkIndex += 1
    return true
  }

  return {
    stream: new TransformStream<Uint8Array, Uint8Array>({
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
          rejectMetadata(err)
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
          const signatureResult = finalizeSignatureMetadata({
            trailingBytes: buffer,
            header: parsedHeader.unauthenticatedBytes,
            chunkMacs,
            expectedSignerPublicKey,
          })
          buffer = new Uint8Array(0)
          resolveMetadata({ signature: signatureResult })
        } catch (err) {
          controller.error(err as Error)
          rejectMetadata(err)
        }
      },
    }),
    metadata,
  }
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
 * transform and return the resulting plaintext ReadableStream alongside
 * a `metadata` Promise that resolves at end-of-stream with the parsed
 * signature block (or `signature: null` for unsigned / legacy files).
 */
export function decryptStreamAesGcmV1(
  source: ReadableStream<Uint8Array>,
  options: AesGcmV1DecryptStreamOptions,
): {
  plaintext: ReadableStream<Uint8Array>
  metadata: Promise<DecryptionMetadata>
} {
  const { stream, metadata } = createAesGcmV1DecryptStream(options)
  return {
    plaintext: source.pipeThrough(stream),
    metadata,
  }
}

/**
 * Parse a trailing signature block (if any) from the decrypt stream's
 * residual buffer, optionally verifying it against the caller's
 * trusted public key.
 *
 * Shared between the AES-GCM and PQ-hybrid stream decoders so the
 * signature semantics live in one place.
 */
export function finalizeSignatureMetadata(input: {
  trailingBytes: Uint8Array
  header: Uint8Array
  chunkMacs: ReadonlyArray<Uint8Array>
  expectedSignerPublicKey: Uint8Array | undefined
}): VerifiedSignature | null {
  if (input.trailingBytes.length === 0) {
    return null
  }
  let parsed: { block: SignatureBlock; consumed: number }
  try {
    parsed = parseSignatureBlock(input.trailingBytes, 0)
  } catch (err) {
    if (err instanceof SignatureError) {
      throw new HeaderError(`signature_block_${err.code}`)
    }
    throw err
  }
  if (parsed.consumed !== input.trailingBytes.length) {
    throw new HeaderError('trailing_bytes_after_signature_block')
  }
  const { algorithm, publicKey, signature } = parsed.block

  let verified: boolean | null = null
  if (input.expectedSignerPublicKey) {
    if (algorithm !== SIGNATURE_ALGO_ED25519) {
      // Unknown / unsupported algorithm: cannot verify with our
      // Ed25519-only verifier; treat as a verification failure under
      // the caller's policy (they asked us to verify, we couldn't).
      verified = false
    } else {
      // Pubkey-pinning: if the embedded pubkey doesn't match the caller's
      // expected one, fail without doing the (still-honest) Ed25519
      // math. This keeps the "verified=true" contract tight: it means
      // the file was signed by the key the caller expected.
      verified =
        bytesEqualConstantTime(publicKey, input.expectedSignerPublicKey) &&
        verifyHeaderAndMacs({
          ed25519PublicKey: input.expectedSignerPublicKey,
          header: input.header,
          chunkMacs: input.chunkMacs,
          signature,
        })
    }
  }
  return { algorithm, publicKey, signature, verified }
}

function bytesEqualConstantTime(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!
  }
  return diff === 0
}
