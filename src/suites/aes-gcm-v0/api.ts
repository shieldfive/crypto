/**
 * Cipher suite "0x00" / v0: legacy AES-256-GCM, READ-ONLY.
 *
 * This module decrypts files written by the pre-v1 ShieldFive client.
 * It is intentionally read-only: there is no `encryptV0` exported symbol,
 * and applications MUST NOT write new files in this format.
 *
 * v0 wire format (described in `spec/format-v0.md`):
 *
 *   v0_file := chunk_0 || chunk_1 || ... || chunk_n
 *   chunk_i := AES-GCM(key=content_key, iv=prefix(4)||counter_be(8), aad=∅, pt=plain_i)
 *
 * No on-disk header. The reader must be told the chunk size and nonce
 * prefix out of band (from the application database).
 */

import { uint64BE } from '../../internal/encoding.js'
import { getSubtle } from '../../internal/runtime.js'
import { type ProgressCallback } from '../../internal/types.js'

export const V0_TAG_BYTES = 16
export const V0_IV_BYTES = 12
export const V0_KEY_BYTES = 32
export const V0_NONCE_PREFIX_BYTES = 4

export interface V0DecryptOptions {
  /** Encrypted file bytes (concatenated chunks; no header) */
  blob: Blob
  /** 32-byte AES-256 content key, already unwrapped from the envelope */
  contentKey: Uint8Array
  /** 4-byte per-file random prefix, stored in the database */
  noncePrefix: Uint8Array
  /** Plaintext bytes per chunk (5 MiB or 8 MiB in production) */
  chunkSize: number
  /** Optional progress callback (0..1) */
  onProgress?: ProgressCallback
}

function buildIv(prefix: Uint8Array, counter: number): Uint8Array {
  const iv = new Uint8Array(V0_IV_BYTES)
  iv.set(prefix, 0)
  iv.set(uint64BE(counter), 4)
  return iv
}

/**
 * Decrypt a v0 file. Throws if any chunk fails to authenticate, if the
 * blob size is inconsistent with the chunk size (no clean chunk boundary),
 * or if the inputs have wrong sizes.
 */
export async function decryptV0(options: V0DecryptOptions): Promise<Blob> {
  const { blob, contentKey, noncePrefix, chunkSize, onProgress } = options

  if (!(blob instanceof Blob)) {
    throw new TypeError('decryptV0: blob must be a Blob or File')
  }
  if (contentKey.length !== V0_KEY_BYTES) {
    throw new RangeError('decryptV0: contentKey must be 32 bytes')
  }
  if (noncePrefix.length !== V0_NONCE_PREFIX_BYTES) {
    throw new RangeError('decryptV0: noncePrefix must be 4 bytes')
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new RangeError('decryptV0: chunkSize must be a positive integer')
  }

  // Compute chunk layout from blob size.
  const fullCipherLen = chunkSize + V0_TAG_BYTES
  const totalSize = blob.size

  if (totalSize === 0) {
    return new Blob([], { type: 'application/octet-stream' })
  }

  const fullChunkCount = Math.floor(totalSize / fullCipherLen)
  const trailingBytes = totalSize - fullChunkCount * fullCipherLen

  let totalChunks: number
  if (trailingBytes === 0) {
    totalChunks = fullChunkCount
  } else if (trailingBytes <= V0_TAG_BYTES) {
    throw new Error(
      `decryptV0: trailing bytes (${trailingBytes}) too small for an AEAD tag — file truncated`,
    )
  } else {
    totalChunks = fullChunkCount + 1
  }

  // Import the AES-GCM key once.
  const key = await getSubtle().importKey(
    'raw',
    contentKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )

  const plaintextParts: BlobPart[] = []
  let cursor = 0
  for (let i = 0; i < totalChunks; i += 1) {
    const isFinal = i === totalChunks - 1
    const cipherLen = isFinal && trailingBytes > 0 ? trailingBytes : fullCipherLen
    const cipherBytes = new Uint8Array(
      await blob.slice(cursor, cursor + cipherLen).arrayBuffer(),
    )
    cursor += cipherLen

    const iv = buildIv(noncePrefix, i)
    let pt: ArrayBuffer
    try {
      pt = await getSubtle().decrypt(
        { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer>, tagLength: 128 },
        key,
        cipherBytes as Uint8Array<ArrayBuffer>,
      )
    } catch (err) {
      throw new Error(
        `decryptV0: chunk ${i} failed authentication`,
        { cause: err as Error },
      )
    }
    plaintextParts.push(pt)

    onProgress?.((i + 1) / totalChunks)
  }

  return new Blob(plaintextParts, { type: 'application/octet-stream' })
}

/**
 * Convenience wrapper that returns plaintext bytes directly.
 */
export async function decryptV0ToBytes(
  options: V0DecryptOptions,
): Promise<Uint8Array> {
  const blob = await decryptV0(options)
  return new Uint8Array(await blob.arrayBuffer())
}

/**
 * Detect whether a blob is v0 (legacy) by checking the absence of the v1
 * magic prefix. Use only when out-of-band metadata is unavailable. For
 * normal application use, the database flag `cipher_version` is canonical.
 */
export async function looksLikeV0(blob: Blob): Promise<boolean> {
  if (blob.size < 5) return true // too small to be v1
  const head = new Uint8Array(await blob.slice(0, 5).arrayBuffer())
  // v1 magic is "SF5\x01\x00" = 0x53 0x46 0x35 0x01 0x00
  return !(
    head[0] === 0x53 &&
    head[1] === 0x46 &&
    head[2] === 0x35 &&
    head[3] === 0x01 &&
    head[4] === 0x00
  )
}
