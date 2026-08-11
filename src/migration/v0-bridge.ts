/**
 * Phase 1 migration bridge: v0 (legacy) format encrypt/decrypt.
 *
 * ⚠️  THIS MODULE EXISTS SOLELY FOR THE PHASE 1 SHIELDFIVE MIGRATION ⚠️
 *
 * The on-disk file format here is the legacy "v0" format documented in
 * `spec/format-v0.md` — concatenated AES-256-GCM chunks, no header, no
 * AAD, IV = 4-byte file-prefix || uint64_be(counter), all metadata stored
 * out-of-band in the application database.
 *
 * v0 has documented structural weaknesses (no truncation detection at
 * the AEAD layer, no chunk-index AAD, etc.) that v1 fixes. We expose a
 * v0 *writer* in this bridge module ONLY so that ShieldFive can swap the
 * inline crypto in the main repository for library calls **without**
 * changing the on-disk format in the same release. Once Phase 2 ships
 * (writers default to suite 0x01 / v1), this module is deprecated; once
 * all v0 files have been migrated to v1, this module is deleted.
 *
 * Outside the ShieldFive main-repo migration, callers SHOULD NOT use
 * `legacyV0Writer.encryptV0`. Use one of the v1 suites instead.
 *
 * The decrypt path delegates straight to `suites/aes-gcm-v0/api.ts`
 * (which is the supported, public legacy reader).
 */

import { uint64BE } from '../internal/encoding.js'
import { getSubtle, randomBytes } from '../internal/runtime.js'
import {
  decryptV0,
  decryptV0ToBytes,
  V0_IV_BYTES,
  V0_KEY_BYTES,
  V0_NONCE_PREFIX_BYTES,
  V0_TAG_BYTES,
  type V0DecryptOptions,
} from '../suites/aes-gcm-v0/api.js'

export {
  decryptV0,
  decryptV0ToBytes,
  V0_IV_BYTES,
  V0_KEY_BYTES,
  V0_NONCE_PREFIX_BYTES,
  V0_TAG_BYTES,
  type V0DecryptOptions,
}

// ─────────────────────────────────────────────────────────────────────
// v0 writer (Phase 1 migration only)
// ─────────────────────────────────────────────────────────────────────

export interface V0EncryptOptions {
  /** Plaintext blob. */
  blob: Blob
  /**
   * 32-byte AES-256 content key. Must already be unwrapped.
   *
   * SECURITY: `contentKey` and `noncePrefix` together form this file's
   * AES-GCM nonce namespace. Reusing the same (contentKey, noncePrefix)
   * pair across two DIFFERENT plaintexts reuses every chunk's (key, IV)
   * and is catastrophic — it reproduces the keystream (ct1 ^ ct2 = pt1 ^
   * pt2, enabling plaintext recovery) and leaks the GHASH authentication
   * key (enabling forgery). See the note on `noncePrefix`.
   */
  contentKey: Uint8Array
  /**
   * 4-byte per-file nonce prefix. Generated fresh (random) when omitted —
   * that is the safe default and requires no caller cooperation.
   *
   * SECURITY: if you persist and re-supply a prefix (which the returned
   * {@link V0EncryptResult} explicitly invites you to do), you MUST use a
   * FRESH prefix whenever you re-encrypt an edited file under the same
   * `contentKey`. Re-encrypting different content under an unchanged
   * (contentKey, noncePrefix) pair reuses the AES-GCM nonce and is
   * catastrophic (see `contentKey`). This legacy v0 writer exists solely
   * for the Phase-1 migration; new data must use a v1 suite instead.
   */
  noncePrefix?: Uint8Array
  /** Plaintext bytes per chunk. Production uses 5 MiB or 8 MiB. */
  chunkSize: number
  /** Optional progress callback (0..1). */
  onProgress?: (progress: number) => void
  /**
   * If true, also computes per-chunk SHA-1 hashes for storage-layer
   * integrity checks (matching the production worker's behavior).
   */
  computeChunkHashes?: boolean
}

export interface V0EncryptResult {
  /** Encrypted blob (concatenated chunks, no header). */
  blob: Blob
  /** Number of chunks emitted. */
  totalChunks: number
  /** Plaintext byte count. */
  plaintextSize: number
  /** Nonce prefix used (caller MUST persist this in the database). */
  noncePrefix: Uint8Array
  /** SHA-1 hashes per chunk if requested; otherwise omitted. */
  chunkHashes?: string[]
}

function buildV0Iv(prefix: Uint8Array, counter: number): Uint8Array {
  const iv = new Uint8Array(V0_IV_BYTES)
  iv.set(prefix, 0)
  iv.set(uint64BE(counter), 4)
  return iv
}

async function sha1Hex(bytes: Uint8Array): Promise<string> {
  const subtle = getSubtle()
  const digest = await subtle.digest(
    'SHA-1',
    bytes as Uint8Array<ArrayBuffer>,
  )
  const arr = new Uint8Array(digest)
  let out = ''
  for (let i = 0; i < arr.length; i += 1) {
    out += arr[i]!.toString(16).padStart(2, '0')
  }
  return out
}

/**
 * Encrypt a blob in the legacy v0 format. Drop-in replacement for the
 * inline AES-GCM calls in `public/workers/sf-crypto-worker.js`.
 *
 * **Wire format:** identical to current production. Bit-for-bit
 * compatible.
 *
 * **Key handling:** the caller must bring their own pre-unwrapped 32-byte
 * content key. This module does not wrap or unwrap keys.
 */
export async function encryptV0(
  options: V0EncryptOptions,
): Promise<V0EncryptResult> {
  const { blob, contentKey, chunkSize, onProgress } = options

  if (!(blob instanceof Blob)) {
    throw new TypeError('encryptV0: blob must be a Blob or File')
  }
  if (contentKey.length !== V0_KEY_BYTES) {
    throw new RangeError('encryptV0: contentKey must be 32 bytes')
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new RangeError('encryptV0: chunkSize must be a positive integer')
  }

  const noncePrefix = options.noncePrefix ?? randomBytes(V0_NONCE_PREFIX_BYTES)
  if (noncePrefix.length !== V0_NONCE_PREFIX_BYTES) {
    throw new RangeError('encryptV0: noncePrefix must be 4 bytes')
  }

  const plaintextSize = blob.size
  if (plaintextSize === 0) {
    return {
      blob: new Blob([], { type: 'application/octet-stream' }),
      totalChunks: 0,
      plaintextSize: 0,
      noncePrefix,
      ...(options.computeChunkHashes ? { chunkHashes: [] } : {}),
    }
  }

  const totalChunks = Math.ceil(plaintextSize / chunkSize)

  const subtle = getSubtle()
  const key = await subtle.importKey(
    'raw',
    contentKey as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )

  const parts: BlobPart[] = []
  const chunkHashes: string[] = []

  for (let i = 0; i < totalChunks; i += 1) {
    const start = i * chunkSize
    const end = Math.min(start + chunkSize, plaintextSize)
    const slice = new Uint8Array(await blob.slice(start, end).arrayBuffer())
    const iv = buildV0Iv(noncePrefix, i)

    const ct = new Uint8Array(
      await subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv as Uint8Array<ArrayBuffer>,
          tagLength: 128,
        },
        key,
        slice as Uint8Array<ArrayBuffer>,
      ),
    )

    parts.push(ct as Uint8Array<ArrayBuffer>)
    if (options.computeChunkHashes) {
      chunkHashes.push(await sha1Hex(ct))
    }

    onProgress?.((i + 1) / totalChunks)
  }

  const result: V0EncryptResult = {
    blob: new Blob(parts, { type: 'application/octet-stream' }),
    totalChunks,
    plaintextSize,
    noncePrefix,
  }
  if (options.computeChunkHashes) {
    result.chunkHashes = chunkHashes
  }
  return result
}

/**
 * Web Worker message handler shaped to match the existing production
 * worker contract at `public/workers/sf-crypto-worker.js`. Lets the main
 * repo replace the worker file's body with `installV0WorkerHandler(self)`
 * during Phase 1 of the migration — no API changes for callers.
 *
 * Message shape (matches production):
 *   { type: 'init', mode: 'encrypt' | 'decrypt', key: ArrayBuffer,
 *     noncePrefix: ArrayBuffer, chunkSize: number, blob: Blob }
 *   { type: 'process', index: number }
 *     (also accepted: { type: 'chunk_request', index: number } — alias)
 *   { type: 'clear' }
 *
 * Responses:
 *   { type: 'inited', totalChunks: number }
 *   { type: 'chunk', mode: 'encrypt', index, data: ArrayBuffer, sha1: string }
 *   { type: 'chunk', mode: 'decrypt', index, data: ArrayBuffer }
 *   { type: 'cleared' }
 *   { type: 'error', error: string }
 */
export interface WorkerLike {
  onmessage:
    | ((event: { data: unknown }) => void | Promise<void>)
    | null
  postMessage: (msg: unknown) => void
}

interface V0WorkerState {
  mode: 'encrypt' | 'decrypt'
  key: CryptoKey
  noncePrefix: Uint8Array
  chunkSize: number
  blob: Blob
  totalChunks: number
}

export function installV0WorkerHandler(scope: WorkerLike): void {
  let state: V0WorkerState | null = null

  scope.onmessage = async (event: { data: unknown }) => {
    const msg = (event.data ?? {}) as Record<string, unknown>
    try {
      if (msg.type === 'init') {
        const mode = msg.mode === 'decrypt' ? 'decrypt' : 'encrypt'
        const rawKeyBuf = msg.key as ArrayBuffer | undefined
        const rawPrefixBuf = msg.noncePrefix as ArrayBuffer | undefined
        const blob = msg.blob as Blob | undefined
        const chunkSize = Number(msg.chunkSize ?? 0)

        if (!rawKeyBuf || !rawPrefixBuf || !blob || !chunkSize || chunkSize <= 0) {
          throw new Error('worker_init_invalid')
        }
        const rawKey = new Uint8Array(rawKeyBuf)
        const noncePrefix = new Uint8Array(rawPrefixBuf)
        if (rawKey.length !== V0_KEY_BYTES) {
          throw new Error('worker_init_key_invalid')
        }
        if (noncePrefix.length !== V0_NONCE_PREFIX_BYTES) {
          throw new Error('worker_init_nonce_prefix_invalid')
        }

        const key = await getSubtle().importKey(
          'raw',
          rawKey as Uint8Array<ArrayBuffer>,
          { name: 'AES-GCM' },
          false,
          ['encrypt', 'decrypt'],
        )

        const ctChunkSize = chunkSize + V0_TAG_BYTES
        const totalChunks =
          mode === 'encrypt'
            ? Math.ceil(blob.size / chunkSize)
            : Math.ceil(blob.size / ctChunkSize)

        state = {
          mode,
          key,
          noncePrefix,
          chunkSize,
          blob,
          totalChunks,
        }
        scope.postMessage({ type: 'inited', totalChunks })
        return
      }

      if (msg.type === 'process' || msg.type === 'chunk_request') {
        if (!state) throw new Error('worker_not_inited')
        const index = Number(msg.index ?? -1)
        if (!Number.isInteger(index) || index < 0 || index >= state.totalChunks) {
          throw new Error('worker_chunk_index_invalid')
        }
        const iv = buildV0Iv(state.noncePrefix, index)
        if (state.mode === 'encrypt') {
          const start = index * state.chunkSize
          const end = Math.min(start + state.chunkSize, state.blob.size)
          const slice = new Uint8Array(
            await state.blob.slice(start, end).arrayBuffer(),
          )
          const ciphertext = await getSubtle().encrypt(
            { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer>, tagLength: 128 },
            state.key,
            slice as Uint8Array<ArrayBuffer>,
          )
          const ctBytes = new Uint8Array(ciphertext)
          const sha1 = await sha1Hex(ctBytes)
          scope.postMessage({
            type: 'chunk',
            mode: 'encrypt',
            index,
            data: ciphertext,
            sha1,
          })
        } else {
          const ctChunk = state.chunkSize + V0_TAG_BYTES
          const start = index * ctChunk
          const end = Math.min(start + ctChunk, state.blob.size)
          const slice = new Uint8Array(
            await state.blob.slice(start, end).arrayBuffer(),
          )
          const plaintext = await getSubtle().decrypt(
            { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer>, tagLength: 128 },
            state.key,
            slice as Uint8Array<ArrayBuffer>,
          )
          scope.postMessage({
            type: 'chunk',
            mode: 'decrypt',
            index,
            data: plaintext,
          })
        }
        return
      }

      if (msg.type === 'clear') {
        state = null
        scope.postMessage({ type: 'cleared' })
        return
      }

      throw new Error('worker_unknown_message_type')
    } catch (err) {
      scope.postMessage({
        type: 'error',
        error: (err as Error).message ?? 'unknown_error',
      })
    }
  }
}
