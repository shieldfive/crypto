/**
 * Runtime detection and validation for the host environment.
 *
 * This module is intentionally tiny. The library targets any environment
 * exposing the WHATWG Web Crypto API at `globalThis.crypto.subtle` —
 * modern browsers, Node 20+, Deno, Bun, Cloudflare Workers, and any
 * compatible WebAssembly runtime.
 *
 * Suites that require additional primitives (Argon2id, ML-KEM,
 * XChaCha20-Poly1305) load those primitives lazily from
 * `libsodium-wrappers-sumo` and `@noble/post-quantum`. Consumers that
 * only use the AES-GCM suite never load those WASM blobs.
 */

import type { Crypto, SubtleCrypto } from './types.js'

let cachedCrypto: Crypto | null = null

export function getCrypto(): Crypto {
  if (cachedCrypto) return cachedCrypto

  const candidate = (globalThis as { crypto?: Crypto }).crypto
  if (
    !candidate ||
    !candidate.subtle ||
    typeof candidate.getRandomValues !== 'function'
  ) {
    throw new Error(
      'shieldfive-crypto: Web Crypto API is not available. ' +
        'This library requires globalThis.crypto with SubtleCrypto support. ' +
        'In Node, use Node 20 or later.',
    )
  }

  cachedCrypto = candidate
  return candidate
}

export function getSubtle(): SubtleCrypto {
  return getCrypto().subtle
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new RangeError('randomBytes: length must be a positive integer')
  }
  if (length > 65536) {
    // Web Crypto specification limits getRandomValues to 65536 bytes per call.
    throw new RangeError('randomBytes: length exceeds 65536')
  }
  const out = new Uint8Array(length)
  getCrypto().getRandomValues(out)
  return out
}

/**
 * Constant-time equality for byte arrays. Used wherever a comparison failure
 * could leak timing information (MAC verification, key comparison).
 */
export function constantTimeEqual(
  a: Uint8Array | null | undefined,
  b: Uint8Array | null | undefined,
): boolean {
  if (!a || !b) return false
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!
  }
  return diff === 0
}

/**
 * Best-effort zeroization of secret material. JavaScript engines may have
 * already copied or reallocated the underlying buffer; this is a hint, not
 * a guarantee. Use only for in-process hardening.
 */
export function zeroize(buffer: Uint8Array): void {
  buffer.fill(0)
}
