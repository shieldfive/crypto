/**
 * HKDF-SHA-256 wrapper.
 *
 * Every domain-separated key the library derives from another key flows
 * through this function. Domain strings are constants in `internal/types.ts`
 * — never construct an `info` parameter ad-hoc at the call site.
 */

import { getSubtle } from './runtime.js'

const TEXT_ENCODER = new TextEncoder()

export async function hkdfSha256(options: {
  ikm: Uint8Array
  salt?: Uint8Array
  info: string
  length: number
}): Promise<Uint8Array> {
  const { ikm, info, length } = options
  const salt = options.salt ?? new Uint8Array(32) // SHA-256 zero-salt fallback
  if (!Number.isSafeInteger(length) || length <= 0 || length > 8160) {
    // 8160 = 255 * 32, the HKDF-SHA-256 output bound.
    throw new RangeError('hkdfSha256: length out of range (1..8160)')
  }

  const subtle = getSubtle()
  const baseKey = await subtle.importKey(
    'raw',
    ikm as Uint8Array<ArrayBuffer>,
    'HKDF',
    false,
    ['deriveBits'],
  )

  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as Uint8Array<ArrayBuffer>,
      info: TEXT_ENCODER.encode(info) as Uint8Array<ArrayBuffer>,
    },
    baseKey,
    length * 8,
  )

  return new Uint8Array(bits)
}
