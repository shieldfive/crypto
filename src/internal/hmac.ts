/**
 * HMAC-SHA-256 wrapper.
 *
 * Used for the file-format header MAC and for any application-level
 * authenticator the library exposes. Always verify with constantTimeEqual.
 */

import { constantTimeEqual, getSubtle } from './runtime.js'

export async function hmacSha256(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const subtle = getSubtle()
  const hmacKey = await subtle.importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await subtle.sign('HMAC', hmacKey, data as Uint8Array<ArrayBuffer>)
  return new Uint8Array(sig)
}

export async function hmacSha256Verify(
  key: Uint8Array,
  data: Uint8Array,
  expected: Uint8Array,
): Promise<boolean> {
  const computed = await hmacSha256(key, data)
  return constantTimeEqual(computed, expected)
}
