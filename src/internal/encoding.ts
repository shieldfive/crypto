/**
 * Cast helper: TypeScript 5.7+ distinguishes Uint8Array<ArrayBuffer> from
 * Uint8Array<ArrayBufferLike>. Blob and many Web Crypto APIs require the
 * narrower variant. This helper centralizes the cast so we don't sprinkle
 * `as Uint8Array<ArrayBuffer>` across the codebase.
 *
 * Functionally a no-op at runtime; purely a type annotation.
 */
export function asBlobPart(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>
}

/**
 * Byte-level encoding helpers.
 *
 * All multi-byte integer functions are explicitly big-endian to match the
 * v1 wire format. Callers should prefer these over hand-rolled bit-shifting.
 */

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let binary = ''
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]!)
    }
    return btoa(binary)
  }
  // Node fallback. Uses Buffer; safe in any Node version.
  return Buffer.from(bytes).toString('base64')
}

export function base64ToBytes(value: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new TypeError('base64ToBytes: input must be a string')
  }
  if (typeof atob === 'function') {
    const binary = atob(value)
    const out = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i)
    }
    return out
  }
  return new Uint8Array(Buffer.from(value, 'base64'))
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i]!.toString(16).padStart(2, '0')
  }
  return out
}

const HEX_RE = /^[0-9a-f]*$/i

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: input must be a string')
  }
  if (hex.length % 2 !== 0 || !HEX_RE.test(hex)) {
    throw new TypeError('hexToBytes: input must be even-length hexadecimal')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0
  for (const part of parts) total += part.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function uint32BE(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError('uint32BE: value out of range')
  }
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value, false)
  return out
}

export function readUint32BE(bytes: Uint8Array, offset = 0): number {
  if (offset + 4 > bytes.length) {
    throw new RangeError('readUint32BE: insufficient bytes')
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(
    0,
    false,
  )
}

export function uint16BE(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError('uint16BE: value out of range')
  }
  const out = new Uint8Array(2)
  new DataView(out.buffer).setUint16(0, value, false)
  return out
}

export function readUint16BE(bytes: Uint8Array, offset = 0): number {
  if (offset + 2 > bytes.length) {
    throw new RangeError('readUint16BE: insufficient bytes')
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 2).getUint16(
    0,
    false,
  )
}

/**
 * Encode a non-negative integer as 8 big-endian bytes. The library never
 * emits values exceeding Number.MAX_SAFE_INTEGER (2^53 - 1) because the
 * format spec caps total_chunks at 1e9 and plaintext_size is bounded by
 * what JavaScript can sensibly handle.
 */
export function uint64BE(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError('uint64BE: value must be a non-negative safe integer')
  }
  const out = new Uint8Array(8)
  // Top 4 bytes: high uint32 (value / 2^32, truncated)
  const high = Math.floor(value / 0x1_0000_0000)
  const low = value >>> 0
  new DataView(out.buffer).setUint32(0, high, false)
  new DataView(out.buffer).setUint32(4, low, false)
  return out
}

export function readUint64BE(bytes: Uint8Array, offset = 0): number {
  if (offset + 8 > bytes.length) {
    throw new RangeError('readUint64BE: insufficient bytes')
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8)
  const high = view.getUint32(0, false)
  const low = view.getUint32(4, false)
  // Reject values that don't fit in a safe JS integer (> 2^53 - 1).
  if (high > 0x1f_ffff) {
    throw new RangeError('readUint64BE: value exceeds Number.MAX_SAFE_INTEGER')
  }
  return high * 0x1_0000_0000 + low
}
