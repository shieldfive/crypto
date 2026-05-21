/**
 * Sender-attribution signatures over the v1 wire format.
 *
 * The v1 file format already authenticates with HMAC under the content
 * key (`header_mac`) and per-chunk AEAD tags, so a recipient can be sure
 * the file decrypts to bytes the encryptor produced. What it does NOT
 * tell them is WHO encrypted it — anyone with the content key could have
 * written the file.
 *
 * This module adds an optional detached signature over
 * `header_unauthenticated_bytes || concat(per-chunk MAC tags)` so that a
 * recipient who trusts a sender's public key can verify authorship. The
 * signature lives in an optional trailing structure (see
 * `spec/format-v1.md § "Signature block"`); legacy files without that
 * structure continue to decrypt unchanged, with the receiving side
 * reporting `signature: null`.
 *
 * Algorithm 0x01 (Ed25519) is the only algorithm defined in v1. 0x02 is
 * reserved for ML-DSA-65; the format leaves room for it but does not yet
 * implement it.
 */

import { ed25519 } from '@noble/curves/ed25519.js'

import {
  concatBytes,
  readUint16BE,
  uint16BE,
} from '../internal/encoding.js'

/** Signature algorithm: Ed25519 (RFC 8032). 32-byte key, 64-byte signature. */
export const SIGNATURE_ALGO_ED25519 = 0x01

/** Signature algorithm reserved for ML-DSA-65 (FIPS 204). Not yet implemented. */
export const SIGNATURE_ALGO_ML_DSA_65 = 0x02

export const ED25519_PUBLIC_KEY_LENGTH = 32
export const ED25519_SECRET_KEY_LENGTH = 32
export const ED25519_SIGNATURE_LENGTH = 64

export interface SignatureBlock {
  /** Algorithm identifier; see `SIGNATURE_ALGO_*`. */
  algorithm: number
  /** Sender's verifying key. Length depends on the algorithm. */
  publicKey: Uint8Array
  /** Detached signature over `signed_message`. */
  signature: Uint8Array
}

export class SignatureError extends Error {
  readonly code: string
  constructor(code: string) {
    super(`shieldfive-crypto: signature error: ${code}`)
    this.name = 'SignatureError'
    this.code = code
  }
}

function buildSignedMessage(
  header: Uint8Array,
  chunkMacs: ReadonlyArray<Uint8Array>,
): Uint8Array {
  let totalMacLen = 0
  for (const mac of chunkMacs) totalMacLen += mac.length
  const out = new Uint8Array(header.length + totalMacLen)
  out.set(header, 0)
  let offset = header.length
  for (const mac of chunkMacs) {
    out.set(mac, offset)
    offset += mac.length
  }
  return out
}

/**
 * Produce a detached Ed25519 signature over
 * `header_unauthenticated_bytes || concat(chunk_macs)`.
 *
 * `header` MUST be the exact bytes covered by the file's `header_mac`
 * (i.e. the output of `buildHeaderUnauthenticated` or
 * `parseHeader().unauthenticatedBytes`). `chunkMacs` MUST be the per-chunk
 * AEAD tags in chunk-index order. For suites defined in v1 (AES-GCM-128,
 * ChaCha20-Poly1305) the tag is the trailing 16 bytes of the chunk's
 * ciphertext field.
 *
 * Returns the raw 64-byte signature. Callers wrap it in a signature block
 * via `buildSignatureBlock`.
 */
export function signHeaderAndMacs(input: {
  ed25519SecretKey: Uint8Array
  header: Uint8Array
  chunkMacs: ReadonlyArray<Uint8Array>
}): Uint8Array {
  if (input.ed25519SecretKey.length !== ED25519_SECRET_KEY_LENGTH) {
    throw new SignatureError('ed25519_secret_key_wrong_length')
  }
  const message = buildSignedMessage(input.header, input.chunkMacs)
  return ed25519.sign(message, input.ed25519SecretKey)
}

/**
 * Verify a detached Ed25519 signature produced by `signHeaderAndMacs`.
 * Returns `true` on success, `false` on any failure (wrong length,
 * malformed point, bad signature). Never throws on a verification
 * mismatch — failures are not exceptional.
 */
export function verifyHeaderAndMacs(input: {
  ed25519PublicKey: Uint8Array
  header: Uint8Array
  chunkMacs: ReadonlyArray<Uint8Array>
  signature: Uint8Array
}): boolean {
  if (input.ed25519PublicKey.length !== ED25519_PUBLIC_KEY_LENGTH) return false
  if (input.signature.length !== ED25519_SIGNATURE_LENGTH) return false
  const message = buildSignedMessage(input.header, input.chunkMacs)
  try {
    return ed25519.verify(input.signature, message, input.ed25519PublicKey)
  } catch {
    // Malformed pubkey or sig encoding — noble throws; we treat as not-verified.
    return false
  }
}

/**
 * Derive the Ed25519 public key from a 32-byte secret seed.
 */
export function deriveEd25519PublicKey(
  ed25519SecretKey: Uint8Array,
): Uint8Array {
  if (ed25519SecretKey.length !== ED25519_SECRET_KEY_LENGTH) {
    throw new SignatureError('ed25519_secret_key_wrong_length')
  }
  return ed25519.getPublicKey(ed25519SecretKey)
}

/**
 * Serialize a signature block:
 *   1 byte algorithm || 2 bytes BE pubkey_len || pubkey || 2 bytes BE sig_len || sig
 */
export function buildSignatureBlock(block: SignatureBlock): Uint8Array {
  if (
    block.algorithm < 0 ||
    block.algorithm > 0xff ||
    !Number.isInteger(block.algorithm)
  ) {
    throw new SignatureError('algorithm_out_of_range')
  }
  if (block.algorithm === 0x00) {
    throw new SignatureError('algorithm_reserved')
  }
  if (block.publicKey.length > 0xffff) {
    throw new SignatureError('public_key_too_large')
  }
  if (block.signature.length > 0xffff) {
    throw new SignatureError('signature_too_large')
  }
  if (block.algorithm === SIGNATURE_ALGO_ED25519) {
    if (block.publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
      throw new SignatureError('ed25519_public_key_wrong_length')
    }
    if (block.signature.length !== ED25519_SIGNATURE_LENGTH) {
      throw new SignatureError('ed25519_signature_wrong_length')
    }
  }
  return concatBytes([
    new Uint8Array([block.algorithm]),
    uint16BE(block.publicKey.length),
    block.publicKey,
    uint16BE(block.signature.length),
    block.signature,
  ])
}

/**
 * Parse a signature block starting at `offset` in `bytes`. Returns the
 * parsed block and the number of bytes consumed. Throws on malformed
 * input (truncation, oversize, or — for known algorithms — wrong key /
 * signature length). Unknown algorithms parse successfully; verification
 * against an unknown algorithm is the caller's policy decision.
 */
export function parseSignatureBlock(
  bytes: Uint8Array,
  offset = 0,
): { block: SignatureBlock; consumed: number } {
  const FIXED_HEADER = 1 + 2 // algorithm + pubkey_len
  if (bytes.length - offset < FIXED_HEADER) {
    throw new SignatureError('block_truncated')
  }
  let pos = offset
  const algorithm = bytes[pos]!
  pos += 1
  if (algorithm === 0x00) {
    throw new SignatureError('algorithm_reserved')
  }
  const pubkeyLen = readUint16BE(bytes, pos)
  pos += 2
  if (bytes.length - pos < pubkeyLen + 2) {
    throw new SignatureError('block_truncated')
  }
  const publicKey = bytes.slice(pos, pos + pubkeyLen)
  pos += pubkeyLen
  const sigLen = readUint16BE(bytes, pos)
  pos += 2
  if (bytes.length - pos < sigLen) {
    throw new SignatureError('block_truncated')
  }
  const signature = bytes.slice(pos, pos + sigLen)
  pos += sigLen
  if (algorithm === SIGNATURE_ALGO_ED25519) {
    if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
      throw new SignatureError('ed25519_public_key_wrong_length')
    }
    if (signature.length !== ED25519_SIGNATURE_LENGTH) {
      throw new SignatureError('ed25519_signature_wrong_length')
    }
  }
  return {
    block: { algorithm, publicKey, signature },
    consumed: pos - offset,
  }
}
