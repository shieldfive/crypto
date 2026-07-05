/**
 * Sender-attribution signatures over the v1 wire format.
 *
 * The v1 file format already authenticates with HMAC under the content
 * key (`header_mac`) and per-chunk AEAD tags, so a recipient can be sure
 * the file decrypts to bytes *some* content-key holder produced. What it
 * does NOT tell them is WHO produced it — anyone with the content key
 * could have written the file.
 *
 * This module adds an optional detached Ed25519 signature so that a
 * recipient who trusts a sender's public key can verify authorship. The
 * signed message is a domain-separated, length-framed SHA-256 transcript
 * that commits to the header AND every chunk's full ciphertext (body +
 * AEAD tag) — see {@link SenderSigTranscript}.
 *
 * It deliberately does NOT sign the AEAD tags alone. An AEAD tag (GHASH
 * for AES-GCM, Poly1305 for the PQ suite) is a keyed polynomial MAC that
 * a *content-key holder* can forge: knowing the key, they can rewrite
 * chunk ciphertext while holding the 16-byte tag byte-identical. Since
 * the entire point of attribution is to bind content against exactly such
 * a holder (an outsider without the content key cannot decrypt at all),
 * the signature must commit to the ciphertext bytes themselves, not to a
 * value the holder can keep fixed under a chosen-plaintext change. The
 * transcript is hashed incrementally, so signing/verifying stays O(1) in
 * memory for multi-gigabyte streams.
 *
 * The signature lives in an optional trailing structure (see
 * `spec/format-v1.md § "Signature block"`); legacy files without that
 * structure continue to decrypt unchanged, with the receiving side
 * reporting `signature: null`.
 *
 * Algorithm 0x01 (Ed25519) is the only algorithm defined in v1. 0x02 is
 * reserved for ML-DSA-65; the format leaves room for it but does not yet
 * implement it.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'

import {
  concatBytes,
  readUint16BE,
  uint16BE,
  uint64BE,
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

/**
 * Domain separator for the sender-attribution signature transcript.
 *
 * Frozen wire constant: these exact bytes are hashed into every
 * signature. Changing them changes every signature and invalidates
 * verification of any previously signed file. Do not edit.
 */
const SENDER_SIG_DOMAIN = new TextEncoder().encode(
  'shieldfive/crypto/v1/sender-sig',
)

/**
 * Incremental transcript for the sender-attribution signature.
 *
 * The signed message commits to the file header (exactly the bytes under
 * `header_mac`) and to EVERY chunk's full ciphertext field (body + AEAD
 * tag), each length-framed and preceded by a domain separator:
 *
 * ```
 * digest = SHA-256(
 *     SENDER_SIG_DOMAIN
 *  || u64be(len(header)) || header
 *  || u64be(total_chunks)
 *  || for each chunk i in order: u64be(i) || u64be(len(ct_i)) || ct_i
 * )
 * ```
 *
 * The 32-byte digest is what Ed25519 signs. Because the transcript binds
 * the ciphertext bytes (not just the malleable per-chunk AEAD tags), a
 * content-key holder cannot alter plaintext while keeping a signature
 * valid: any change to a ciphertext byte changes the digest, and forging
 * an Ed25519 signature over the new digest requires the signing key.
 * Length-framing the chunk index and each ciphertext also binds chunk
 * order and count, so truncation/reorder/splice change the digest too.
 *
 * Only the running SHA-256 state is retained, never the ciphertext, so
 * signing or verifying a multi-gigabyte file uses O(1) memory.
 */
export class SenderSigTranscript {
  private readonly hash = sha256.create()
  private headerAbsorbed = false

  constructor() {
    this.hash.update(SENDER_SIG_DOMAIN)
  }

  /**
   * Absorb the header and the total chunk count. MUST be called exactly
   * once, before any chunk. `header` MUST be the exact bytes covered by
   * `header_mac` (`buildHeaderUnauthenticated` output /
   * `parseHeader().unauthenticatedBytes`).
   */
  absorbHeader(header: Uint8Array, totalChunks: number): void {
    if (this.headerAbsorbed) {
      throw new SignatureError('transcript_header_already_absorbed')
    }
    this.hash.update(uint64BE(header.length))
    this.hash.update(header)
    this.hash.update(uint64BE(totalChunks))
    this.headerAbsorbed = true
  }

  /**
   * Absorb one chunk's FULL ciphertext field (body + tag), in chunk-index
   * order. The index and length are framed alongside the bytes so
   * reordering or splicing a chunk changes the digest.
   */
  absorbChunk(chunkIndex: number, ciphertext: Uint8Array): void {
    if (!this.headerAbsorbed) {
      throw new SignatureError('transcript_header_not_absorbed')
    }
    this.hash.update(uint64BE(chunkIndex))
    this.hash.update(uint64BE(ciphertext.length))
    this.hash.update(ciphertext)
  }

  /** Finalize and return the 32-byte transcript digest. Single-use. */
  digest(): Uint8Array {
    if (!this.headerAbsorbed) {
      throw new SignatureError('transcript_header_not_absorbed')
    }
    return this.hash.digest()
  }
}

/**
 * Produce a detached Ed25519 signature over a {@link SenderSigTranscript}
 * digest (see the class docstring for the transcript definition).
 *
 * Returns the raw 64-byte signature. Callers wrap it in a signature block
 * via `buildSignatureBlock`.
 */
export function signSenderTranscript(input: {
  ed25519SecretKey: Uint8Array
  transcriptDigest: Uint8Array
}): Uint8Array {
  if (input.ed25519SecretKey.length !== ED25519_SECRET_KEY_LENGTH) {
    throw new SignatureError('ed25519_secret_key_wrong_length')
  }
  return ed25519.sign(input.transcriptDigest, input.ed25519SecretKey)
}

/**
 * Verify a detached Ed25519 signature produced by `signSenderTranscript`.
 * Returns `true` on success, `false` on any failure (wrong length,
 * malformed point, bad signature). Never throws on a verification
 * mismatch — failures are not exceptional.
 */
export function verifySenderTranscript(input: {
  ed25519PublicKey: Uint8Array
  transcriptDigest: Uint8Array
  signature: Uint8Array
}): boolean {
  if (input.ed25519PublicKey.length !== ED25519_PUBLIC_KEY_LENGTH) return false
  if (input.signature.length !== ED25519_SIGNATURE_LENGTH) return false
  try {
    return ed25519.verify(
      input.signature,
      input.transcriptDigest,
      input.ed25519PublicKey,
    )
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
