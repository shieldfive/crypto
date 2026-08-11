/**
 * Shared trailing-signature-block handling for the v1 wire format.
 *
 * A v1 file MAY carry an optional trailing Ed25519 signature block after
 * the last chunk (see `spec/format-v1.md § "Signature block"`). Both the
 * streaming decoders and the whole-blob decryptors need identical
 * semantics for that tail — parse it, reject malformed trailing garbage,
 * and optionally verify it against a caller-pinned public key — so the
 * logic lives here, in one place, rather than being duplicated (or, as
 * happened before, implemented by the streams and silently omitted by the
 * blob readers).
 */

import { HeaderError } from './header.js'
import {
  parseSignatureBlock,
  type SignatureBlock,
  SignatureError,
  SIGNATURE_ALGO_ED25519,
  verifySenderTranscript,
} from '../identity/sign.js'

/**
 * Verified signature metadata surfaced by a v1 decryptor.
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

/**
 * Parse a trailing signature block (if any) from a decryptor's residual
 * bytes, optionally verifying it against the caller's trusted public key.
 *
 * `transcriptDigest` is the {@link SenderSigTranscript} digest rebuilt
 * over the header and every chunk's full ciphertext as it was decrypted,
 * so `verified: true` means the signer signed exactly these bytes. It is
 * only consulted when `expectedSignerPublicKey` is supplied.
 *
 * Returns `null` for a file with no trailing bytes (legacy / unsigned).
 * Throws `HeaderError` if the trailing bytes are not a well-formed
 * signature block or carry garbage after it — the spec's MUST-reject.
 *
 * Shared between the AES-GCM and PQ-hybrid stream decoders and every
 * whole-blob decryptor so the signature semantics live in one place.
 */
export function finalizeSignatureMetadata(input: {
  trailingBytes: Uint8Array
  transcriptDigest: Uint8Array
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
        verifySenderTranscript({
          ed25519PublicKey: input.expectedSignerPublicKey,
          transcriptDigest: input.transcriptDigest,
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
