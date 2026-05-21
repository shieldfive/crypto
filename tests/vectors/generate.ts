/**
 * Generate deterministic test vectors for the v1 wire format.
 *
 * Run with: npx tsx tests/vectors/generate.ts
 *
 * Outputs JSON files into tests/vectors/ that any independent implementation
 * of the v1 spec MUST be able to reproduce bit-for-bit. These vectors are
 * committed to the repository.
 *
 * Determinism note: every random byte that would normally be generated
 * fresh per file is replaced with a fixed seed-derived value here. The
 * library APIs that need randomness (content key, file_id, IVs, ML-KEM
 * seed) are called with explicit values where possible; for the rest we
 * monkey-patch crypto.getRandomValues for the duration of generation.
 */

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildAuthenticatedHeader,
  buildChunkAad,
  parseHeader,
} from '../../src/format/header.js'
import {
  bytesToBase64,
  bytesToHex,
} from '../../src/internal/encoding.js'
import { hkdfSha256 } from '../../src/internal/hkdf.js'
import { hmacSha256 } from '../../src/internal/hmac.js'
import { HKDF_INFO, SUITE } from '../../src/internal/types.js'

import * as aes from '../../src/suites/aes-gcm-v1/api.js'
import * as xchacha from '../../src/suites/xchacha-v1/api.js'
import { deriveMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

function fixedBytes(byte: number, length: number): Uint8Array {
  const out = new Uint8Array(length)
  out.fill(byte)
  return out
}

/** Reproducible "random-ish" bytes from a seed. SHAKE-style via HKDF. */
async function seeded(label: string, length: number): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: new TextEncoder().encode(label),
    info: 'shieldfive/v1/test-vector',
    length,
  })
}

function vec(value: Uint8Array): { hex: string; base64: string; length: number } {
  return {
    hex: bytesToHex(value),
    base64: bytesToBase64(value),
    length: value.length,
  }
}

async function blobToBytes(b: Blob): Promise<Uint8Array> {
  return new Uint8Array(await b.arrayBuffer())
}

// ──────────────────────────────────────────────────────────────────────
// Vector 1 — encoding primitives
// ──────────────────────────────────────────────────────────────────────

async function encodingVectors() {
  return {
    description:
      'Big-endian integer codec test vectors. Each entry: input value → expected bytes.',
    uint16BE: [
      { value: 0, hex: '0000' },
      { value: 1, hex: '0001' },
      { value: 256, hex: '0100' },
      { value: 65535, hex: 'ffff' },
    ],
    uint32BE: [
      { value: 0, hex: '00000000' },
      { value: 1, hex: '00000001' },
      { value: 256, hex: '00000100' },
      { value: 65536, hex: '00010000' },
      { value: 4294967295, hex: 'ffffffff' },
    ],
    uint64BE: [
      { value: 0, hex: '0000000000000000' },
      { value: 1, hex: '0000000000000001' },
      { value: 256, hex: '0000000000000100' },
      { value: 65536, hex: '0000000000010000' },
      { value: 4294967296, hex: '0000000100000000' },
      { value: Number.MAX_SAFE_INTEGER, hex: '001fffffffffffff' },
    ],
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 2 — HKDF-SHA-256 derivations used by the format
// ──────────────────────────────────────────────────────────────────────

async function hkdfVectors() {
  const contentKey = fixedBytes(0xa5, 32)
  const fileId = fixedBytes(0x5a, 16)

  const headerMacKey = await hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.HEADER_MAC,
    length: 32,
  })

  const aesChunkKey = await hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.AES_GCM_CHUNK_KEY,
    length: 32,
  })

  const aesNoncePrefix = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.AES_GCM_NONCE_PREFIX,
    length: 4,
  })

  const xchachaChunkKey = await hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.XCHACHA_CHUNK_KEY,
    length: 32,
  })

  const xchachaNoncePrefix = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.XCHACHA_NONCE_PREFIX,
    length: 16,
  })

  return {
    description:
      'HKDF-SHA-256 derivations used by the v1 format. Inputs are fixed; outputs MUST match for any conforming implementation.',
    inputs: {
      content_key: vec(contentKey),
      file_id: vec(fileId),
    },
    derived: {
      header_mac_key: vec(headerMacKey),
      'aes-256-gcm-v1.chunk_key': vec(aesChunkKey),
      'aes-256-gcm-v1.nonce_prefix': vec(aesNoncePrefix),
      'xchacha20-poly1305-v1.chunk_key': vec(xchachaChunkKey),
      'xchacha20-poly1305-v1.nonce_prefix': vec(xchachaNoncePrefix),
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 3 — chunk AAD construction
// ──────────────────────────────────────────────────────────────────────

async function chunkAadVectors() {
  return {
    description:
      'Chunk AAD layout: domain string ("shieldfive/v1/chunk", 19 bytes) || uint64_be(index) || uint64_be(total) || is_final.',
    cases: [
      {
        chunk_index: 0,
        total_chunks: 1,
        is_final: true,
        aad: vec(buildChunkAad(0, 1, true)),
      },
      {
        chunk_index: 0,
        total_chunks: 4,
        is_final: false,
        aad: vec(buildChunkAad(0, 4, false)),
      },
      {
        chunk_index: 3,
        total_chunks: 4,
        is_final: true,
        aad: vec(buildChunkAad(3, 4, true)),
      },
      {
        chunk_index: 12345,
        total_chunks: 67890,
        is_final: false,
        aad: vec(buildChunkAad(12345, 67890, false)),
      },
    ],
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 4 — header construction (suite-agnostic check)
// ──────────────────────────────────────────────────────────────────────

async function headerVectors() {
  const contentKey = fixedBytes(0xa5, 32)
  const fileId = fixedBytes(0x5a, 16)
  const suitePayload = fixedBytes(0x00, 72) // AES-GCM-v1 layout, zero-filled

  const header = await buildAuthenticatedHeader(
    {
      suite: SUITE.AES_256_GCM_V1,
      fileId,
      chunkSize: 4096,
      totalChunks: 3,
      plaintextSize: 4096 * 2 + 17,
      suitePayload,
    },
    contentKey,
  )

  // Re-parse to confirm round-trip and report fields explicitly.
  const parsed = parseHeader(header)

  return {
    description:
      'Full v1 header bytes for fixed inputs. Implementations MUST produce this exact byte sequence given the same inputs.',
    inputs: {
      suite: '0x01 (aes-256-gcm-v1)',
      content_key: vec(contentKey),
      file_id: vec(fileId),
      chunk_size: 4096,
      total_chunks: 3,
      plaintext_size: 4096 * 2 + 17,
      suite_payload: vec(suitePayload),
    },
    output: {
      header_total_bytes: header.length,
      header: vec(header),
      parsed: {
        suite: parsed.suite,
        flags: parsed.flags,
        chunk_size: parsed.chunkSize,
        total_chunks: parsed.totalChunks,
        plaintext_size: parsed.plaintextSize,
        suite_payload_length: parsed.suitePayload.length,
      },
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 5 — full file round trip, AES-GCM-v1
// ──────────────────────────────────────────────────────────────────────

async function aesGcmFileVector() {
  const contentKey = fixedBytes(0x11, 32)
  const fileId = fixedBytes(0x22, 16)
  // Plaintext: 100 bytes, deterministic pattern.
  const plaintext = await seeded('aes-gcm-v1/plaintext-100', 100)

  const result = await aes.encryptBlob({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: 32, // forces multi-chunk: 100/32 = 4 chunks (32+32+32+4)
  })

  const ciphertext = await blobToBytes(result.blob)

  // Sanity-check that decryption recovers the input
  const decrypted = await aes.decryptToBytes({
    blob: result.blob,
    contentKey,
  })
  if (
    decrypted.length !== plaintext.length ||
    !decrypted.every((b, i) => b === plaintext[i])
  ) {
    throw new Error('vector self-check failed: aes-gcm-v1 round trip')
  }

  return {
    description:
      'Full encrypt/decrypt round trip with fixed key, fixed file_id, deterministic plaintext. ' +
      'Note that AES-GCM is deterministic given (key, IV, plaintext, AAD), so this vector is bit-stable.',
    inputs: {
      suite: '0x01 (aes-256-gcm-v1)',
      content_key: vec(contentKey),
      file_id: vec(fileId),
      chunk_size: 32,
      plaintext: vec(plaintext),
    },
    output: {
      total_chunks: result.totalChunks,
      plaintext_size: result.plaintextSize,
      encrypted_total_bytes: ciphertext.length,
      encrypted_blob: vec(ciphertext),
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 6 — full file round trip, XChaCha20-Poly1305-v1
// ──────────────────────────────────────────────────────────────────────

async function xchachaFileVector() {
  const contentKey = fixedBytes(0x33, 32)
  const fileId = fixedBytes(0x44, 16)
  const plaintext = await seeded('xchacha-v1/plaintext-100', 100)

  const result = await xchacha.encryptBlob({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: 32,
  })

  const ciphertext = await blobToBytes(result.blob)

  const decrypted = await xchacha.decryptToBytes({
    blob: result.blob,
    contentKey,
  })
  if (
    decrypted.length !== plaintext.length ||
    !decrypted.every((b, i) => b === plaintext[i])
  ) {
    throw new Error('vector self-check failed: xchacha-v1 round trip')
  }

  return {
    description:
      'Full encrypt/decrypt round trip for xchacha-v1 with fixed inputs. XChaCha20-Poly1305 is deterministic given (key, nonce, AAD, plaintext).',
    inputs: {
      suite: '0x02 (xchacha20-poly1305-v1)',
      content_key: vec(contentKey),
      file_id: vec(fileId),
      chunk_size: 32,
      plaintext: vec(plaintext),
    },
    output: {
      total_chunks: result.totalChunks,
      plaintext_size: result.plaintextSize,
      encrypted_total_bytes: ciphertext.length,
      encrypted_blob: vec(ciphertext),
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 7 — HMAC-SHA-256 sanity check
// ──────────────────────────────────────────────────────────────────────

async function hmacVector() {
  // RFC 4231 test case 1
  const key = new Uint8Array(20).fill(0x0b)
  const data = new TextEncoder().encode('Hi There')
  const expected =
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
  const computed = await hmacSha256(key, data)
  const computedHex = bytesToHex(computed)
  if (computedHex !== expected) {
    throw new Error(
      `HMAC-SHA-256 self-check failed: expected ${expected}, got ${computedHex}`,
    )
  }
  return {
    description:
      'HMAC-SHA-256 sanity check against RFC 4231 test case 1. Confirms the host primitive is correct before deriving header MAC keys.',
    rfc_4231_case_1: {
      key: vec(key),
      data_utf8: 'Hi There',
      expected_hex: expected,
      computed_hex: computedHex,
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 8 — AAD binding (file_id is NOT in AAD)
// ──────────────────────────────────────────────────────────────────────
//
// Pins the AES-GCM-v1 ciphertext bytes for fixed all-zero key/file_id at
// chunk_index=0 (total_chunks=1) and chunk_index=1 (total_chunks=2). If
// any future change adds file_id to the AAD construction, the AEAD tag
// bytes will diverge and these vectors will fail.
//
// Internal-review finding 1.1: spec prose previously claimed file_id was
// in the AAD; the structural binding is via per-suite HKDF salts.

async function aadBindingVectors() {
  const contentKey = fixedBytes(0x00, 32)
  const fileId = fixedBytes(0x00, 16)

  // Single-chunk file: 32 bytes of 0x00 → chunk_index=0, total_chunks=1, is_final=true
  const oneChunkPlaintext = fixedBytes(0x00, 32)
  const oneChunk = await aes.encryptBlob({
    blob: new Blob([oneChunkPlaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: 32,
  })
  const oneChunkCt = await blobToBytes(oneChunk.blob)

  // Two-chunk file: 33 bytes → first chunk is full (32 bytes), final chunk is 1 byte
  const twoChunkPlaintext = fixedBytes(0x00, 33)
  const twoChunk = await aes.encryptBlob({
    blob: new Blob([twoChunkPlaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: 32,
  })
  const twoChunkCt = await blobToBytes(twoChunk.blob)

  return {
    description:
      'AES-GCM-v1 full-file ciphertext with fixed all-zero content_key and file_id. ' +
      'Pins that file_id is NOT mixed into the AAD bytes. Cross-file splice resistance is ' +
      'provided structurally via HKDF salts in chunk-key and nonce-prefix derivation. ' +
      'Adding file_id to AAD construction would change the AEAD tags and fail these vectors. ' +
      'See spec/format-v1.md and internal-review finding 1.1.',
    inputs: {
      suite: '0x01 (aes-256-gcm-v1)',
      content_key: vec(contentKey),
      file_id: vec(fileId),
      chunk_size: 32,
    },
    one_chunk: {
      plaintext: vec(oneChunkPlaintext),
      total_chunks: oneChunk.totalChunks,
      plaintext_size: oneChunk.plaintextSize,
      encrypted_blob: vec(oneChunkCt),
    },
    two_chunk: {
      plaintext: vec(twoChunkPlaintext),
      total_chunks: twoChunk.totalChunks,
      plaintext_size: twoChunk.plaintextSize,
      encrypted_blob: vec(twoChunkCt),
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 9 — nonce-prefix absent-salt convention (RFC 5869 zeros(32))
// ──────────────────────────────────────────────────────────────────────
//
// Pins the AES-GCM-v1 (4-byte) and XChaCha-v1 (16-byte) nonce prefixes
// for file_id = zeros(16). The HKDF salt is the RFC 5869 absent-salt
// zero-fill: zeros(32). This documents the convention the spec now
// states explicitly.
//
// Note for implementers: under HMAC-SHA-256, salt = Uint8Array(0) and
// salt = zeros(32) produce identical HKDF-Extract outputs, because HMAC
// zero-pads keys shorter than its 64-byte block size. The vectors
// therefore cannot computationally distinguish the two cases; they can,
// however, catch grosser errors such as using salt = file_id or
// omitting HKDF-Extract entirely.
//
// Internal-review findings 1.2 + 2.8.

async function noncePrefixAbsentSaltVectors() {
  const fileId = fixedBytes(0x00, 16)

  const aesNoncePrefix = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.AES_GCM_NONCE_PREFIX,
    length: 4,
  })

  const xchachaNoncePrefix = await hkdfSha256({
    ikm: fileId,
    info: HKDF_INFO.XCHACHA_NONCE_PREFIX,
    length: 16,
  })

  return {
    description:
      'Nonce-prefix HKDF outputs with file_id = zeros(16). Salt is the RFC 5869 ' +
      'absent-salt zero-fill (zeros(32) for SHA-256). For HMAC-SHA-256, ' +
      'salt=Uint8Array(0) and salt=zeros(32) are computationally equivalent; the ' +
      'vector documents the canonical convention rather than catching that ' +
      'distinction. See internal-review findings 1.2 + 2.8.',
    inputs: {
      file_id: vec(fileId),
      salt_convention: 'absent (HKDF default → zeros(32) per RFC 5869)',
    },
    derived: {
      'aes-256-gcm-v1.nonce_prefix': vec(aesNoncePrefix),
      'xchacha20-poly1305-v1.nonce_prefix': vec(xchachaNoncePrefix),
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector 10 — ML-KEM-1024 keypair derivation (seed split convention)
// ──────────────────────────────────────────────────────────────────────
//
// Pins the deterministic ML-KEM-1024 keypair derived from a master
// secret of zeros(32). The 64-byte HKDF output is split into
// d = seed[0..32] and z = seed[32..64] per FIPS 203 (Algorithms 16
// and 17). Third-party implementations using a library whose KeyGen
// API exposes (d, z) separately MUST split the seed exactly this way;
// implementations using a combined-seed KeyGen(seed) (e.g.,
// @noble/post-quantum) can verify by reproducing the full pk and sk
// outputs.
//
// Internal-review finding 2.4.

async function mlKemKeypairDerivationVectors() {
  const masterSecret = fixedBytes(0x00, 32)

  const mlKemSeed = await hkdfSha256({
    ikm: masterSecret,
    info: HKDF_INFO.ML_KEM_1024_SEED,
    length: 64,
  })

  const { publicKey, secretKey } = await deriveMlKemKeypair(masterSecret)

  return {
    description:
      'Deterministic ML-KEM-1024 keypair derivation from master_secret = zeros(32). ' +
      'Pins the 64-byte HKDF seed output and the full pk (1568 bytes) and sk ' +
      '(3168 bytes) produced by ML-KEM-1024.KeyGen(d=seed[0..32], z=seed[32..64]). ' +
      'See spec/key-derivation.md § "Derivation tree" and internal-review finding 2.4.',
    inputs: {
      master_secret: vec(masterSecret),
      hkdf_info: HKDF_INFO.ML_KEM_1024_SEED,
      seed_length: 64,
    },
    derived: {
      ml_kem_seed: vec(mlKemSeed),
      'ml_kem_seed.d_first_32': vec(mlKemSeed.subarray(0, 32)),
      'ml_kem_seed.z_last_32': vec(mlKemSeed.subarray(32, 64)),
      ml_kem_public_key: vec(publicKey),
      ml_kem_secret_key: vec(secretKey),
    },
  }
}

// ──────────────────────────────────────────────────────────────────────
// Driver
// ──────────────────────────────────────────────────────────────────────

async function main() {
  const out = {
    spec_version: 'v1.0.0-alpha.1',
    note:
      'Bit-stable test vectors for @shieldfive/crypto v1. Independent implementations MUST reproduce these outputs exactly.',
    generated_by: 'tests/vectors/generate.ts',
    vectors: {
      '01_encoding': await encodingVectors(),
      '02_hkdf': await hkdfVectors(),
      '03_chunk_aad': await chunkAadVectors(),
      '04_header': await headerVectors(),
      '05_aes_gcm_v1_file': await aesGcmFileVector(),
      '06_xchacha_v1_file': await xchachaFileVector(),
      '07_hmac_sha256_rfc4231': await hmacVector(),
      '08_aad_binding': await aadBindingVectors(),
      '09_nonce_prefix_absent_salt': await noncePrefixAbsentSaltVectors(),
      '10_ml_kem_keypair_derivation': await mlKemKeypairDerivationVectors(),
    },
  }

  const path = resolve(__dirname, 'vectors.json')
  writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
  console.log(`wrote ${path}`)
  console.log(
    `${Object.keys(out.vectors).length} vector groups, ` +
      `${(JSON.stringify(out).length / 1024).toFixed(1)} KiB JSON`,
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
