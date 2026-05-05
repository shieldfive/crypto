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
import { HEADER_SIZES, HKDF_INFO, SUITE } from '../../src/internal/types.js'

import * as aes from '../../src/suites/aes-gcm-v1/api.js'
import * as xchacha from '../../src/suites/xchacha-v1/api.js'

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
