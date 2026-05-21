/**
 * Test vector verifier.
 *
 * Loads tests/vectors/vectors.json and re-derives every vector from scratch.
 * If any output diverges from what's committed, the format has changed in a
 * way that breaks bit-compatibility — either intentional (in which case
 * regenerate the vectors and bump the spec_version) or unintentional (a
 * regression to be caught here, not by users).
 */

import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  buildAuthenticatedHeader,
  buildChunkAad,
} from '../../src/format/header.js'
import {
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  uint16BE,
  uint32BE,
  uint64BE,
} from '../../src/internal/encoding.js'
import { hkdfSha256 } from '../../src/internal/hkdf.js'
import { hmacSha256 } from '../../src/internal/hmac.js'
import { HKDF_INFO, SUITE } from '../../src/internal/types.js'

import * as aes from '../../src/suites/aes-gcm-v1/api.js'
import * as xchacha from '../../src/suites/xchacha-v1/api.js'
import { deriveMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const VECTORS = JSON.parse(
  readFileSync(resolve(__dirname, 'vectors.json'), 'utf8'),
)

async function seeded(label: string, length: number): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: new TextEncoder().encode(label),
    info: 'shieldfive/v1/test-vector',
    length,
  })
}

test('vectors: encoding uint16BE', () => {
  for (const c of VECTORS.vectors['01_encoding'].uint16BE) {
    assert.equal(bytesToHex(uint16BE(c.value)), c.hex)
  }
})

test('vectors: encoding uint32BE', () => {
  for (const c of VECTORS.vectors['01_encoding'].uint32BE) {
    assert.equal(bytesToHex(uint32BE(c.value)), c.hex)
  }
})

test('vectors: encoding uint64BE', () => {
  for (const c of VECTORS.vectors['01_encoding'].uint64BE) {
    assert.equal(bytesToHex(uint64BE(c.value)), c.hex)
  }
})

test('vectors: HKDF derivations', async () => {
  const v = VECTORS.vectors['02_hkdf']
  const contentKey = hexToBytes(v.inputs.content_key.hex)
  const fileId = hexToBytes(v.inputs.file_id.hex)

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: contentKey,
        salt: fileId,
        info: HKDF_INFO.HEADER_MAC,
        length: 32,
      }),
    ),
    v.derived.header_mac_key.hex,
  )

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: contentKey,
        salt: fileId,
        info: HKDF_INFO.AES_GCM_CHUNK_KEY,
        length: 32,
      }),
    ),
    v.derived['aes-256-gcm-v1.chunk_key'].hex,
  )

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: fileId,
        info: HKDF_INFO.AES_GCM_NONCE_PREFIX,
        length: 4,
      }),
    ),
    v.derived['aes-256-gcm-v1.nonce_prefix'].hex,
  )

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: contentKey,
        salt: fileId,
        info: HKDF_INFO.XCHACHA_CHUNK_KEY,
        length: 32,
      }),
    ),
    v.derived['xchacha20-poly1305-v1.chunk_key'].hex,
  )

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: fileId,
        info: HKDF_INFO.XCHACHA_NONCE_PREFIX,
        length: 16,
      }),
    ),
    v.derived['xchacha20-poly1305-v1.nonce_prefix'].hex,
  )
})

test('vectors: chunk AAD construction', () => {
  for (const c of VECTORS.vectors['03_chunk_aad'].cases) {
    const computed = buildChunkAad(c.chunk_index, c.total_chunks, c.is_final)
    assert.equal(bytesToHex(computed), c.aad.hex)
  }
})

test('vectors: header construction', async () => {
  const v = VECTORS.vectors['04_header']
  const header = await buildAuthenticatedHeader(
    {
      suite: SUITE.AES_256_GCM_V1,
      fileId: hexToBytes(v.inputs.file_id.hex),
      chunkSize: v.inputs.chunk_size,
      totalChunks: v.inputs.total_chunks,
      plaintextSize: v.inputs.plaintext_size,
      suitePayload: hexToBytes(v.inputs.suite_payload.hex),
    },
    hexToBytes(v.inputs.content_key.hex),
  )
  assert.equal(bytesToHex(header), v.output.header.hex)
})

test('vectors: full aes-gcm-v1 file round trip', async () => {
  const v = VECTORS.vectors['05_aes_gcm_v1_file']
  const contentKey = hexToBytes(v.inputs.content_key.hex)
  const fileId = hexToBytes(v.inputs.file_id.hex)
  const plaintext = await seeded('aes-gcm-v1/plaintext-100', 100)
  // Confirm the seeded plaintext matches what the vectors recorded.
  assert.equal(bytesToBase64(plaintext), v.inputs.plaintext.base64)

  const result = await aes.encryptBlob({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: v.inputs.chunk_size,
  })

  const ciphertext = new Uint8Array(await result.blob.arrayBuffer())
  assert.equal(bytesToHex(ciphertext), v.output.encrypted_blob.hex)
})

test('vectors: full xchacha-v1 file round trip', async () => {
  const v = VECTORS.vectors['06_xchacha_v1_file']
  const contentKey = hexToBytes(v.inputs.content_key.hex)
  const fileId = hexToBytes(v.inputs.file_id.hex)
  const plaintext = await seeded('xchacha-v1/plaintext-100', 100)
  assert.equal(bytesToBase64(plaintext), v.inputs.plaintext.base64)

  const result = await xchacha.encryptBlob({
    blob: new Blob([plaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: v.inputs.chunk_size,
  })

  const ciphertext = new Uint8Array(await result.blob.arrayBuffer())
  assert.equal(bytesToHex(ciphertext), v.output.encrypted_blob.hex)
})

test('vectors: HMAC-SHA-256 RFC 4231 case 1', async () => {
  const v = VECTORS.vectors['07_hmac_sha256_rfc4231'].rfc_4231_case_1
  const computed = await hmacSha256(
    hexToBytes(v.key.hex),
    new TextEncoder().encode(v.data_utf8),
  )
  assert.equal(bytesToHex(computed), v.expected_hex)
})

test('vectors: AAD binding — file_id is NOT in AAD (aes-gcm-v1)', async () => {
  const v = VECTORS.vectors['08_aad_binding']
  const contentKey = hexToBytes(v.inputs.content_key.hex)
  const fileId = hexToBytes(v.inputs.file_id.hex)

  const oneChunkPlaintext = hexToBytes(v.one_chunk.plaintext.hex)
  const oneChunk = await aes.encryptBlob({
    blob: new Blob([oneChunkPlaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: v.inputs.chunk_size,
  })
  assert.equal(
    bytesToHex(new Uint8Array(await oneChunk.blob.arrayBuffer())),
    v.one_chunk.encrypted_blob.hex,
  )

  const twoChunkPlaintext = hexToBytes(v.two_chunk.plaintext.hex)
  const twoChunk = await aes.encryptBlob({
    blob: new Blob([twoChunkPlaintext as Uint8Array<ArrayBuffer>]),
    contentKey,
    fileId,
    chunkSize: v.inputs.chunk_size,
  })
  assert.equal(
    bytesToHex(new Uint8Array(await twoChunk.blob.arrayBuffer())),
    v.two_chunk.encrypted_blob.hex,
  )
})

test('vectors: nonce-prefix absent-salt convention is zeros(32)', async () => {
  const v = VECTORS.vectors['09_nonce_prefix_absent_salt']
  const fileId = hexToBytes(v.inputs.file_id.hex)

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: fileId,
        info: HKDF_INFO.AES_GCM_NONCE_PREFIX,
        length: 4,
      }),
    ),
    v.derived['aes-256-gcm-v1.nonce_prefix'].hex,
  )

  assert.equal(
    bytesToHex(
      await hkdfSha256({
        ikm: fileId,
        info: HKDF_INFO.XCHACHA_NONCE_PREFIX,
        length: 16,
      }),
    ),
    v.derived['xchacha20-poly1305-v1.nonce_prefix'].hex,
  )
})

test('vectors: ML-KEM-1024 keypair derivation (seed split convention)', async () => {
  const v = VECTORS.vectors['10_ml_kem_keypair_derivation']
  const masterSecret = hexToBytes(v.inputs.master_secret.hex)

  // Step 1: re-derive the 64-byte seed and confirm bit-stability.
  const mlKemSeed = await hkdfSha256({
    ikm: masterSecret,
    info: HKDF_INFO.ML_KEM_1024_SEED,
    length: 64,
  })
  assert.equal(bytesToHex(mlKemSeed), v.derived.ml_kem_seed.hex)

  // Step 2: confirm the documented d/z split halves match the seed.
  assert.equal(
    bytesToHex(mlKemSeed.subarray(0, 32)),
    v.derived['ml_kem_seed.d_first_32'].hex,
  )
  assert.equal(
    bytesToHex(mlKemSeed.subarray(32, 64)),
    v.derived['ml_kem_seed.z_last_32'].hex,
  )

  // Step 3: derive the keypair and confirm pk / sk match the pinned bytes.
  // A reimplementation that splits the seed differently than
  // d=seed[0..32], z=seed[32..64] will produce different pk/sk and fail
  // here.
  const { publicKey, secretKey } = await deriveMlKemKeypair(masterSecret)
  assert.equal(bytesToHex(publicKey), v.derived.ml_kem_public_key.hex)
  assert.equal(bytesToHex(secretKey), v.derived.ml_kem_secret_key.hex)
})
