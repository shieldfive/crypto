/**
 * Generate PUBLISHED NEGATIVE / adversarial test vectors for the v1 wire format.
 *
 * Run with: npx tsx tests/vectors/generate-adversarial.ts
 *
 * Companion to vectors.json (which pins POSITIVE known-answer vectors). This
 * file pins the format's misuse-resistance guarantees as reproducible negative
 * vectors: for each attack class we build a valid baseline file, apply a precise
 * byte mutation, and record the full invalid bytes plus the expected outcome.
 *
 * A conforming decoder MUST reject every `result: "invalid"` vector and MUST
 * accept every `result: "valid"` control. Independent implementations can feed
 * the exact bytes and confirm the same accept/reject decision.
 *
 * SELF-CHECKING: as it generates, this script decrypts every variant and asserts
 * the library actually rejects each "invalid" one (and accepts each "valid"
 * baseline). A vector that does not behave as claimed fails generation — so a
 * committed vector is always one the reference implementation genuinely enforces.
 *
 * Determinism: all keys / file_ids / plaintexts are fixed, so the AEAD outputs
 * (and therefore every vector's bytes) are bit-stable across runs.
 */

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { bytesToHex } from '../../src/internal/encoding.js'
import {
  FORMAT_MAGIC_LENGTH,
  HEADER_FIXED_PREFIX_LENGTH,
  HEADER_SIZES,
  SUITE,
} from '../../src/internal/types.js'

import * as aesV1 from '../../src/suites/aes-gcm-v1/api.js'
import * as aesV2 from '../../src/suites/aes-gcm-v2/api.js'
import * as xchacha from '../../src/suites/xchacha-v1/api.js'
import * as pqHybrid from '../../src/suites/pq-hybrid-v1/api.js'
import { deriveMlKemKeypair } from '../../src/suites/pq-hybrid-v1/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── helpers ────────────────────────────────────────────────────────────

function fixedBytes(byte: number, length: number): Uint8Array {
  const out = new Uint8Array(length)
  out.fill(byte)
  return out
}

async function blobToBytes(b: Blob): Promise<Uint8Array> {
  return new Uint8Array(await b.arrayBuffer())
}

// Field offsets inside the fixed header prefix (see spec/format-v1.md).
const OFF = (() => {
  let o = 0
  const magic = o
  o += HEADER_SIZES.MAGIC
  const suite = o
  o += HEADER_SIZES.SUITE
  const flags = o
  o += HEADER_SIZES.FLAGS
  const fileId = o
  o += HEADER_SIZES.FILE_ID
  const chunkSize = o
  o += HEADER_SIZES.CHUNK_SIZE
  const totalChunks = o
  o += HEADER_SIZES.TOTAL_CHUNKS
  const plaintextSize = o
  o += HEADER_SIZES.PLAINTEXT_SIZE
  return { magic, suite, flags, fileId, chunkSize, totalChunks, plaintextSize }
})()

interface Chunk {
  prefixStart: number
  dataStart: number
  len: number
  end: number
}

/** Locate the header length and each length-prefixed chunk in a v1 file. */
function layout(bytes: Uint8Array): { headerLen: number; chunks: Chunk[] } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const suitePayloadLen = view.getUint16(HEADER_FIXED_PREFIX_LENGTH - HEADER_SIZES.SUITE_PAYLOAD_LEN)
  const headerLen = HEADER_FIXED_PREFIX_LENGTH + suitePayloadLen + HEADER_SIZES.HEADER_MAC
  const chunks: Chunk[] = []
  let off = headerLen
  while (off + 4 <= bytes.length) {
    const len = view.getUint32(off)
    const prefixStart = off
    const dataStart = off + 4
    off = dataStart + len
    chunks.push({ prefixStart, dataStart, len, end: off })
  }
  return { headerLen, chunks }
}

function withByteFlipped(bytes: Uint8Array, offset: number): Uint8Array {
  const out = bytes.slice()
  out[offset] ^= 0xff
  return out
}

function withByteSet(bytes: Uint8Array, offset: number, value: number): Uint8Array {
  const out = bytes.slice()
  out[offset] = value
  return out
}

// ── suite configs ──────────────────────────────────────────────────────

interface SuiteConfig {
  id: string
  suiteByte: number
  /** Build a valid baseline file for the given file_id seed. */
  build: (fileIdSeed: number) => Promise<Uint8Array>
  /** Decrypt bytes with the suite's keys. Throws on any rejection. */
  decrypt: (bytes: Uint8Array) => Promise<Uint8Array>
  /** A different valid suite byte to flip to, for the suite-confusion vector. */
  confuseTo: number
}

const PLAINTEXT = (() => {
  // 100 bytes, deterministic pattern → 4 chunks at chunkSize 32.
  const p = new Uint8Array(100)
  for (let i = 0; i < p.length; i += 1) p[i] = (i * 7 + 3) & 0xff
  return p
})()
const CHUNK_SIZE = 32

function symmetricConfig(
  id: string,
  suiteByte: number,
  suite: {
    encryptBlob: (o: {
      blob: Blob
      contentKey: Uint8Array
      fileId: Uint8Array
      chunkSize: number
    }) => Promise<{ blob: Blob }>
    decryptBlob: (o: { blob: Blob; contentKey: Uint8Array }) => Promise<Blob>
  },
  confuseTo: number,
): SuiteConfig {
  const contentKey = fixedBytes(0x11, 32)
  return {
    id,
    suiteByte,
    confuseTo,
    build: async (fileIdSeed) => {
      const r = await suite.encryptBlob({
        blob: new Blob([PLAINTEXT as Uint8Array<ArrayBuffer>]),
        contentKey,
        fileId: fixedBytes(fileIdSeed, 16),
        chunkSize: CHUNK_SIZE,
      })
      return blobToBytes(r.blob)
    },
    decrypt: async (bytes) => {
      const b = await suite.decryptBlob({
        blob: new Blob([bytes as Uint8Array<ArrayBuffer>]),
        contentKey,
      })
      return blobToBytes(b)
    },
  }
}

async function pqHybridConfig(): Promise<SuiteConfig> {
  const envelopeKey = fixedBytes(0x22, 32)
  const { publicKey, secretKey } = await deriveMlKemKeypair(fixedBytes(0x00, 32))
  return {
    id: 'pq-hybrid-v1',
    suiteByte: SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1,
    confuseTo: SUITE.XCHACHA20_POLY1305_V1,
    build: async (fileIdSeed) => {
      const r = await pqHybrid.encryptBlob({
        blob: new Blob([PLAINTEXT as Uint8Array<ArrayBuffer>]),
        recipientPublicKey: publicKey,
        envelopeKey,
        fileId: fixedBytes(fileIdSeed, 16),
        chunkSize: CHUNK_SIZE,
      })
      return blobToBytes(r.blob)
    },
    decrypt: async (bytes) => {
      const b = await pqHybrid.decryptBlob({
        blob: new Blob([bytes as Uint8Array<ArrayBuffer>]),
        recipientSecretKey: secretKey,
        envelopeKey,
      })
      return blobToBytes(b)
    },
  }
}

// ── vector construction ────────────────────────────────────────────────

interface Vector {
  id: string
  attackClass: string
  result: 'valid' | 'invalid'
  comment: string
  file_hex: string
}

function plaintextMatches(pt: Uint8Array): boolean {
  if (pt.length !== PLAINTEXT.length) return false
  for (let i = 0; i < pt.length; i += 1) if (pt[i] !== PLAINTEXT[i]) return false
  return true
}

async function suiteVectors(cfg: SuiteConfig): Promise<Vector[]> {
  const baseline = await cfg.build(0x5a)
  const other = await cfg.build(0xa5) // different file_id, same key → for splice
  const { headerLen, chunks } = layout(baseline)
  if (chunks.length < 2) {
    throw new Error(`${cfg.id}: expected a multi-chunk baseline, got ${chunks.length}`)
  }

  const candidates: Array<{ id: string; attackClass: string; bytes: Uint8Array; comment: string }> = []

  // Header-field mutations.
  candidates.push({
    id: 'bad_magic',
    attackClass: 'Magic strip / format confusion',
    bytes: withByteFlipped(baseline, OFF.magic),
    comment: `magic[0] flipped; must be refused before any crypto op (FORMAT_MAGIC_LENGTH=${FORMAT_MAGIC_LENGTH})`,
  })
  candidates.push({
    id: 'reserved_flags_set',
    attackClass: 'Reserved-flag abuse',
    bytes: withByteSet(baseline, OFF.flags, 0x01),
    comment: 'flags byte set to 0x01; reserved flags must be rejected during header parse',
  })
  candidates.push({
    id: 'unknown_suite',
    attackClass: 'Unknown / reserved suite id',
    bytes: withByteSet(baseline, OFF.suite, 0x7f),
    comment: 'suite byte set to an unassigned id (0x7f); must not fall back to a default',
  })
  candidates.push({
    id: 'suite_confusion',
    attackClass: 'Suite confusion / cross-suite downgrade',
    bytes: withByteSet(baseline, OFF.suite, cfg.confuseTo),
    comment: `suite byte changed to another valid suite (0x${cfg.confuseTo.toString(16).padStart(2, '0')}); defeated by the header MAC over the suite byte`,
  })
  candidates.push({
    id: 'file_id_tamper',
    attackClass: 'Header field tamper (file_id)',
    bytes: withByteFlipped(baseline, OFF.fileId),
    comment: 'first file_id byte flipped; MAC-authenticated and mixed into chunk-key/nonce derivation',
  })
  candidates.push({
    id: 'total_chunks_tamper',
    attackClass: 'Header field tamper (total_chunks)',
    bytes: withByteFlipped(baseline, OFF.totalChunks + HEADER_SIZES.TOTAL_CHUNKS - 1),
    comment: 'low byte of total_chunks flipped; MAC-authenticated + cross-field consistency checked',
  })
  candidates.push({
    id: 'plaintext_size_tamper',
    attackClass: 'Header field tamper (plaintext_size)',
    bytes: withByteFlipped(baseline, OFF.plaintextSize + HEADER_SIZES.PLAINTEXT_SIZE - 1),
    comment: 'low byte of plaintext_size flipped; MAC-authenticated + cross-field consistency checked',
  })
  candidates.push({
    id: 'header_mac_tamper',
    attackClass: 'Header MAC forgery',
    bytes: withByteFlipped(baseline, headerLen - 1),
    comment: 'last header_mac byte flipped; header MAC verification must fail',
  })

  // Chunk-level mutations.
  const c0 = chunks[0]
  const cLast = chunks[chunks.length - 1]
  candidates.push({
    id: 'chunk_length_prefix_tamper',
    attackClass: 'Chunk framing tamper (length prefix)',
    bytes: withByteFlipped(baseline, c0.prefixStart + 3),
    comment: 'low byte of chunk 0 length prefix flipped; reframes the chunk stream',
  })
  candidates.push({
    id: 'chunk_ciphertext_tamper',
    attackClass: 'Chunk ciphertext tamper',
    bytes: withByteFlipped(baseline, c0.dataStart),
    comment: 'first ciphertext byte of chunk 0 flipped; AEAD tag must fail',
  })
  candidates.push({
    id: 'chunk_tag_tamper',
    attackClass: 'Chunk AEAD tag tamper',
    bytes: withByteFlipped(baseline, c0.end - 1),
    comment: 'last byte (AEAD tag) of chunk 0 flipped; AEAD verification must fail',
  })

  // Chunk reorder (swap chunk 0 and chunk 1) — requires equal-length chunks,
  // which holds for the two leading full chunks.
  if (chunks[0].len === chunks[1].len) {
    const swapped = baseline.slice()
    const a = baseline.subarray(chunks[0].prefixStart, chunks[0].end)
    const b = baseline.subarray(chunks[1].prefixStart, chunks[1].end)
    swapped.set(b, chunks[0].prefixStart)
    swapped.set(a, chunks[1].prefixStart)
    candidates.push({
      id: 'chunk_reorder',
      attackClass: 'Chunk reordering',
      bytes: swapped,
      comment: 'chunks 0 and 1 swapped; per-chunk AAD binds the chunk index, so reorder must fail',
    })
  }

  // Truncation: drop the final chunk entirely.
  candidates.push({
    id: 'truncation_drop_last_chunk',
    attackClass: 'Truncation (final chunk dropped)',
    bytes: baseline.slice(0, cLast.prefixStart),
    comment: 'final chunk removed; the final-chunk flag / total_chunks binding must reject the short stream',
  })

  // Cross-file splice: replace chunk 1 with chunk 1 from a different file_id.
  const otherLayout = layout(other)
  if (
    otherLayout.chunks.length > 1 &&
    otherLayout.chunks[1].len === chunks[1].len
  ) {
    const spliced = baseline.slice()
    const donor = other.subarray(otherLayout.chunks[1].prefixStart, otherLayout.chunks[1].end)
    spliced.set(donor, chunks[1].prefixStart)
    candidates.push({
      id: 'cross_file_splice',
      attackClass: 'Cross-file splice',
      bytes: spliced,
      comment: 'chunk 1 replaced with chunk 1 from a different file_id (same key); file-bound chunk-key/nonce must reject it',
    })
  }

  // Self-check each candidate: it MUST fail to decrypt.
  const vectors: Vector[] = []
  for (const cand of candidates) {
    let rejected = false
    try {
      await cfg.decrypt(cand.bytes)
    } catch {
      rejected = true
    }
    if (!rejected) {
      throw new Error(
        `${cfg.id}/${cand.id}: expected the library to REJECT this mutation, but decrypt succeeded — vector is not valid`,
      )
    }
    vectors.push({
      id: `${cfg.id}/${cand.id}`,
      attackClass: cand.attackClass,
      result: 'invalid',
      comment: cand.comment,
      file_hex: bytesToHex(cand.bytes),
    })
  }

  // Valid control: the untouched baseline MUST decrypt to the known plaintext.
  const pt = await cfg.decrypt(baseline)
  if (!plaintextMatches(pt)) {
    throw new Error(`${cfg.id}: baseline did not round-trip to the known plaintext`)
  }
  vectors.push({
    id: `${cfg.id}/valid_baseline`,
    attackClass: 'Valid control',
    result: 'valid',
    comment: 'untouched baseline; a conforming decoder must ACCEPT and recover the plaintext',
    file_hex: bytesToHex(baseline),
  })

  return vectors
}

async function main() {
  const configs: SuiteConfig[] = [
    symmetricConfig('aes-gcm-v1', SUITE.AES_256_GCM_V1, aesV1, SUITE.AES_256_GCM_V2),
    symmetricConfig('aes-gcm-v2', SUITE.AES_256_GCM_V2, aesV2, SUITE.AES_256_GCM_V1),
    symmetricConfig('xchacha-v1', SUITE.XCHACHA20_POLY1305_V1, xchacha, SUITE.AES_256_GCM_V1),
    await pqHybridConfig(),
  ]

  const groups: Record<string, Vector[]> = {}
  let total = 0
  for (const cfg of configs) {
    const vectors = await suiteVectors(cfg)
    groups[cfg.id] = vectors
    total += vectors.length
  }

  const out = {
    spec_version: 'v1.0.0-alpha.1',
    kind: 'negative',
    note:
      'Adversarial / negative test vectors for @shieldfive/crypto v1. A conforming decoder MUST reject every result:"invalid" vector and MUST accept every result:"valid" control. Every vector here is self-checked against the reference implementation at generation time. Keys/file_ids/plaintext are fixed; see tests/vectors/generate-adversarial.ts.',
    generated_by: 'tests/vectors/generate-adversarial.ts',
    plaintext_hex: bytesToHex(PLAINTEXT),
    groups,
  }

  const path = resolve(__dirname, 'adversarial-vectors.json')
  writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
  console.log(`wrote ${path}`)
  console.log(
    `${Object.keys(groups).length} suites, ${total} vectors, ` +
      `${(JSON.stringify(out).length / 1024).toFixed(1)} KiB JSON`,
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
