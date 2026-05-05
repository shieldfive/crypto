/**
 * Performance benchmarks for @shieldfive/crypto.
 *
 * Run with: npx tsx bench/throughput.ts
 *
 * Measures encrypt and decrypt throughput per suite for representative
 * file sizes. Numbers are environment-dependent; report them with the
 * Node version, OS, and CPU model.
 */

import { performance } from 'node:perf_hooks'
import { cpus } from 'node:os'

import * as aes from '../src/suites/aes-gcm-v1/api.js'
import * as xchacha from '../src/suites/xchacha-v1/api.js'
import * as pqHybrid from '../src/suites/pq-hybrid-v1/api.js'
import { generateMlKemKeypair } from '../src/suites/pq-hybrid-v1/index.js'
import { randomBytes } from '../src/internal/runtime.js'

const SIZES = [
  { label: '1 MiB', bytes: 1024 * 1024 },
  { label: '16 MiB', bytes: 16 * 1024 * 1024 },
  { label: '64 MiB', bytes: 64 * 1024 * 1024 },
]

const CHUNK_SIZE = 4 * 1024 * 1024

function fmtRate(bytes: number, ms: number): string {
  const mibPerSec = bytes / (1024 * 1024) / (ms / 1000)
  return `${mibPerSec.toFixed(0).padStart(5)} MiB/s (${ms.toFixed(0)} ms)`
}

async function benchAes(plain: Uint8Array): Promise<{ enc: number; dec: number }> {
  const t0 = performance.now()
  const r = await aes.encryptBytes(plain, { chunkSize: CHUNK_SIZE })
  const t1 = performance.now()
  await aes.decryptToBytes({ blob: r.blob, contentKey: r.contentKey })
  const t2 = performance.now()
  return { enc: t1 - t0, dec: t2 - t1 }
}

async function benchXchacha(plain: Uint8Array): Promise<{ enc: number; dec: number }> {
  const t0 = performance.now()
  const r = await xchacha.encryptBytes(plain, { chunkSize: CHUNK_SIZE })
  const t1 = performance.now()
  await xchacha.decryptToBytes({ blob: r.blob, contentKey: r.contentKey })
  const t2 = performance.now()
  return { enc: t1 - t0, dec: t2 - t1 }
}

async function benchPqHybrid(plain: Uint8Array): Promise<{ enc: number; dec: number }> {
  const { publicKey, secretKey } = generateMlKemKeypair()
  const envelopeKey = randomBytes(32)
  const t0 = performance.now()
  const r = await pqHybrid.encryptBytes(plain, {
    recipientPublicKey: publicKey,
    envelopeKey,
    chunkSize: CHUNK_SIZE,
  })
  const t1 = performance.now()
  await pqHybrid.decryptToBytes({
    blob: r.blob,
    recipientSecretKey: secretKey,
    envelopeKey,
  })
  const t2 = performance.now()
  return { enc: t1 - t0, dec: t2 - t1 }
}

async function main() {
  console.log('@shieldfive/crypto throughput benchmark')
  console.log(`node ${process.version}, ${cpus()[0]?.model ?? 'unknown CPU'}`)
  console.log(`chunk size: ${(CHUNK_SIZE / 1024 / 1024).toFixed(0)} MiB\n`)

  for (const { label, bytes } of SIZES) {
    const plain = randomBytes(bytes > 65536 ? 65536 : bytes)
    // Tile a small random buffer to fill the requested size — random bytes
    // don't compress, and tiling keeps memory usage sane.
    const full = new Uint8Array(bytes)
    for (let off = 0; off < bytes; off += plain.length) {
      full.set(plain.subarray(0, Math.min(plain.length, bytes - off)), off)
    }

    console.log(`── ${label}`)
    {
      const { enc, dec } = await benchAes(full)
      console.log(`  aes-256-gcm-v1   enc ${fmtRate(bytes, enc)}   dec ${fmtRate(bytes, dec)}`)
    }
    {
      const { enc, dec } = await benchXchacha(full)
      console.log(`  xchacha-v1       enc ${fmtRate(bytes, enc)}   dec ${fmtRate(bytes, dec)}`)
    }
    {
      const { enc, dec } = await benchPqHybrid(full)
      console.log(`  pq-hybrid-v1     enc ${fmtRate(bytes, enc)}   dec ${fmtRate(bytes, dec)}`)
    }
    console.log()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
