/**
 * Pins the offline decryptor recipe (examples/decrypt-one.mjs) — the reference
 * implementation of https://shieldfive.com/export Part 2. Two things broke and
 * are covered here:
 *
 *   1. Filename decryption hard-coded Argon2id INTERACTIVE and never handled
 *      the AAD-bound v6 format, so every file fell back to <uuid>.bin. These
 *      tests build encrypted names exactly the way the web client
 *      (utils/metadataClient.ts) does — v4 at both kdf levels, v6 with the row
 *      UUID as AAD, and the legacy v3 — and assert the original name is
 *      recovered, plus that a swapped row UUID is rejected.
 *
 *   2. `--output ./decrypted` wrote a FILE named `decrypted` on a fresh run
 *      (stat() threw, the literal path was used). resolveOutputPath now treats
 *      --output as a directory by default; the end-to-end `run()` test asserts
 *      a directory containing the file under its real name is produced from a
 *      real suite-0x03 bundle.
 *
 * Imports go through the package's public subpaths (Node self-reference →
 * exports map), the same surface the recipe uses. Requires `dist/` — pretest
 * runs `npm run build`.
 */

import { strict as assert } from 'node:assert'
import { mkdtemp, mkdir, readFile, writeFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { webcrypto } from 'node:crypto'
import test from 'node:test'

import sodium from 'libsodium-wrappers-sumo'
import { bytesToBase64 } from '@shieldfive/crypto'
import { createIdentity } from '@shieldfive/crypto/unstable_identity'
import { encryptBlob as pqEncryptBlob } from '@shieldfive/crypto/pq-hybrid-v1'

import {
  decryptFilename,
  resolveOutputPath,
  run,
} from '../../examples/decrypt-one.mjs'

const subtle = webcrypto.subtle
type KdfLevel = 'interactive' | 'moderate'

function randomBytes(n: number): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(n))
}

/**
 * Build an encrypted filename the way utils/metadataClient.ts does:
 *   secret  = bytesToBase64(parentKey)  (the same string fed to crypto_pwhash)
 *   key     = Argon2id(secret, salt) at the given level
 *   payload = { v, ct, iv, tag, salt, kdf } with v=6 binding rowId as AAD.
 */
async function buildEncryptedName(opts: {
  name: string
  parentKey: Uint8Array
  kdf?: KdfLevel
  rowId?: string | null
}): Promise<string> {
  await sodium.ready
  const salt = randomBytes(16)
  const secret = bytesToBase64(opts.parentKey)
  const level: KdfLevel = opts.kdf ?? 'interactive'
  const ops =
    level === 'interactive'
      ? sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
      : sodium.crypto_pwhash_OPSLIMIT_MODERATE
  const mem =
    level === 'interactive'
      ? sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
      : sodium.crypto_pwhash_MEMLIMIT_MODERATE
  const keyBytes = sodium.crypto_pwhash(
    32,
    secret,
    salt,
    ops,
    mem,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )
  const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
  ])
  const iv = randomBytes(12)
  const additionalData = opts.rowId
    ? new TextEncoder().encode(opts.rowId)
    : undefined
  const encrypted = new Uint8Array(
    await subtle.encrypt(
      additionalData
        ? { name: 'AES-GCM', iv, additionalData }
        : { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(opts.name),
    ),
  )
  const ct = encrypted.slice(0, encrypted.length - 16)
  const tag = encrypted.slice(encrypted.length - 16)
  const payload: Record<string, unknown> = {
    v: opts.rowId ? 6 : 4,
    ct: bytesToBase64(ct),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(tag),
    salt: bytesToBase64(salt),
  }
  if (opts.kdf) payload.kdf = opts.kdf
  return JSON.stringify(payload)
}

/** Legacy v3 name: AES-GCM key = SHA-256(secret), no salt, no AAD. */
async function buildLegacyName(opts: {
  name: string
  parentKey: Uint8Array
}): Promise<string> {
  const secret = bytesToBase64(opts.parentKey)
  const digest = await subtle.digest(
    'SHA-256',
    new TextEncoder().encode(secret),
  )
  const key = await subtle.importKey(
    'raw',
    new Uint8Array(digest),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const iv = randomBytes(12)
  const encrypted = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(opts.name),
    ),
  )
  const ct = encrypted.slice(0, encrypted.length - 16)
  const tag = encrypted.slice(encrypted.length - 16)
  return JSON.stringify({
    v: 3,
    ct: bytesToBase64(ct),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(tag),
  })
}

async function aesGcmWrap(
  wrappingKey: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ wrapped: string; iv: string }> {
  const key = await subtle.importKey(
    'raw',
    wrappingKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )
  const iv = randomBytes(12)
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext),
  )
  return { wrapped: bytesToBase64(ct), iv: bytesToBase64(iv) }
}

test('decryptFilename recovers a v4 name encrypted with kdf=interactive', async () => {
  const parentKey = randomBytes(32)
  const encryptedJson = await buildEncryptedName({
    name: 'quarterly-report.pdf',
    parentKey,
    kdf: 'interactive',
  })
  const name = await decryptFilename({ encryptedJson, parentKey })
  assert.equal(name, 'quarterly-report.pdf')
})

test('decryptFilename recovers a v4 name encrypted with kdf=moderate', async () => {
  const parentKey = randomBytes(32)
  const encryptedJson = await buildEncryptedName({
    name: 'desktop-export.csv',
    parentKey,
    kdf: 'moderate',
  })
  const name = await decryptFilename({ encryptedJson, parentKey })
  assert.equal(name, 'desktop-export.csv')
})

test('decryptFilename recovers a v4 name with no recorded kdf (tries both)', async () => {
  const parentKey = randomBytes(32)
  // moderate ciphertext but the kdf field omitted — the fallback order must
  // still land on the right level.
  const encryptedJson = await buildEncryptedName({
    name: 'legacy-strong.txt',
    parentKey,
    kdf: undefined,
  })
  const name = await decryptFilename({ encryptedJson, parentKey })
  assert.equal(name, 'legacy-strong.txt')
})

test('decryptFilename recovers an AAD-bound v6 name with the matching row id', async () => {
  const parentKey = randomBytes(32)
  const rowId = '11111111-2222-3333-4444-555555555555'
  const encryptedJson = await buildEncryptedName({
    name: 'bound-to-row.png',
    parentKey,
    kdf: 'interactive',
    rowId,
  })
  const name = await decryptFilename({ encryptedJson, parentKey, rowId })
  assert.equal(name, 'bound-to-row.png')
})

test('decryptFilename rejects a v6 name carrying a swapped row id', async () => {
  const parentKey = randomBytes(32)
  const realRowId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
  const encryptedJson = await buildEncryptedName({
    name: 'should-not-decrypt.png',
    parentKey,
    kdf: 'interactive',
    rowId: realRowId,
  })
  await assert.rejects(
    () =>
      decryptFilename({
        encryptedJson,
        parentKey,
        rowId: 'ffffffff-ffff-ffff-ffff-ffffffffffff',
      }),
    /filename decryption failed for v6/,
  )
})

test('decryptFilename surfaces a clear error when v6 row id is missing', async () => {
  const parentKey = randomBytes(32)
  const encryptedJson = await buildEncryptedName({
    name: 'needs-aad.png',
    parentKey,
    kdf: 'interactive',
    rowId: 'cafef00d-0000-0000-0000-000000000000',
  })
  await assert.rejects(
    () => decryptFilename({ encryptedJson, parentKey, rowId: null }),
    /requires the file row id/,
  )
})

test('decryptFilename recovers a legacy v3 name', async () => {
  const parentKey = randomBytes(32)
  const encryptedJson = await buildLegacyName({
    name: 'old-school.doc',
    parentKey,
  })
  const name = await decryptFilename({ encryptedJson, parentKey })
  assert.equal(name, 'old-school.doc')
})

test('resolveOutputPath treats a fresh --output dir as a directory (regression)', async () => {
  const base = await mkdtemp(join(tmpdir(), 'sf-out-'))
  try {
    // Path does NOT exist yet and has no extension → directory mode. This is
    // the case that previously wrote a FILE named `decrypted`.
    const target = join(base, 'decrypted')
    const outPath = await resolveOutputPath(target, 'report.pdf')
    assert.equal(outPath, join(target, 'report.pdf'))
    const dirStat = await stat(target)
    assert.ok(dirStat.isDirectory(), 'output target should be created as a dir')
    await writeFile(outPath, new Uint8Array([1, 2, 3]))
    const written = await readFile(outPath)
    assert.deepEqual(new Uint8Array(written), new Uint8Array([1, 2, 3]))
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('resolveOutputPath writes a single file when --output has an extension', async () => {
  const base = await mkdtemp(join(tmpdir(), 'sf-out-'))
  try {
    const target = join(base, 'nested', 'exact-name.bin')
    const outPath = await resolveOutputPath(target, 'ignored-fallback.bin')
    assert.equal(outPath, target, 'should use the literal path in file mode')
    await writeFile(outPath, new Uint8Array([9]))
    assert.ok((await stat(target)).isFile())
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('resolveOutputPath joins the name into an existing directory', async () => {
  const base = await mkdtemp(join(tmpdir(), 'sf-out-'))
  try {
    const outPath = await resolveOutputPath(base, 'inside.txt')
    assert.equal(outPath, join(base, 'inside.txt'))
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('run() decrypts a real suite-0x03 bundle into <output-dir>/<original-name>', async () => {
  await sodium.ready
  const work = await mkdtemp(join(tmpdir(), 'sf-bundle-'))
  try {
    const bundleDir = join(work, 'backup')
    await mkdir(join(bundleDir, 'blobs'), { recursive: true })

    // Root key (raw) + recovery key. The vault uses the recovery-key path so
    // the test doesn't pay for a vault-unwrap Argon2id.
    const rootKey = randomBytes(32)
    const recoveryKey = randomBytes(32)
    const recWrapped = await aesGcmWrap(recoveryKey, rootKey)
    await writeFile(
      join(bundleDir, 'vault.json'),
      JSON.stringify({
        recIv: recWrapped.iv,
        rkWrappedByRec: recWrapped.wrapped,
      }),
    )

    // A root-level file. parentKey === rootKey, so the filename secret is
    // bytesToBase64(rootKey) — exactly what the web client would feed.
    const fileId = '0fa1afe1-dead-beef-cafe-000000000001'
    const plaintext = new TextEncoder().encode(
      'offline export round-trip — suite 0x03 owner path',
    )

    // CSK is the classical envelope key for the PQ-hybrid suite.
    const csk = randomBytes(32)
    const identity = await createIdentity({
      userId: 'shieldfive-export',
      masterSecret: rootKey,
    })
    const { blob } = await pqEncryptBlob({
      blob: new Blob([plaintext]),
      recipientPublicKey: identity.publicBundle.mlKemPublicKey,
      envelopeKey: csk,
    })
    const blobBytes = new Uint8Array(await blob.arrayBuffer())
    await writeFile(join(bundleDir, 'blobs', `${fileId}.bin`), blobBytes)

    // CSK wrapped under the root key (file at root).
    const cskWrapped = await aesGcmWrap(rootKey, csk)

    // AAD-bound v6 name, the format current uploads produce.
    const originalName = 'année-fiscale.pdf'
    const nameEncrypted = await buildEncryptedName({
      name: originalName,
      parentKey: rootKey,
      kdf: 'interactive',
      rowId: fileId,
    })

    await writeFile(
      join(bundleDir, 'files.json'),
      JSON.stringify([
        {
          id: fileId,
          name: nameEncrypted,
          folder_id: null,
          cipher_version: 3,
          csk_wrapped: cskWrapped.wrapped,
          csk_iv: cskWrapped.iv,
        },
      ]),
    )
    await writeFile(join(bundleDir, 'folders.json'), JSON.stringify([]))

    // --output is a non-existent directory (no extension) → directory mode.
    const outputDir = join(work, 'decrypted')
    const result = await run({
      bundleDir,
      fileId,
      output: outputDir,
      recoveryKey: bytesToBase64(recoveryKey),
    })

    assert.equal(result.plaintextName, originalName)
    assert.equal(result.outPath, join(outputDir, originalName))
    assert.ok(
      (await stat(outputDir)).isDirectory(),
      'output should be created as a directory',
    )
    const recovered = new Uint8Array(await readFile(result.outPath))
    assert.deepEqual(recovered, plaintext)
  } finally {
    await rm(work, { recursive: true, force: true })
  }
})
