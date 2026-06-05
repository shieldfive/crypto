#!/usr/bin/env node
// Offline ShieldFive decryptor for a single file from an exported backup
// bundle. Reads vault.json, files.json, folders.json, and a blob from
// <bundle>/, derives the key hierarchy from the user's master password (or
// recovery key), and writes the plaintext to <output>. It is self-contained:
// the only runtime dependencies are @shieldfive/crypto and
// libsodium-wrappers-sumo — the same library that runs in the browser.
//
// This is the reference implementation of the "decrypt offline" recipe at
// https://shieldfive.com/export. The recipe walks through pulling your
// ciphertext archive and running this script; the two are kept in sync.
//
// Target library version: @shieldfive/crypto 1.0.0-alpha.11 — the version
// shieldfive.com currently pins. Install the exact version your files were
// encrypted with (printed by the export bundle); the public API used here
// (autoDecryptBlob, decryptV0, createIdentity, deriveMasterSecret) is stable
// across the 1.0.0-alpha line. Handles the v0 legacy format (cipher_version
// 1), AES-256-GCM-v1 / suite 0x01 (cipher_version 2), and the PQ-hybrid
// ML-KEM-1024 default / suite 0x03 (cipher_version 3).
//
// Usage:
//   node decrypt-one.mjs --bundle ./backup --file-id <uuid> \
//     --password 'YOUR PASSWORD' --output ./decrypted
//
//   # Recovery-key path (use instead of --password):
//   node decrypt-one.mjs --bundle ./backup --file-id <uuid> \
//     --recovery-key 'BASE64...' --output ./decrypted
//
// Required peer dependencies (install in the working directory):
//   npm install @shieldfive/crypto@1.0.0-alpha.11 libsodium-wrappers-sumo
//
// Outputs:
//   - If --output is a directory: writes <output>/<decrypted-filename>
//   - Otherwise: writes the literal <output> path
//   - Falls back to <file-id>.bin if filename decryption fails

import { readFile, writeFile, stat, mkdir } from 'node:fs/promises'
import { webcrypto } from 'node:crypto'
import { resolve, join, dirname } from 'node:path'

import sodium from 'libsodium-wrappers-sumo'
import {
  autoDecryptBlob,
  base64ToBytes,
  bytesToBase64,
} from '@shieldfive/crypto'
import { deriveMasterSecret } from '@shieldfive/crypto/kdf/argon2id'
import { createIdentity } from '@shieldfive/crypto/identity'
import { decryptV0 } from '@shieldfive/crypto/legacy-v0'

const subtle = webcrypto.subtle

// ───────────────────────────────────────────────────────────────────────────
// Arg parsing
// ───────────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = {}
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    if (!flag.startsWith('--')) continue
    const key = flag.slice(2)
    const value = argv[i + 1]
    args[key] = value
    i++
  }
  return args
}

function requireArg(args, name) {
  if (!args[name]) {
    console.error(`Missing required --${name}`)
    process.exit(2)
  }
  return args[name]
}

// ───────────────────────────────────────────────────────────────────────────
// Key derivation (mirrors the vault-key unwrap the ShieldFive web client
// performs: user key from password/recovery key, then the wrapped root key)
// ───────────────────────────────────────────────────────────────────────────

async function deriveUserKey({ password, salt, kdf, iterations, argon2Preset }) {
  if (kdf === 'pbkdf2-sha256') {
    if (!iterations || iterations <= 0) {
      throw new Error('PBKDF2 unwrap requires a positive iteration count')
    }
    const material = await subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    )
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )
  }
  if (kdf === 'argon2id') {
    if (argon2Preset !== 'moderate' && argon2Preset !== 'sensitive') {
      throw new Error(`Unsupported Argon2id preset: ${argon2Preset}`)
    }
    const { masterSecret } = await deriveMasterSecret({
      passphrase: password,
      salt,
      preset: argon2Preset,
    })
    return subtle.importKey(
      'raw',
      masterSecret,
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    )
  }
  throw new Error(`Unsupported vault KDF: ${kdf}`)
}

async function aesGcmDecrypt(key, iv, ciphertext) {
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext),
  )
}

async function importAesKey(rawKey32) {
  return subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, [
    'decrypt',
  ])
}

async function unwrapRootKey({ vault, password, recoveryKey }) {
  if (recoveryKey) {
    const recKeyBytes = base64ToBytes(recoveryKey.trim())
    const recKey = await importAesKey(recKeyBytes)
    const rk = await aesGcmDecrypt(
      recKey,
      base64ToBytes(vault.recIv),
      base64ToBytes(vault.rkWrappedByRec),
    )
    return rk
  }
  const ukSalt = base64ToBytes(vault.ukSalt)
  const ukIv = base64ToBytes(vault.ukIv)
  const wrapped = base64ToBytes(vault.rkWrappedByUk)
  const uk = await deriveUserKey({
    password,
    salt: ukSalt,
    kdf: vault.ukKdf,
    iterations: vault.ukIterations,
    argon2Preset: vault.ukArgon2Preset,
  })
  return aesGcmDecrypt(uk, ukIv, wrapped)
}

// ───────────────────────────────────────────────────────────────────────────
// Folder ancestry: walk parent_id chain, unwrapping each fk_wrapped under its
// parent's key. Root-level folders' fk is wrapped under rootKey.
// ───────────────────────────────────────────────────────────────────────────

async function deriveFolderKey({ folderId, folders, rootKey }) {
  if (!folderId) return rootKey
  const ancestors = []
  let cursor = folderId
  while (cursor) {
    const node = folders.find((f) => f.id === cursor)
    if (!node) {
      throw new Error(`Folder ${cursor} not found in folders.json`)
    }
    ancestors.unshift(node)
    cursor = node.parent_id
  }
  let parentKey = rootKey
  for (const node of ancestors) {
    if (!node.fk_wrapped || !node.fk_iv) {
      throw new Error(`Folder ${node.id} has no fk_wrapped — cannot derive key`)
    }
    const wrappingKey = await importAesKey(parentKey)
    parentKey = await aesGcmDecrypt(
      wrappingKey,
      base64ToBytes(node.fk_iv),
      base64ToBytes(node.fk_wrapped),
    )
  }
  return parentKey
}

// ───────────────────────────────────────────────────────────────────────────
// Filename decryption (the v3 SHA-256 and v4 Argon2id metadata paths the
// ShieldFive web client uses for encrypted filenames)
// ───────────────────────────────────────────────────────────────────────────

async function decryptFilename({ encryptedJson, parentKey }) {
  let parsed
  try {
    parsed = JSON.parse(encryptedJson)
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object') return null

  if (parsed.v === 4) {
    await sodium.ready
    const salt = base64ToBytes(parsed.salt)
    const secret = bytesToBase64(parentKey)
    // Web client always uses INTERACTIVE for cross-device compatibility.
    const keyBytes = sodium.crypto_pwhash(
      32,
      secret,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    )
    const key = await importAesKey(keyBytes)
    const ct = base64ToBytes(parsed.ct)
    const tag = base64ToBytes(parsed.tag)
    const iv = base64ToBytes(parsed.iv)
    const combined = new Uint8Array(ct.length + tag.length)
    combined.set(ct, 0)
    combined.set(tag, ct.length)
    const plaintext = await aesGcmDecrypt(key, iv, combined)
    return new TextDecoder().decode(plaintext)
  }

  if (parsed.v === 3) {
    const secret = bytesToBase64(parentKey)
    const digest = await subtle.digest(
      'SHA-256',
      new TextEncoder().encode(secret),
    )
    const key = await importAesKey(new Uint8Array(digest))
    const ct = base64ToBytes(parsed.ct)
    const tag = base64ToBytes(parsed.tag)
    const iv = base64ToBytes(parsed.iv)
    const combined = new Uint8Array(ct.length + tag.length)
    combined.set(ct, 0)
    combined.set(tag, ct.length)
    const plaintext = await aesGcmDecrypt(key, iv, combined)
    return new TextDecoder().decode(plaintext)
  }

  return null
}

// ───────────────────────────────────────────────────────────────────────────
// Blob decryption (dispatches by cipher_version)
// ───────────────────────────────────────────────────────────────────────────

async function decryptBlob({ blob, file, csk, rootKey }) {
  const version = file.cipher_version
  if (version === 1) {
    if (
      typeof file.cipher_chunk_size !== 'number' ||
      typeof file.cipher_nonce_prefix !== 'string'
    ) {
      throw new Error(
        'Missing v0 (cipher_version=1) chunk_size or nonce_prefix on file row',
      )
    }
    return decryptV0({
      blob,
      contentKey: csk,
      noncePrefix: base64ToBytes(file.cipher_nonce_prefix),
      chunkSize: file.cipher_chunk_size,
    })
  }
  if (version === 2) {
    // Suite 0x01 — AES-256-GCM-v1. autoDecryptBlob reads file_id from header
    // and derives chunk_key/nonce_prefix internally.
    return autoDecryptBlob({ blob, contentKey: csk })
  }
  if (version === 3) {
    // Suite 0x03 — PQ-hybrid (ML-KEM-1024 + XChaCha20-Poly1305). Owner path:
    // csk is the *classical envelope key*; the ML-KEM secret is re-derived
    // from rootKey (deterministic per the v1 spec). userId is bundle
    // metadata only — does not affect the derived keypair bytes.
    const { mlKemSecretKey } = await createIdentity({
      userId: 'shieldfive-export',
      masterSecret: rootKey,
    })
    return autoDecryptBlob({
      blob,
      envelopeKey: csk,
      recipientSecretKey: mlKemSecretKey,
    })
  }
  throw new Error(`Unsupported cipher_version: ${version}`)
}

// ───────────────────────────────────────────────────────────────────────────
// Main
// ───────────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const bundleDir = resolve(requireArg(args, 'bundle'))
  const fileId = requireArg(args, 'file-id')
  const output = resolve(requireArg(args, 'output'))
  const password = args.password ?? null
  const recoveryKey = args['recovery-key'] ?? null
  if (!password && !recoveryKey) {
    console.error('Provide either --password or --recovery-key')
    process.exit(2)
  }

  const vault = JSON.parse(await readFile(join(bundleDir, 'vault.json'), 'utf8'))
  const filesRaw = JSON.parse(
    await readFile(join(bundleDir, 'files.json'), 'utf8'),
  )
  const folders = JSON.parse(
    await readFile(join(bundleDir, 'folders.json'), 'utf8'),
  )
  const files = Array.isArray(filesRaw)
    ? filesRaw
    : Array.isArray(filesRaw?.files)
      ? filesRaw.files
      : []
  const file = files.find((f) => f.id === fileId)
  if (!file) {
    throw new Error(`File ${fileId} not found in files.json`)
  }
  if (!file.csk_wrapped || !file.csk_iv) {
    throw new Error(
      `File ${fileId} has no csk_wrapped — owner-side metadata missing`,
    )
  }

  const rootKey = await unwrapRootKey({ vault, password, recoveryKey })

  const parentKey = await deriveFolderKey({
    folderId: file.folder_id,
    folders,
    rootKey,
  })

  // Unwrap content-stream key (CSK) for this file.
  const wrappingKey = await importAesKey(parentKey)
  const csk = await aesGcmDecrypt(
    wrappingKey,
    base64ToBytes(file.csk_iv),
    base64ToBytes(file.csk_wrapped),
  )

  // Decrypt the encrypted filename.
  const plaintextName = await decryptFilename({
    encryptedJson: file.name,
    parentKey,
  }).catch(() => null)
  const safeName = plaintextName?.replace(/[/\\]/g, '_') || `${fileId}.bin`

  // Load the encrypted blob.
  const blobPath = join(bundleDir, 'blobs', `${fileId}.bin`)
  const blobBytes = await readFile(blobPath)
  const blob = new Blob([blobBytes])

  const decrypted = await decryptBlob({ blob, file, csk, rootKey })
  const decryptedBytes = new Uint8Array(await decrypted.arrayBuffer())

  // Resolve output path: directory → join with filename; otherwise literal.
  let outPath = output
  try {
    const s = await stat(output)
    if (s.isDirectory()) outPath = join(output, safeName)
  } catch {
    // output doesn't exist yet — use as-is. mkdir its parent.
    await mkdir(dirname(output), { recursive: true })
  }
  await writeFile(outPath, decryptedBytes)

  console.log(`Decrypted ${fileId} → ${outPath} (${decryptedBytes.length} bytes)`)
  if (!plaintextName) {
    console.warn(
      'Filename could not be decrypted; wrote with fallback name. Ensure parent folder ancestry in folders.json is intact.',
    )
  }
}

main().catch((err) => {
  console.error('decrypt-one failed:', err?.message ?? err)
  process.exit(1)
})
