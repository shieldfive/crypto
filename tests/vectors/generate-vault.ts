/**
 * Generate tests/vectors/vault-vectors.json for spec/vault-formats.md.
 *
 * Run with: npx tsx tests/vectors/generate-vault.ts
 *
 * Deliberately built WITHOUT src/vault: Argon2id comes from @noble/hashes
 * (not libsodium), AES-GCM and HKDF from Web Crypto directly. The verifier
 * then checks src/vault against these bytes, so the vectors are an
 * independent second implementation of the spec, not a snapshot of itself.
 */

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { argon2id } from '@noble/hashes/argon2.js'
import { sha256 } from '@noble/hashes/sha2.js'

const subtle = globalThis.crypto.subtle
const enc = new TextEncoder()
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url')
const fill = (n: number, start: number) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff)

async function gcm(key: Uint8Array, iv: Uint8Array, pt: Uint8Array, aad?: Uint8Array) {
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt'])
  const params: AesGcmParams = { name: 'AES-GCM', iv }
  if (aad) params.additionalData = aad
  return new Uint8Array(await subtle.encrypt(params, k, pt))
}

async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(
    await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, k, 256),
  )
}

async function main() {
  const rootKey = fill(32, 0x10)
  const folderKey = fill(32, 0x40)
  const fileKey = fill(32, 0x70)
  const chainIv = fill(12, 0xa0)
  const fkWrapped = await gcm(rootKey, chainIv, folderKey)

  const rowId = '6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7'
  const name = 'Tax return 2025 – final (signed).pdf'
  const salt = fill(16, 0xc0)
  const nameIv = fill(12, 0xd0)
  // web: libsodium crypto_pwhash(32, base64(folderKey) as UTF-8, salt, 2, 64 MiB, ARGON2ID13)
  const nameKey = argon2id(enc.encode(b64(folderKey)), salt, { t: 2, m: 64 * 1024, p: 1, dkLen: 32, version: 0x13 })
  const v6 = await gcm(nameKey, nameIv, enc.encode(name), enc.encode(rowId))
  const v4 = await gcm(nameKey, nameIv, enc.encode(name))
  const split = (s: Uint8Array) => ({ ct: b64(s.slice(0, s.length - 16)), tag: b64(s.slice(s.length - 16)) })

  const grantId = '0b7e9d2c-1a3f-4e5d-9c8b-7a6f5e4d3c2b'
  const token = fill(32, 0x01)
  const secret = fill(32, 0x81)
  const mlKemPk = fill(1568, 0x05)
  const gk = await hkdf(secret, enc.encode(grantId), 'shieldfive/v1/agent-grant/wrap')
  const grantIv = fill(12, 0xe0)
  const folderId = '11111111-2222-4333-8444-555555555555'
  const aad = `sf-grant-v1|${grantId}|folder|${folderId}`
  const grantWrap = await gcm(gk, grantIv, folderKey, enc.encode(aad))

  // Owner copy of the grant secret: HKDF(RK, salt = grant id, "…/agent-grant/secret"),
  // AAD = canonical scope.
  const scope = `sf-grant-scope-v1|${grantId}|all=0|media=0|roots=${folderId}|trash=-|excluded=`
  const sk = await hkdf(rootKey, enc.encode(grantId), 'shieldfive/v1/agent-grant/secret')
  const secretIv = fill(12, 0xf0)
  const secretWrap = await gcm(sk, secretIv, secret, enc.encode(scope))

  const out = {
    spec: 'spec/vault-formats.md',
    chain: {
      root_key_hex: hex(rootKey),
      folder_key_hex: hex(folderKey),
      file_key_hex: hex(fileKey),
      fk_wrapped: b64(fkWrapped),
      fk_iv: b64(chainIv),
    },
    names: {
      folder_key_hex: hex(folderKey),
      row_id: rowId,
      plaintext: name,
      v6: { v: 6, ...split(v6), iv: b64(nameIv), salt: b64(salt), kdf: 'interactive' },
      v4_no_kdf: { v: 4, ...split(v4), iv: b64(nameIv), salt: b64(salt) },
    },
    grant: {
      grant_id: grantId,
      token_hex: hex(token),
      secret_hex: hex(secret),
      ml_kem_pk_fill_start: 5,
      pk_fingerprint: hex(sha256(mlKemPk)),
      connection_string: `sf-grant-v1:${grantId}.${b64url(token)}.${b64url(secret)}.${hex(sha256(mlKemPk))}`,
      token_hash: hex(sha256(token)),
      wrap_key_hex: hex(gk),
      folder_id: folderId,
      aad,
      folder_key_wrapped: b64(grantWrap),
      folder_key_iv: b64(grantIv),
      scope_canonical: scope,
      secret_wrapped: b64(secretWrap),
      secret_iv: b64(secretIv),
    },
  }
  const here = dirname(fileURLToPath(import.meta.url))
  writeFileSync(resolve(here, 'vault-vectors.json'), JSON.stringify(out, null, 2) + '\n')
}

await main()
