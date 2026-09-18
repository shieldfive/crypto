/**
 * Verify src/vault against tests/vectors/vault-vectors.json, which
 * generate-vault.ts builds from an independent implementation (@noble Argon2id
 * + raw Web Crypto). A failure here means src/vault no longer reads what the
 * web app writes.
 */

import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { hexToBytes, bytesToHex } from '../../src/internal/encoding.js'
import {
  decryptName,
  deriveGrantWrapKey,
  formatConnectionString,
  hashGrantToken,
  grantBearerToken,
  parseConnectionString,
  parseNameEnvelope,
  publicKeyFingerprint,
  unwrapChainKey,
  unwrapKeyForGrant,
  canonicalGrantScope,
  unwrapGrantSecret,
} from '../../src/vault/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const V = JSON.parse(readFileSync(resolve(here, 'vault-vectors.json'), 'utf8'))

test('chain: fk_wrapped opens under the root key', async () => {
  const fk = await unwrapChainKey(hexToBytes(V.chain.root_key_hex), {
    wrapped: V.chain.fk_wrapped,
    iv: V.chain.fk_iv,
  })
  assert.equal(bytesToHex(fk), V.chain.folder_key_hex)
})

test('names: v6 and kdf-less v4 decrypt to the vector plaintext', async () => {
  const folderKey = hexToBytes(V.names.folder_key_hex)
  const v6 = parseNameEnvelope(JSON.stringify(V.names.v6))
  assert.ok(v6)
  assert.equal(await decryptName({ envelope: v6, folderKey, rowId: V.names.row_id }), V.names.plaintext)
  const v4 = parseNameEnvelope(JSON.stringify(V.names.v4_no_kdf))
  assert.ok(v4)
  assert.equal(await decryptName({ envelope: v4, folderKey }), V.names.plaintext)
})

test('grant: wrap key, fingerprint, token hash and connection string match', async () => {
  const g = V.grant
  const secret = hexToBytes(g.secret_hex)
  const token = hexToBytes(g.token_hex)
  const gk = await deriveGrantWrapKey(secret, g.grant_id)
  assert.equal(bytesToHex(gk), g.wrap_key_hex)

  const pk = Uint8Array.from({ length: 1568 }, (_, i) => (g.ml_kem_pk_fill_start + i) & 0xff)
  assert.equal(publicKeyFingerprint(pk), g.pk_fingerprint)

  const cred = { grantId: g.grant_id, token, secret, publicKeyFingerprint: g.pk_fingerprint }
  assert.equal(formatConnectionString(cred), g.connection_string)
  const parsed = parseConnectionString(g.connection_string)
  assert.equal(bytesToHex(parsed.token), g.token_hex)
  assert.equal(bytesToHex(parsed.secret), g.secret_hex)
  assert.equal(hashGrantToken(grantBearerToken(parsed)), g.token_hash)

  const fk = await unwrapKeyForGrant({
    grantWrapKey: gk,
    grantId: g.grant_id,
    kind: 'folder',
    objectId: g.folder_id,
    wrapped: { wrapped: g.folder_key_wrapped, iv: g.folder_key_iv },
  })
  assert.equal(bytesToHex(fk), V.chain.folder_key_hex)
})

test('grant secret: canonical scope and the owner wrap match the independent vector', async () => {
  const g = V.grant
  const scope = { grantId: g.grant_id, scopeAll: false, includeMedia: false, rootIds: [g.folder_id], trashFolderId: null, excludedIds: [] }
  assert.equal(canonicalGrantScope(scope), g.scope_canonical)
  const secret = await unwrapGrantSecret({ rootKey: hexToBytes(V.chain.root_key_hex), scope, wrapped: { wrapped: g.secret_wrapped, iv: g.secret_iv } })
  assert.equal(bytesToHex(secret), g.secret_hex)
})
