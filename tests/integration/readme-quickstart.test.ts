/**
 * Pins the README quick-start contract. Any future change that removes
 * generateMlKemKeypair (or breaks encryptBlob/decryptBlob) from the
 * `@shieldfive/crypto/pq-hybrid-v1` subpath will fail here.
 *
 * Imports go through the package's public subpath (Node self-reference
 * resolves to the `exports` map in package.json), so this exercises the
 * same surface a consumer copy-pasting from README sees. Requires `dist/`
 * to exist — `npm run build` before `npm test`.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  decryptBlob,
  encryptBlob,
  generateMlKemKeypair,
} from '@shieldfive/crypto/pq-hybrid-v1'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test('README quick-start: pq-hybrid-v1 round trip via public subpath', async () => {
  const { publicKey, secretKey } = generateMlKemKeypair()

  const envelopeKey = crypto.getRandomValues(new Uint8Array(32))

  const myData = new TextEncoder().encode(
    'README quick-start payload — pins generateMlKemKeypair on the public subpath',
  )
  const file = new File([myData], 'document.pdf')
  const result = await encryptBlob({
    blob: file,
    recipientPublicKey: publicKey,
    envelopeKey,
  })

  const plaintext = await decryptBlob({
    blob: result.blob,
    recipientSecretKey: secretKey,
    envelopeKey,
  })

  const decoded = new Uint8Array(await plaintext.arrayBuffer())
  assert.ok(bytesEqual(myData, decoded))
})
