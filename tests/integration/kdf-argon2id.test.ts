/**
 * Argon2id master-secret derivation tests.
 *
 * These tests use the 'moderate' preset (3 ops, 256 MiB) which takes
 * roughly 1 second per derivation. We deliberately do not test the
 * 'sensitive' preset in CI because it requires 1 GiB of RAM.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'

import {
  ARGON2ID_SALT_BYTES,
  MASTER_SECRET_BYTES,
  deriveMasterSecret,
  reDeriveMasterSecret,
  verifyPassphrase,
} from '../../src/kdf/argon2id.js'
import { randomBytes } from '../../src/internal/runtime.js'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false
  return true
}

test(
  'argon2id: derives a 32-byte master secret with a 16-byte salt by default',
  { timeout: 30_000 },
  async () => {
    const out = await deriveMasterSecret({
      passphrase: 'correct horse battery staple',
    })
    assert.equal(out.masterSecret.length, MASTER_SECRET_BYTES)
    assert.equal(out.salt.length, ARGON2ID_SALT_BYTES)
    assert.equal(out.preset, 'moderate')
  },
)

test(
  'argon2id: same passphrase + salt produces the same master secret',
  { timeout: 60_000 },
  async () => {
    const salt = randomBytes(ARGON2ID_SALT_BYTES)
    const a = await deriveMasterSecret({
      passphrase: 'correct horse battery staple',
      salt,
    })
    const b = await reDeriveMasterSecret({
      passphrase: 'correct horse battery staple',
      salt,
      preset: 'moderate',
    })
    assert.ok(bytesEqual(a.masterSecret, b))
  },
)

test(
  'argon2id: different salt produces different master secret',
  { timeout: 60_000 },
  async () => {
    const a = await deriveMasterSecret({ passphrase: 'pp' })
    const b = await deriveMasterSecret({ passphrase: 'pp' })
    assert.equal(a.salt.length, b.salt.length)
    assert.ok(!bytesEqual(a.salt, b.salt), 'salts should be random')
    assert.ok(!bytesEqual(a.masterSecret, b.masterSecret))
  },
)

test(
  'argon2id: different passphrase produces different master secret',
  { timeout: 60_000 },
  async () => {
    const salt = randomBytes(ARGON2ID_SALT_BYTES)
    const a = await deriveMasterSecret({ passphrase: 'aaa', salt })
    const b = await deriveMasterSecret({ passphrase: 'bbb', salt })
    assert.ok(!bytesEqual(a.masterSecret, b.masterSecret))
  },
)

test(
  'argon2id: verifyPassphrase accepts correct passphrase',
  { timeout: 60_000 },
  async () => {
    const out = await deriveMasterSecret({ passphrase: 'pp' })
    const ok = await verifyPassphrase({
      passphrase: 'pp',
      salt: out.salt,
      preset: out.preset,
      expectedMasterSecret: out.masterSecret,
    })
    assert.equal(ok, true)
  },
)

test(
  'argon2id: verifyPassphrase rejects wrong passphrase',
  { timeout: 60_000 },
  async () => {
    const out = await deriveMasterSecret({ passphrase: 'pp' })
    const ok = await verifyPassphrase({
      passphrase: 'wrong',
      salt: out.salt,
      preset: out.preset,
      expectedMasterSecret: out.masterSecret,
    })
    assert.equal(ok, false)
  },
)

test('argon2id: rejects empty passphrase', async () => {
  await assert.rejects(
    () => deriveMasterSecret({ passphrase: '' }),
    /non-empty/,
  )
})

test('argon2id: rejects too-short salt', async () => {
  await assert.rejects(
    () =>
      deriveMasterSecret({
        passphrase: 'pp',
        salt: new Uint8Array(8),
      }),
    /at least 16 bytes/,
  )
})

test(
  'argon2id: long salt is compressed via HKDF deterministically',
  { timeout: 60_000 },
  async () => {
    const longSalt = new Uint8Array(64).fill(0x42)
    const a = await deriveMasterSecret({
      passphrase: 'pp',
      salt: longSalt,
    })
    const b = await deriveMasterSecret({
      passphrase: 'pp',
      salt: longSalt,
    })
    assert.ok(bytesEqual(a.masterSecret, b.masterSecret))
    // The salt returned is the original (caller-supplied) value.
    assert.equal(a.salt.length, 64)
  },
)
