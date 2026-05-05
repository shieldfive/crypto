/**
 * Argon2id-based key derivation for password-derived master secrets.
 *
 * The library does not require its callers to use this module — the host
 * application can produce a 32-byte master secret any way it likes. But
 * for the common case of "stretch a user passphrase into a master key,"
 * this module gives a vetted default with explicit parameter choices.
 *
 * Backed by libsodium-wrappers-sumo (loaded lazily). Requires the
 * optional peer dependency to be installed.
 */

import { getSodium } from '../internal/sodium.js'
import { hkdfSha256 } from '../internal/hkdf.js'
import { randomBytes } from '../internal/runtime.js'

/**
 * Argon2id parameter presets.
 *
 * "interactive" is libsodium's MIN; we deliberately do not expose it.
 * "moderate" is the documented default for password storage on
 *  contemporary devices (3 ops, 256 MiB).
 * "sensitive" is appropriate for high-value secrets but requires 1 GiB
 *  of RAM and is unsuitable for mobile devices.
 *
 * The chosen preset is encoded into the output so a derived secret can be
 * re-derived later without storing the parameters alongside.
 */
export type Argon2idPreset = 'moderate' | 'sensitive'

export const ARGON2ID_SALT_BYTES = 16
export const MASTER_SECRET_BYTES = 32

interface PresetConfig {
  opslimit: number // libsodium ops parameter
  memlimit: number // libsodium memory parameter (bytes)
}

/** Resolve a preset name to (opslimit, memlimit) using libsodium constants. */
async function resolvePreset(preset: Argon2idPreset): Promise<PresetConfig> {
  const sodium = await getSodium()
  switch (preset) {
    case 'moderate':
      return {
        opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
        memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      }
    case 'sensitive':
      return {
        opslimit: sodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
        memlimit: sodium.crypto_pwhash_MEMLIMIT_SENSITIVE,
      }
    default: {
      const _exhaustive: never = preset
      throw new Error(`unknown Argon2id preset: ${String(_exhaustive)}`)
    }
  }
}

export interface DeriveMasterSecretInput {
  /** User passphrase. UTF-8 encoded internally. */
  passphrase: string
  /** Per-user salt. Must be ≥16 bytes. Generated if not provided. */
  salt?: Uint8Array
  /** Argon2id strength preset. Default: 'moderate'. */
  preset?: Argon2idPreset
}

export interface DeriveMasterSecretOutput {
  /** 32-byte master secret. Treat as the highest-value secret in the system. */
  masterSecret: Uint8Array
  /** Salt used (caller must persist this for re-derivation). */
  salt: Uint8Array
  /** Preset used. Encoded so a future re-derivation produces the same key. */
  preset: Argon2idPreset
}

/**
 * Derive a 32-byte master secret from a passphrase using Argon2id.
 *
 * The host application MUST persist `salt` and `preset` alongside the
 * user's account so that future logins can reproduce the same master
 * secret. The passphrase itself MUST NOT be stored.
 */
export async function deriveMasterSecret(
  input: DeriveMasterSecretInput,
): Promise<DeriveMasterSecretOutput> {
  const sodium = await getSodium()

  if (typeof input.passphrase !== 'string' || input.passphrase.length === 0) {
    throw new Error('deriveMasterSecret: passphrase must be a non-empty string')
  }

  const salt = input.salt ?? randomBytes(ARGON2ID_SALT_BYTES)
  if (salt.length < ARGON2ID_SALT_BYTES) {
    throw new RangeError(
      `deriveMasterSecret: salt must be at least ${ARGON2ID_SALT_BYTES} bytes`,
    )
  }
  // libsodium expects exactly SALTBYTES; if a longer salt is supplied,
  // we domain-separate it through HKDF first to land on 16 bytes.
  let usableSalt = salt
  if (salt.length > ARGON2ID_SALT_BYTES) {
    usableSalt = await hkdfSha256({
      ikm: salt,
      info: 'shieldfive/v1/argon2id/salt-compression',
      length: ARGON2ID_SALT_BYTES,
    })
  }

  const preset = input.preset ?? 'moderate'
  const { opslimit, memlimit } = await resolvePreset(preset)

  const passphraseBytes = new TextEncoder().encode(input.passphrase)

  const derived = sodium.crypto_pwhash(
    MASTER_SECRET_BYTES,
    passphraseBytes,
    usableSalt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  )

  return {
    masterSecret: new Uint8Array(derived),
    salt,
    preset,
  }
}

/**
 * Re-derive the same master secret given the previously stored salt and
 * preset. Convenience wrapper; exactly equivalent to deriveMasterSecret
 * called with the saved parameters.
 */
export async function reDeriveMasterSecret(input: {
  passphrase: string
  salt: Uint8Array
  preset: Argon2idPreset
}): Promise<Uint8Array> {
  const result = await deriveMasterSecret(input)
  return result.masterSecret
}

/**
 * Verify a passphrase against a previously derived master secret without
 * exposing whether the input was wrong before the constant-time compare.
 * Returns true iff the rederived master secret matches.
 */
export async function verifyPassphrase(input: {
  passphrase: string
  salt: Uint8Array
  preset: Argon2idPreset
  expectedMasterSecret: Uint8Array
}): Promise<boolean> {
  const computed = await reDeriveMasterSecret(input)
  if (computed.length !== input.expectedMasterSecret.length) return false
  let diff = 0
  for (let i = 0; i < computed.length; i += 1) {
    diff |= computed[i]! ^ input.expectedMasterSecret[i]!
  }
  return diff === 0
}
