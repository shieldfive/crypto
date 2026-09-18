/**
 * Vault key chain, name envelopes and agent grants.
 *
 * These are the formats the ShieldFive web app already writes to its
 * database, reproduced here so every non-browser client (the MCP server, the
 * CLI, the mobile app) opens them with ONE reviewed implementation instead of
 * each carrying its own copy.
 *
 *   Key chain   folders.fk_wrapped / files.csk_wrapped / files.pqk_fk_wrapped:
 *               AES-256-GCM, 12-byte random IV stored beside the ciphertext,
 *               no AAD. The wrapping key is the parent folder key, or the vault
 *               root key for top-level objects.
 *
 *   Names       files.name / folders.name: a JSON envelope
 *               {v, ct, iv, tag, salt, kdf?}. The AES-256-GCM key is
 *               Argon2id(password = the base64 text of the parent folder key,
 *               salt). v6 additionally authenticates the row UUID as AAD so a
 *               server cannot move a name onto another row.
 *
 *   Agent grant A fresh 32-byte secret, generated in the owner's browser and
 *               never sent to the server, wraps the grant's scope-root keys.
 *               Wrapping key = HKDF-SHA-256(secret, salt = grant id,
 *               info = HKDF_INFO.AGENT_GRANT_WRAP). Every wrap authenticates
 *               the grant id, the object kind and the object id as AAD.
 *
 * Nothing in this module is a new primitive: it composes AES-256-GCM,
 * HKDF-SHA-256, SHA-256 and libsodium's Argon2id13.
 */

import { sha256 } from '@noble/hashes/sha2.js'

import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  concatBytes,
} from '../internal/encoding.js'
import { hkdfSha256 } from '../internal/hkdf.js'
import { getSubtle, randomBytes } from '../internal/runtime.js'
import { getSodium } from '../internal/sodium.js'
import { HKDF_INFO } from '../internal/types.js'

const KEY_BYTES = 32
const IV_BYTES = 12
const TAG_BYTES = 16
const NAME_SALT_BYTES = 16
const TEXT_ENCODER = new TextEncoder()
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true })

/** Raised for any envelope or wrap that does not open. Never carries key bytes. */
export class VaultCryptoError extends Error {
  readonly code:
    | 'unwrap_failed'
    | 'name_decrypt_failed'
    | 'unsupported_envelope'
    | 'invalid_input'
    | 'invalid_connection_string'
  constructor(code: VaultCryptoError['code'], message: string) {
    super(message)
    this.name = 'VaultCryptoError'
    this.code = code
  }
}

function assertKey(key: Uint8Array, what: string): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw new VaultCryptoError('invalid_input', `${what} must be 32 bytes`)
  }
}

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  return getSubtle().importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function aesGcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> }
  if (aad) params.additionalData = aad as Uint8Array<ArrayBuffer>
  const out = await getSubtle().encrypt(
    params,
    await importAesKey(key),
    plaintext as Uint8Array<ArrayBuffer>,
  )
  return new Uint8Array(out)
}

async function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer> }
  if (aad) params.additionalData = aad as Uint8Array<ArrayBuffer>
  try {
    const out = await getSubtle().decrypt(
      params,
      await importAesKey(key),
      ciphertext as Uint8Array<ArrayBuffer>,
    )
    return new Uint8Array(out)
  } catch {
    return null
  }
}

// ──────────────────────────────────────────────────────────────────────
// Key chain
// ──────────────────────────────────────────────────────────────────────

/** A wrapped key as the database stores it: base64 ciphertext+tag and base64 IV. */
export interface WrappedKey {
  wrapped: string
  iv: string
}

/** Wrap a 32-byte key under a 32-byte key (the fk/csk/pqk chain format). */
export async function wrapChainKey(
  wrappingKey: Uint8Array,
  key: Uint8Array,
): Promise<WrappedKey> {
  assertKey(wrappingKey, 'wrappingKey')
  assertKey(key, 'key')
  const iv = randomBytes(IV_BYTES)
  const ct = await aesGcmSeal(wrappingKey, iv, key)
  return { wrapped: bytesToBase64(ct), iv: bytesToBase64(iv) }
}

/** Open one hop of the key chain. Throws `unwrap_failed` on a wrong key or tampering. */
export async function unwrapChainKey(
  wrappingKey: Uint8Array,
  wrapped: WrappedKey,
): Promise<Uint8Array> {
  assertKey(wrappingKey, 'wrappingKey')
  const iv = base64ToBytes(wrapped.iv)
  const ct = base64ToBytes(wrapped.wrapped)
  if (iv.length !== IV_BYTES || ct.length !== KEY_BYTES + TAG_BYTES) {
    throw new VaultCryptoError('unwrap_failed', 'wrapped key has the wrong shape')
  }
  const key = await aesGcmOpen(wrappingKey, iv, ct)
  if (!key) throw new VaultCryptoError('unwrap_failed', 'wrapped key did not open')
  return key
}

// ──────────────────────────────────────────────────────────────────────
// Name envelopes (v4, v6)
// ──────────────────────────────────────────────────────────────────────

export type NameKdfLevel = 'interactive' | 'moderate'

export interface NameEnvelope {
  v: 4 | 6
  ct: string
  iv: string
  tag: string
  salt: string
  kdf?: NameKdfLevel
}

/** Parse a stored name. Returns null for anything that is not a v4/v6 envelope. */
export function parseNameEnvelope(raw: string | null | undefined): NameEnvelope | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 8192) return null
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return null
  }
  if (!value || typeof value !== 'object') return null
  const p = value as Record<string, unknown>
  if (p.v !== 4 && p.v !== 6) return null
  for (const f of ['ct', 'iv', 'tag', 'salt'] as const) {
    if (typeof p[f] !== 'string') return null
  }
  if (p.kdf !== undefined && p.kdf !== 'interactive' && p.kdf !== 'moderate') return null
  const env: NameEnvelope = {
    v: p.v,
    ct: p.ct as string,
    iv: p.iv as string,
    tag: p.tag as string,
    salt: p.salt as string,
  }
  if (p.kdf !== undefined) env.kdf = p.kdf as NameKdfLevel
  return env
}

/**
 * Derive the per-envelope name key. The Argon2id password is the base64 TEXT
 * of the folder key, byte-for-byte what the web app passes to libsodium; the
 * input is already 256 bits of entropy, so the cost level is a compatibility
 * parameter, not a security one.
 */
export async function deriveNameKey(
  folderKey: Uint8Array,
  salt: Uint8Array,
  level: NameKdfLevel,
): Promise<Uint8Array> {
  assertKey(folderKey, 'folderKey')
  if (salt.length !== NAME_SALT_BYTES) {
    throw new VaultCryptoError('invalid_input', 'name salt must be 16 bytes')
  }
  const sodium = await getSodium()
  const ops =
    level === 'interactive'
      ? sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
      : sodium.crypto_pwhash_OPSLIMIT_MODERATE
  const mem =
    level === 'interactive'
      ? sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
      : sodium.crypto_pwhash_MEMLIMIT_MODERATE
  return new Uint8Array(
    sodium.crypto_pwhash(
      KEY_BYTES,
      TEXT_ENCODER.encode(bytesToBase64(folderKey)),
      salt,
      ops,
      mem,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    ),
  )
}

/**
 * Decrypt a v4 or v6 name. `rowId` is the database UUID of the row the name
 * belongs to and is REQUIRED for v6 (it is the AAD). An envelope written
 * without a `kdf` field is tried at interactive, then moderate, which is the
 * web app's own fallback order for a device that cannot know the level.
 */
export async function decryptName(options: {
  envelope: NameEnvelope
  folderKey: Uint8Array
  rowId?: string
}): Promise<string> {
  const { envelope, folderKey, rowId } = options
  if (envelope.v === 6 && !rowId) {
    throw new VaultCryptoError('invalid_input', 'v6 names need the row id')
  }
  const iv = base64ToBytes(envelope.iv)
  const salt = base64ToBytes(envelope.salt)
  const sealed = concatBytes([base64ToBytes(envelope.ct), base64ToBytes(envelope.tag)])
  const aad = envelope.v === 6 ? TEXT_ENCODER.encode(rowId as string) : undefined
  const levels: NameKdfLevel[] = envelope.kdf
    ? [envelope.kdf]
    : ['interactive', 'moderate']
  for (const level of levels) {
    const key = await deriveNameKey(folderKey, salt, level)
    const pt = await aesGcmOpen(key, iv, sealed, aad)
    if (pt) {
      try {
        return TEXT_DECODER.decode(pt)
      } catch {
        break
      }
    }
  }
  throw new VaultCryptoError('name_decrypt_failed', 'name envelope did not open')
}

/**
 * Decrypt a name with an already-derived name key (a grant's `name` wrap),
 * for objects whose parent key the caller does not hold.
 */
export async function decryptNameWithKey(options: {
  envelope: NameEnvelope
  nameKey: Uint8Array
  rowId?: string
}): Promise<string> {
  const { envelope, nameKey, rowId } = options
  assertKey(nameKey, 'nameKey')
  if (envelope.v === 6 && !rowId) {
    throw new VaultCryptoError('invalid_input', 'v6 names need the row id')
  }
  const sealed = concatBytes([base64ToBytes(envelope.ct), base64ToBytes(envelope.tag)])
  const aad = envelope.v === 6 ? TEXT_ENCODER.encode(rowId as string) : undefined
  const pt = await aesGcmOpen(nameKey, base64ToBytes(envelope.iv), sealed, aad)
  if (pt) {
    try {
      return TEXT_DECODER.decode(pt)
    } catch {
      // fall through
    }
  }
  throw new VaultCryptoError('name_decrypt_failed', 'name envelope did not open')
}

/**
 * The name key for one envelope: what an owner wraps as a grant's `name`
 * object. For an envelope without a `kdf` field the level is found by opening
 * it, the same fallback `decryptName` uses, so the wrapped key always works.
 */
export async function deriveNameKeyForEnvelope(options: {
  envelope: NameEnvelope
  parentKey: Uint8Array
  rowId?: string
}): Promise<Uint8Array> {
  const { envelope, parentKey, rowId } = options
  const salt = base64ToBytes(envelope.salt)
  const levels: NameKdfLevel[] = envelope.kdf ? [envelope.kdf] : ['interactive', 'moderate']
  for (const level of levels) {
    const nameKey = await deriveNameKey(parentKey, salt, level)
    try {
      await decryptNameWithKey(rowId === undefined ? { envelope, nameKey } : { envelope, nameKey, rowId })
      return nameKey
    } catch (err) {
      if (!(err instanceof VaultCryptoError) || err.code !== 'name_decrypt_failed') throw err
    }
  }
  throw new VaultCryptoError('name_decrypt_failed', 'name envelope did not open')
}

/** Encrypt a name as a v6 envelope bound to `rowId`, at the web app's default level. */
export async function encryptNameV6(options: {
  name: string
  folderKey: Uint8Array
  rowId: string
}): Promise<NameEnvelope> {
  const { name, folderKey, rowId } = options
  if (typeof name !== 'string' || name.length === 0) {
    throw new VaultCryptoError('invalid_input', 'name must be a non-empty string')
  }
  if (typeof rowId !== 'string' || rowId.length === 0) {
    throw new VaultCryptoError('invalid_input', 'rowId is required')
  }
  const salt = randomBytes(NAME_SALT_BYTES)
  const iv = randomBytes(IV_BYTES)
  const key = await deriveNameKey(folderKey, salt, 'interactive')
  const sealed = await aesGcmSeal(key, iv, TEXT_ENCODER.encode(name), TEXT_ENCODER.encode(rowId))
  return {
    v: 6,
    ct: bytesToBase64(sealed.slice(0, sealed.length - TAG_BYTES)),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(sealed.slice(sealed.length - TAG_BYTES)),
    salt: bytesToBase64(salt),
    kdf: 'interactive',
  }
}

// ──────────────────────────────────────────────────────────────────────
// Agent grants
// ──────────────────────────────────────────────────────────────────────

export const GRANT_CONNECTION_PREFIX = 'sf-grant-v1:'

/**
 * What a grant wrap covers.
 *
 *   folder   a folder key (scope roots, and top-level folders for whole-vault)
 *   file     the key a file's `csk_wrapped` holds: the content key for suites
 *            0x00-0x02, the classical envelope key for 0x03
 *   file_pq  the combined content key of a suite-0x03 file
 *   name     the Argon2id-derived key of ONE name envelope, for objects whose
 *            name is sealed under a key outside the grant (a scope root's own
 *            name, a file at the vault root). Opens that envelope only.
 *
 * `file`, `file_pq` and `name` are only issued for objects whose parent key the
 * grant does not hold; everything below a scope root is reached by the chain.
 */
export type GrantObjectKind = 'folder' | 'file' | 'file_pq' | 'name'
const GRANT_KINDS: ReadonlySet<string> = new Set(['folder', 'file', 'file_pq', 'name'])

export interface GrantCredential {
  grantId: string
  /** Sent to the server as a bearer token. The server stores only its SHA-256. */
  token: Uint8Array
  /** Never leaves the client. Wraps the grant's keys. */
  secret: Uint8Array
  /** SHA-256 of the owner's ML-KEM public key at grant creation, hex. */
  publicKeyFingerprint: string
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function assertUuid(value: string, what: string): void {
  if (typeof value !== 'string' || !UUID_RE.test(value)) {
    throw new VaultCryptoError('invalid_input', `${what} must be a lowercase UUID`)
  }
}

function toBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new VaultCryptoError('invalid_connection_string', 'bad base64url')
  }
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
  return base64ToBytes(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
}

/** SHA-256 of an ML-KEM public key, hex. Pinned in the connection string. */
export function publicKeyFingerprint(mlKemPublicKey: Uint8Array): string {
  return bytesToHex(sha256(mlKemPublicKey))
}

/** Fresh token + secret for a new grant. Call in the owner's unlocked client. */
export function createGrantCredential(options: {
  grantId: string
  mlKemPublicKey: Uint8Array
}): GrantCredential {
  assertUuid(options.grantId, 'grantId')
  return {
    grantId: options.grantId,
    token: randomBytes(KEY_BYTES),
    secret: randomBytes(KEY_BYTES),
    publicKeyFingerprint: publicKeyFingerprint(options.mlKemPublicKey),
  }
}

/** `sf-grant-v1:<grant_id>.<token>.<secret>.<pk_fingerprint>` (base64url, hex). */
export function formatConnectionString(c: GrantCredential): string {
  assertUuid(c.grantId, 'grantId')
  assertKey(c.token, 'token')
  assertKey(c.secret, 'secret')
  if (!/^[0-9a-f]{64}$/.test(c.publicKeyFingerprint)) {
    throw new VaultCryptoError('invalid_input', 'fingerprint must be 64 hex chars')
  }
  return `${GRANT_CONNECTION_PREFIX}${c.grantId}.${toBase64Url(c.token)}.${toBase64Url(c.secret)}.${c.publicKeyFingerprint}`
}

export function parseConnectionString(value: string): GrantCredential {
  const bad = (why: string) => new VaultCryptoError('invalid_connection_string', why)
  if (typeof value !== 'string') throw bad('not a string')
  const trimmed = value.trim()
  if (!trimmed.startsWith(GRANT_CONNECTION_PREFIX)) throw bad('wrong prefix')
  const parts = trimmed.slice(GRANT_CONNECTION_PREFIX.length).split('.')
  if (parts.length !== 4) throw bad('expected four parts')
  const [grantId, tokenPart, secretPart, fingerprint] = parts as [string, string, string, string]
  if (!UUID_RE.test(grantId)) throw bad('bad grant id')
  const token = fromBase64Url(tokenPart)
  const secret = fromBase64Url(secretPart)
  if (token.length !== KEY_BYTES || secret.length !== KEY_BYTES) throw bad('bad key length')
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) throw bad('bad fingerprint')
  return { grantId, token, secret, publicKeyFingerprint: fingerprint }
}

/** The bearer value a client sends. */
export function grantBearerToken(c: Pick<GrantCredential, 'token'>): string {
  return toBase64Url(c.token)
}

/** What the server stores and looks up: SHA-256 of the bearer token's bytes, hex. */
export function hashGrantToken(bearer: string): string {
  const bytes = fromBase64Url(bearer)
  if (bytes.length !== KEY_BYTES) {
    throw new VaultCryptoError('invalid_input', 'bearer token has the wrong length')
  }
  return bytesToHex(sha256(bytes))
}

/** GK = HKDF-SHA-256(secret, salt = utf8(grant id), info = AGENT_GRANT_WRAP). */
export async function deriveGrantWrapKey(
  secret: Uint8Array,
  grantId: string,
): Promise<Uint8Array> {
  assertKey(secret, 'secret')
  assertUuid(grantId, 'grantId')
  return hkdfSha256({
    ikm: secret,
    salt: TEXT_ENCODER.encode(grantId),
    info: HKDF_INFO.AGENT_GRANT_WRAP,
    length: KEY_BYTES,
  })
}

function grantAad(grantId: string, kind: GrantObjectKind, objectId: string): Uint8Array {
  if (!GRANT_KINDS.has(kind)) {
    throw new VaultCryptoError('invalid_input', 'unknown grant object kind')
  }
  assertUuid(grantId, 'grantId')
  assertUuid(objectId, 'objectId')
  return TEXT_ENCODER.encode(`sf-grant-v1|${grantId}|${kind}|${objectId}`)
}

/** Wrap a folder key or file content key for a grant, bound to (grant, kind, object). */
export async function wrapKeyForGrant(options: {
  grantWrapKey: Uint8Array
  grantId: string
  kind: GrantObjectKind
  objectId: string
  key: Uint8Array
}): Promise<WrappedKey> {
  assertKey(options.grantWrapKey, 'grantWrapKey')
  assertKey(options.key, 'key')
  const aad = grantAad(options.grantId, options.kind, options.objectId)
  const iv = randomBytes(IV_BYTES)
  const ct = await aesGcmSeal(options.grantWrapKey, iv, options.key, aad)
  return { wrapped: bytesToBase64(ct), iv: bytesToBase64(iv) }
}

export async function unwrapKeyForGrant(options: {
  grantWrapKey: Uint8Array
  grantId: string
  kind: GrantObjectKind
  objectId: string
  wrapped: WrappedKey
}): Promise<Uint8Array> {
  assertKey(options.grantWrapKey, 'grantWrapKey')
  const aad = grantAad(options.grantId, options.kind, options.objectId)
  const iv = base64ToBytes(options.wrapped.iv)
  const ct = base64ToBytes(options.wrapped.wrapped)
  if (iv.length !== IV_BYTES || ct.length !== KEY_BYTES + TAG_BYTES) {
    throw new VaultCryptoError('unwrap_failed', 'grant wrap has the wrong shape')
  }
  const key = await aesGcmOpen(options.grantWrapKey, iv, ct, aad)
  if (!key) throw new VaultCryptoError('unwrap_failed', 'grant wrap did not open')
  return key
}
