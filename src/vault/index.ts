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

import { sha256 } from "@noble/hashes/sha2.js";

import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  hexToBytes,
} from "../internal/encoding.js";
import { parseHeader } from "../format/header.js";
import { hmacSha256 } from "../internal/hmac.js";
import { hkdfSha256 } from "../internal/hkdf.js";
import { getSubtle, randomBytes } from "../internal/runtime.js";
import { getSodium } from "../internal/sodium.js";
import { HKDF_INFO } from "../internal/types.js";

const KEY_BYTES = 32;
// The upload-proof frame (see buildUploadProofV3): a version byte, the cipher
// version, then the MAC. The 4-byte big-endian length prefix belongs to the
// container format, not to the proof.
const PROOF_VERSION_V3 = 3;
const CIPHER_VERSION_PQ_HYBRID = 3;
const LENGTH_PREFIX_BYTES = 4;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const NAME_SALT_BYTES = 16;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });

/** Raised for any envelope or wrap that does not open. Never carries key bytes. */
export class VaultCryptoError extends Error {
  readonly code:
    | "unwrap_failed"
    | "name_decrypt_failed"
    | "unsupported_envelope"
    | "invalid_input"
    | "invalid_connection_string";
  constructor(code: VaultCryptoError["code"], message: string) {
    super(message);
    this.name = "VaultCryptoError";
    this.code = code;
  }
}

function assertKey(key: Uint8Array, what: string): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw new VaultCryptoError("invalid_input", `${what} must be 32 bytes`);
  }
}

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  return getSubtle().importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

async function aesGcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const params: AesGcmParams = {
    name: "AES-GCM",
    iv: iv as Uint8Array<ArrayBuffer>,
  };
  if (aad) params.additionalData = aad as Uint8Array<ArrayBuffer>;
  const out = await getSubtle().encrypt(
    params,
    await importAesKey(key),
    plaintext as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(out);
}

async function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array | null> {
  const params: AesGcmParams = {
    name: "AES-GCM",
    iv: iv as Uint8Array<ArrayBuffer>,
  };
  if (aad) params.additionalData = aad as Uint8Array<ArrayBuffer>;
  try {
    const out = await getSubtle().decrypt(
      params,
      await importAesKey(key),
      ciphertext as Uint8Array<ArrayBuffer>,
    );
    return new Uint8Array(out);
  } catch {
    return null;
  }
}

// ──────────────────────────────────────────────────────────────────────
// Key chain
// ──────────────────────────────────────────────────────────────────────

/** A wrapped key as the database stores it: base64 ciphertext+tag and base64 IV. */
export interface WrappedKey {
  wrapped: string;
  iv: string;
}

/** Wrap a 32-byte key under a 32-byte key (the fk/csk/pqk chain format). */
export async function wrapChainKey(
  wrappingKey: Uint8Array,
  key: Uint8Array,
): Promise<WrappedKey> {
  assertKey(wrappingKey, "wrappingKey");
  assertKey(key, "key");
  const iv = randomBytes(IV_BYTES);
  const ct = await aesGcmSeal(wrappingKey, iv, key);
  return { wrapped: bytesToBase64(ct), iv: bytesToBase64(iv) };
}

/** Open one hop of the key chain. Throws `unwrap_failed` on a wrong key or tampering. */
export async function unwrapChainKey(
  wrappingKey: Uint8Array,
  wrapped: WrappedKey,
): Promise<Uint8Array> {
  assertKey(wrappingKey, "wrappingKey");
  const iv = base64ToBytes(wrapped.iv);
  const ct = base64ToBytes(wrapped.wrapped);
  if (iv.length !== IV_BYTES || ct.length !== KEY_BYTES + TAG_BYTES) {
    throw new VaultCryptoError(
      "unwrap_failed",
      "wrapped key has the wrong shape",
    );
  }
  const key = await aesGcmOpen(wrappingKey, iv, ct);
  if (!key)
    throw new VaultCryptoError("unwrap_failed", "wrapped key did not open");
  return key;
}

// ──────────────────────────────────────────────────────────────────────
// Name envelopes (v4, v6)
// ──────────────────────────────────────────────────────────────────────

export type NameKdfLevel = "interactive" | "moderate";

export interface NameEnvelope {
  v: 4 | 6;
  ct: string;
  iv: string;
  tag: string;
  salt: string;
  kdf?: NameKdfLevel;
}

/** Parse a stored name. Returns null for anything that is not a v4/v6 envelope. */
export function parseNameEnvelope(
  raw: string | null | undefined,
): NameEnvelope | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 8192)
    return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const p = value as Record<string, unknown>;
  if (p.v !== 4 && p.v !== 6) return null;
  for (const f of ["ct", "iv", "tag", "salt"] as const) {
    if (typeof p[f] !== "string") return null;
  }
  if (p.kdf !== undefined && p.kdf !== "interactive" && p.kdf !== "moderate")
    return null;
  const env: NameEnvelope = {
    v: p.v,
    ct: p.ct as string,
    iv: p.iv as string,
    tag: p.tag as string,
    salt: p.salt as string,
  };
  if (p.kdf !== undefined) env.kdf = p.kdf as NameKdfLevel;
  return env;
}

const NAME_IV_BYTES = 12;
const NAME_TAG_BYTES = 16;

/** Decode one base64 envelope field, inside the module's error contract. */
function envelopeField(
  value: string,
  what: string,
  length?: number,
): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(value);
  } catch {
    throw new VaultCryptoError("unsupported_envelope", `${what} is not base64`);
  }
  if (length !== undefined && bytes.length !== length) {
    throw new VaultCryptoError(
      "unsupported_envelope",
      `${what} must be ${length} bytes`,
    );
  }
  return bytes;
}

/**
 * The levels a reader tries, cheapest first. The stored `kdf` is data the
 * server can rewrite, so it may only narrow the search, never raise the cost:
 * "interactive" means interactive alone, anything else means interactive then
 * moderate. An honest envelope relabelled "moderate" still opens at the
 * interactive cost, and no envelope costs more than one legacy (kdf-less)
 * envelope already did.
 */
function nameKdfLevels(envelope: NameEnvelope): NameKdfLevel[] {
  return envelope.kdf === "interactive"
    ? ["interactive"]
    : ["interactive", "moderate"];
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
  assertKey(folderKey, "folderKey");
  if (salt.length !== NAME_SALT_BYTES) {
    throw new VaultCryptoError("invalid_input", "name salt must be 16 bytes");
  }
  const sodium = await getSodium();
  const ops =
    level === "interactive"
      ? sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
      : sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const mem =
    level === "interactive"
      ? sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
      : sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  return new Uint8Array(
    sodium.crypto_pwhash(
      KEY_BYTES,
      TEXT_ENCODER.encode(bytesToBase64(folderKey)),
      salt,
      ops,
      mem,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    ),
  );
}

/**
 * Decrypt a v4 or v6 name. `rowId` is the database UUID of the row the name
 * belongs to and is REQUIRED for v6 (it is the AAD). An envelope written
 * without a `kdf` field is tried at interactive, then moderate, which is the
 * web app's own fallback order for a device that cannot know the level. A
 * stored `kdf` never raises the cost (see nameKdfLevels).
 */
export async function decryptName(options: {
  envelope: NameEnvelope;
  folderKey: Uint8Array;
  rowId?: string;
}): Promise<string> {
  const { envelope, folderKey, rowId } = options;
  if (envelope.v === 6 && !rowId) {
    throw new VaultCryptoError("invalid_input", "v6 names need the row id");
  }
  const iv = envelopeField(envelope.iv, "iv", NAME_IV_BYTES);
  const salt = envelopeField(envelope.salt, "salt", NAME_SALT_BYTES);
  const sealed = concatBytes([
    envelopeField(envelope.ct, "ct"),
    envelopeField(envelope.tag, "tag", NAME_TAG_BYTES),
  ]);
  const aad =
    envelope.v === 6 ? TEXT_ENCODER.encode(rowId as string) : undefined;
  for (const level of nameKdfLevels(envelope)) {
    const key = await deriveNameKey(folderKey, salt, level);
    const pt = await aesGcmOpen(key, iv, sealed, aad);
    if (pt) {
      try {
        return TEXT_DECODER.decode(pt);
      } catch {
        break;
      }
    }
  }
  throw new VaultCryptoError(
    "name_decrypt_failed",
    "name envelope did not open",
  );
}

/**
 * Decrypt a name with an already-derived name key (a grant's `name` wrap),
 * for objects whose parent key the caller does not hold.
 */
export async function decryptNameWithKey(options: {
  envelope: NameEnvelope;
  nameKey: Uint8Array;
  rowId?: string;
}): Promise<string> {
  const { envelope, nameKey, rowId } = options;
  assertKey(nameKey, "nameKey");
  if (envelope.v === 6 && !rowId) {
    throw new VaultCryptoError("invalid_input", "v6 names need the row id");
  }
  const sealed = concatBytes([
    envelopeField(envelope.ct, "ct"),
    envelopeField(envelope.tag, "tag", NAME_TAG_BYTES),
  ]);
  const aad =
    envelope.v === 6 ? TEXT_ENCODER.encode(rowId as string) : undefined;
  const iv = envelopeField(envelope.iv, "iv", NAME_IV_BYTES);
  const pt = await aesGcmOpen(nameKey, iv, sealed, aad);
  if (pt) {
    try {
      return TEXT_DECODER.decode(pt);
    } catch {
      // fall through
    }
  }
  throw new VaultCryptoError(
    "name_decrypt_failed",
    "name envelope did not open",
  );
}

/**
 * The name key for one envelope: what an owner wraps as a grant's `name`
 * object. For an envelope without a `kdf` field the level is found by opening
 * it, the same fallback `decryptName` uses, so the wrapped key always works.
 */
export async function deriveNameKeyForEnvelope(options: {
  envelope: NameEnvelope;
  parentKey: Uint8Array;
  rowId?: string;
}): Promise<Uint8Array> {
  const { envelope, parentKey, rowId } = options;
  const salt = envelopeField(envelope.salt, "salt", NAME_SALT_BYTES);
  for (const level of nameKdfLevels(envelope)) {
    const nameKey = await deriveNameKey(parentKey, salt, level);
    try {
      await decryptNameWithKey(
        rowId === undefined
          ? { envelope, nameKey }
          : { envelope, nameKey, rowId },
      );
      return nameKey;
    } catch (err) {
      if (
        !(err instanceof VaultCryptoError) ||
        err.code !== "name_decrypt_failed"
      )
        throw err;
    }
  }
  throw new VaultCryptoError(
    "name_decrypt_failed",
    "name envelope did not open",
  );
}

/** Encrypt a name as a v6 envelope bound to `rowId`, at the web app's default level. */
export async function encryptNameV6(options: {
  name: string;
  folderKey: Uint8Array;
  rowId: string;
}): Promise<NameEnvelope> {
  const { name, folderKey, rowId } = options;
  if (typeof name !== "string" || name.length === 0) {
    throw new VaultCryptoError(
      "invalid_input",
      "name must be a non-empty string",
    );
  }
  if (typeof rowId !== "string" || rowId.length === 0) {
    throw new VaultCryptoError("invalid_input", "rowId is required");
  }
  const salt = randomBytes(NAME_SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveNameKey(folderKey, salt, "interactive");
  const sealed = await aesGcmSeal(
    key,
    iv,
    TEXT_ENCODER.encode(name),
    TEXT_ENCODER.encode(rowId),
  );
  return {
    v: 6,
    ct: bytesToBase64(sealed.slice(0, sealed.length - TAG_BYTES)),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(sealed.slice(sealed.length - TAG_BYTES)),
    salt: bytesToBase64(salt),
    kdf: "interactive",
  };
}

// ──────────────────────────────────────────────────────────────────────
// Agent grants
// ──────────────────────────────────────────────────────────────────────

export const GRANT_CONNECTION_PREFIX = "sf-grant-v1:";

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
export type GrantObjectKind = "folder" | "file" | "file_pq" | "name";
const GRANT_KINDS: ReadonlySet<string> = new Set([
  "folder",
  "file",
  "file_pq",
  "name",
]);

export interface GrantCredential {
  grantId: string;
  /** Sent to the server as a bearer token. The server stores only its SHA-256. */
  token: Uint8Array;
  /** Never leaves the client. Wraps the grant's keys. */
  secret: Uint8Array;
  /** SHA-256 of the owner's ML-KEM public key at grant creation, hex. */
  publicKeyFingerprint: string;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function assertUuid(value: string, what: string): void {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new VaultCryptoError(
      "invalid_input",
      `${what} must be a lowercase UUID`,
    );
  }
}

function toBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new VaultCryptoError("invalid_connection_string", "bad base64url");
  }
  if (value.length % 4 === 1) {
    throw new VaultCryptoError(
      "invalid_connection_string",
      "bad base64url length",
    );
  }
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  } catch {
    throw new VaultCryptoError("invalid_connection_string", "bad base64url");
  }
  // One value, one spelling: reject encodings whose final character carries
  // non-zero padding bits, which decoders silently discard.
  if (toBase64Url(bytes) !== value) {
    throw new VaultCryptoError(
      "invalid_connection_string",
      "non-canonical base64url",
    );
  }
  return bytes;
}

/** SHA-256 of an ML-KEM public key, hex. Pinned in the connection string. */
export function publicKeyFingerprint(mlKemPublicKey: Uint8Array): string {
  return bytesToHex(sha256(mlKemPublicKey));
}

/**
 * The upload proof for a PQ-hybrid (Suite 0x03) object, in the frame the
 * ShieldFive server verifies:
 *
 *   base64( [0x03][0x03] || HMAC-SHA256(proofKey, [0x03][0x03] || header || chunk_0) )
 *
 * `chunk_0` is the first frame INCLUDING its 4-byte big-endian length prefix.
 * The server re-reads exactly those ranges from storage and recomputes the MAC,
 * so a matching proof says the header and first chunk frame storage holds are
 * the ones the client encrypted. It commits to nothing after chunk_0: a
 * truncated or replaced tail still verifies, and is caught only when the
 * client decrypts (each chunk is AEAD-authenticated). It says nothing about
 * the plaintext.
 *
 * It lives here because it is a keyed construction over ShieldFive's own
 * container format, and the clients that produce it (the web app, and the MCP
 * server's upload path) must produce byte-identical frames. A second
 * hand-written implementation is how the two silently diverge.
 */
export async function buildUploadProofV3(options: {
  /** The per-upload proof key the server issued, hex. */
  proofKeyHex: string;
  /** The complete ciphertext, or at least header + first chunk frame. */
  ciphertext: Uint8Array;
}): Promise<string> {
  const { proofKeyHex, ciphertext } = options;
  if (!/^[0-9a-f]{64}$/i.test(proofKeyHex)) {
    throw new VaultCryptoError(
      "invalid_input",
      "proofKeyHex must be 32 bytes of hex",
    );
  }
  let header: ReturnType<typeof parseHeader>;
  try {
    header = parseHeader(ciphertext);
  } catch {
    throw new VaultCryptoError(
      "invalid_input",
      "ciphertext does not start with a valid header",
    );
  }
  const lengthOffset = header.headerLength;
  if (ciphertext.length < lengthOffset + LENGTH_PREFIX_BYTES) {
    throw new VaultCryptoError(
      "invalid_input",
      "ciphertext is shorter than its header",
    );
  }
  const view = new DataView(
    ciphertext.buffer,
    ciphertext.byteOffset,
    ciphertext.byteLength,
  );
  const chunkZeroLength = view.getUint32(lengthOffset, false);
  const end = lengthOffset + LENGTH_PREFIX_BYTES + chunkZeroLength;
  // Match the server verifier's bounds: a frame is at least one ciphertext
  // byte plus the 16-byte tag, and at most chunkSize plus the tag.
  if (
    chunkZeroLength < 1 + TAG_BYTES ||
    chunkZeroLength > header.chunkSize + TAG_BYTES
  ) {
    throw new VaultCryptoError(
      "invalid_input",
      "first chunk length is outside the valid frame range",
    );
  }
  if (ciphertext.length < end) {
    throw new VaultCryptoError(
      "invalid_input",
      "ciphertext is missing its first chunk",
    );
  }

  const prefix = Uint8Array.from([PROOF_VERSION_V3, CIPHER_VERSION_PQ_HYBRID]);
  const macPayload = new Uint8Array(prefix.length + end);
  macPayload.set(prefix, 0);
  macPayload.set(ciphertext.subarray(0, end), prefix.length);

  const mac = await hmacSha256(hexToBytes(proofKeyHex), macPayload);
  const frame = new Uint8Array(prefix.length + mac.length);
  frame.set(prefix, 0);
  frame.set(mac, prefix.length);
  return bytesToBase64(frame);
}

/** Fresh token + secret for a new grant. Call in the owner's unlocked client. */
export function createGrantCredential(options: {
  grantId: string;
  mlKemPublicKey: Uint8Array;
}): GrantCredential {
  assertUuid(options.grantId, "grantId");
  return {
    grantId: options.grantId,
    token: randomBytes(KEY_BYTES),
    secret: randomBytes(KEY_BYTES),
    publicKeyFingerprint: publicKeyFingerprint(options.mlKemPublicKey),
  };
}

/** `sf-grant-v1:<grant_id>.<token>.<secret>.<pk_fingerprint>` (base64url, hex). */
export function formatConnectionString(c: GrantCredential): string {
  assertUuid(c.grantId, "grantId");
  assertKey(c.token, "token");
  assertKey(c.secret, "secret");
  if (!/^[0-9a-f]{64}$/.test(c.publicKeyFingerprint)) {
    throw new VaultCryptoError(
      "invalid_input",
      "fingerprint must be 64 hex chars",
    );
  }
  return `${GRANT_CONNECTION_PREFIX}${c.grantId}.${toBase64Url(c.token)}.${toBase64Url(c.secret)}.${c.publicKeyFingerprint}`;
}

export function parseConnectionString(value: string): GrantCredential {
  const bad = (why: string) =>
    new VaultCryptoError("invalid_connection_string", why);
  if (typeof value !== "string") throw bad("not a string");
  const trimmed = value.trim();
  if (!trimmed.startsWith(GRANT_CONNECTION_PREFIX)) throw bad("wrong prefix");
  const parts = trimmed.slice(GRANT_CONNECTION_PREFIX.length).split(".");
  if (parts.length !== 4) throw bad("expected four parts");
  const [grantId, tokenPart, secretPart, fingerprint] = parts as [
    string,
    string,
    string,
    string,
  ];
  if (!UUID_RE.test(grantId)) throw bad("bad grant id");
  const token = fromBase64Url(tokenPart);
  const secret = fromBase64Url(secretPart);
  if (token.length !== KEY_BYTES || secret.length !== KEY_BYTES)
    throw bad("bad key length");
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) throw bad("bad fingerprint");
  return { grantId, token, secret, publicKeyFingerprint: fingerprint };
}

/** The bearer value a client sends. */
export function grantBearerToken(c: Pick<GrantCredential, "token">): string {
  return toBase64Url(c.token);
}

/** What the server stores and looks up: SHA-256 of the bearer token's bytes, hex. */
export function hashGrantToken(bearer: string): string {
  const bytes = fromBase64Url(bearer);
  if (bytes.length !== KEY_BYTES) {
    throw new VaultCryptoError(
      "invalid_input",
      "bearer token has the wrong length",
    );
  }
  return bytesToHex(sha256(bytes));
}

/** GK = HKDF-SHA-256(secret, salt = utf8(grant id), info = AGENT_GRANT_WRAP). */
export async function deriveGrantWrapKey(
  secret: Uint8Array,
  grantId: string,
): Promise<Uint8Array> {
  assertKey(secret, "secret");
  assertUuid(grantId, "grantId");
  return hkdfSha256({
    ikm: secret,
    salt: TEXT_ENCODER.encode(grantId),
    info: HKDF_INFO.AGENT_GRANT_WRAP,
    length: KEY_BYTES,
  });
}

function grantAad(
  grantId: string,
  kind: GrantObjectKind,
  objectId: string,
): Uint8Array {
  if (!GRANT_KINDS.has(kind)) {
    throw new VaultCryptoError("invalid_input", "unknown grant object kind");
  }
  assertUuid(grantId, "grantId");
  assertUuid(objectId, "objectId");
  return TEXT_ENCODER.encode(`sf-grant-v1|${grantId}|${kind}|${objectId}`);
}

/** Wrap a folder key or file content key for a grant, bound to (grant, kind, object). */
export async function wrapKeyForGrant(options: {
  grantWrapKey: Uint8Array;
  grantId: string;
  kind: GrantObjectKind;
  objectId: string;
  key: Uint8Array;
}): Promise<WrappedKey> {
  assertKey(options.grantWrapKey, "grantWrapKey");
  assertKey(options.key, "key");
  const aad = grantAad(options.grantId, options.kind, options.objectId);
  const iv = randomBytes(IV_BYTES);
  const ct = await aesGcmSeal(options.grantWrapKey, iv, options.key, aad);
  return { wrapped: bytesToBase64(ct), iv: bytesToBase64(iv) };
}

export async function unwrapKeyForGrant(options: {
  grantWrapKey: Uint8Array;
  grantId: string;
  kind: GrantObjectKind;
  objectId: string;
  wrapped: WrappedKey;
}): Promise<Uint8Array> {
  assertKey(options.grantWrapKey, "grantWrapKey");
  const aad = grantAad(options.grantId, options.kind, options.objectId);
  const iv = base64ToBytes(options.wrapped.iv);
  const ct = base64ToBytes(options.wrapped.wrapped);
  if (iv.length !== IV_BYTES || ct.length !== KEY_BYTES + TAG_BYTES) {
    throw new VaultCryptoError(
      "unwrap_failed",
      "grant wrap has the wrong shape",
    );
  }
  const key = await aesGcmOpen(options.grantWrapKey, iv, ct, aad);
  if (!key)
    throw new VaultCryptoError("unwrap_failed", "grant wrap did not open");
  return key;
}

// ──────────────────────────────────────────────────────────────────────
// The owner's copy of a grant secret, bound to the grant's scope
// ──────────────────────────────────────────────────────────────────────

/** What a grant covers, as the owner decided it when creating the grant. */
export interface GrantScope {
  grantId: string;
  scopeAll: boolean;
  includeMedia: boolean;
  /** Scope-root folder ids (empty for a whole-vault grant). */
  rootIds: readonly string[];
  /** The grant's own trash folder, or null for a read-only grant. */
  trashFolderId: string | null;
  /** Top-level folders a whole-vault grant must never cover (the Bin, and Media unless opted in). */
  excludedIds: readonly string[];
  /**
   * keyFingerprint() of those folders' keys. A server can relabel a row with
   * another folder's wrapped key; it cannot change a key's fingerprint, so the
   * owner's browser refuses to hand an excluded folder's key to the grant under
   * any id.
   */
  excludedKeyFingerprints: readonly string[];
}

/** SHA-256 of a 32-byte key, hex. Reveals nothing usable about a random key. */
export function keyFingerprint(key: Uint8Array): string {
  assertKey(key, "key");
  return bytesToHex(sha256(key));
}

/** A canonical, order-independent string for a scope. Any change to the scope changes it. */
export function canonicalGrantScope(scope: GrantScope): string {
  assertUuid(scope.grantId, "grantId");
  const ids = (list: readonly string[], what: string) => {
    for (const id of list) assertUuid(id, what);
    return [...new Set(list)].sort().join(",");
  };
  if (scope.trashFolderId !== null)
    assertUuid(scope.trashFolderId, "trashFolderId");
  return [
    "sf-grant-scope-v1",
    scope.grantId,
    `all=${scope.scopeAll ? 1 : 0}`,
    `media=${scope.includeMedia ? 1 : 0}`,
    `roots=${ids(scope.rootIds, "rootIds")}`,
    `trash=${scope.trashFolderId ?? "-"}`,
    `excluded=${ids(scope.excludedIds, "excludedIds")}`,
    `excludedKeys=${[...new Set(scope.excludedKeyFingerprints)]
      .map((f) => {
        if (!/^[0-9a-f]{64}$/.test(f))
          throw new VaultCryptoError("invalid_input", "bad key fingerprint");
        return f;
      })
      .sort()
      .join(",")}`,
  ].join("|");
}

async function grantSecretKey(
  rootKey: Uint8Array,
  grantId: string,
): Promise<Uint8Array> {
  assertKey(rootKey, "rootKey");
  assertUuid(grantId, "grantId");
  return hkdfSha256({
    ikm: rootKey,
    salt: TEXT_ENCODER.encode(grantId),
    info: HKDF_INFO.AGENT_GRANT_SECRET,
    length: KEY_BYTES,
  });
}

/**
 * Wrap a grant secret for the owner: AES-256-GCM under HKDF(RK, grant id,
 * AGENT_GRANT_SECRET), with the canonical scope as AAD. Only the owner's
 * vault root key opens it, and only for exactly this scope.
 */
export async function wrapGrantSecret(options: {
  rootKey: Uint8Array;
  scope: GrantScope;
  secret: Uint8Array;
}): Promise<WrappedKey> {
  assertKey(options.secret, "secret");
  const key = await grantSecretKey(options.rootKey, options.scope.grantId);
  const iv = randomBytes(IV_BYTES);
  const ct = await aesGcmSeal(
    key,
    iv,
    options.secret,
    TEXT_ENCODER.encode(canonicalGrantScope(options.scope)),
  );
  return { wrapped: bytesToBase64(ct), iv: bytesToBase64(iv) };
}

/** Open the owner's copy of a grant secret. Fails if the scope differs in any way from the one it was wrapped for. */
export async function unwrapGrantSecret(options: {
  rootKey: Uint8Array;
  scope: GrantScope;
  wrapped: WrappedKey;
}): Promise<Uint8Array> {
  const key = await grantSecretKey(options.rootKey, options.scope.grantId);
  const iv = base64ToBytes(options.wrapped.iv);
  const ct = base64ToBytes(options.wrapped.wrapped);
  if (iv.length !== IV_BYTES || ct.length !== KEY_BYTES + TAG_BYTES) {
    throw new VaultCryptoError(
      "unwrap_failed",
      "grant secret wrap has the wrong shape",
    );
  }
  const secret = await aesGcmOpen(
    key,
    iv,
    ct,
    TEXT_ENCODER.encode(canonicalGrantScope(options.scope)),
  );
  if (!secret)
    throw new VaultCryptoError(
      "unwrap_failed",
      "grant secret did not open for this scope",
    );
  return secret;
}
