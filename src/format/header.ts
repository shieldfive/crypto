/**
 * v1 header builder and parser.
 *
 * The header is constructed without the MAC, then the MAC is computed
 * with the content key, then the MAC is appended. On decode, the parser
 * reads everything up to (but not including) the MAC, then the caller
 * verifies the MAC before trusting any field.
 */

import {
  CHUNK_AAD_DOMAIN,
  CHUNK_AAD_LENGTH,
  FORMAT_MAGIC,
  FORMAT_MAGIC_LENGTH,
  HEADER_FIXED_PREFIX_LENGTH,
  HEADER_SIZES,
  HKDF_INFO,
  MAX_CHUNK_SIZE,
  MAX_TOTAL_CHUNKS,
  type ParsedHeader,
  SUITE,
  type SuiteId,
} from '../internal/types.js'
import {
  concatBytes,
  readUint16BE,
  readUint32BE,
  readUint64BE,
  uint16BE,
  uint32BE,
  uint64BE,
} from '../internal/encoding.js'
import { hkdfSha256 } from '../internal/hkdf.js'
import { hmacSha256, hmacSha256Verify } from '../internal/hmac.js'

const TEXT_ENCODER = new TextEncoder()
const CHUNK_AAD_DOMAIN_BYTES = TEXT_ENCODER.encode(CHUNK_AAD_DOMAIN)

const VALID_SUITES = new Set<number>(Object.values(SUITE))

export interface HeaderInputs {
  suite: SuiteId
  fileId: Uint8Array
  chunkSize: number
  totalChunks: number
  plaintextSize: number
  suitePayload: Uint8Array
}

/**
 * Build the unauthenticated header bytes (everything before the MAC).
 * The caller appends the MAC after deriving header_mac_key.
 */
export function buildHeaderUnauthenticated(input: HeaderInputs): Uint8Array {
  validateHeaderInputs(input)
  return concatBytes([
    FORMAT_MAGIC,
    new Uint8Array([input.suite]),
    new Uint8Array([0x00]), // flags reserved
    input.fileId,
    uint32BE(input.chunkSize),
    uint64BE(input.totalChunks),
    uint64BE(input.plaintextSize),
    uint16BE(input.suitePayload.length),
    input.suitePayload,
  ])
}

/**
 * Derive the per-file header MAC key from the content key + file_id.
 */
export async function deriveHeaderMacKey(
  contentKey: Uint8Array,
  fileId: Uint8Array,
): Promise<Uint8Array> {
  return hkdfSha256({
    ikm: contentKey,
    salt: fileId,
    info: HKDF_INFO.HEADER_MAC,
    length: 32,
  })
}

/**
 * Build a complete authenticated header. `contentKey` is the suite-specific
 * key used to authenticate the header. For the PQ-hybrid suite this is the
 * combined key K (post-HKDF); for AES-GCM and XChaCha suites this is the
 * raw 32-byte content key.
 */
export async function buildAuthenticatedHeader(
  input: HeaderInputs,
  contentKey: Uint8Array,
): Promise<Uint8Array> {
  const unauthenticated = buildHeaderUnauthenticated(input)
  const macKey = await deriveHeaderMacKey(contentKey, input.fileId)
  const mac = await hmacSha256(macKey, unauthenticated)
  return concatBytes([unauthenticated, mac])
}

/**
 * Parse a header from a byte slice. Returns the parsed fields and the
 * total bytes consumed. Does NOT verify the MAC — callers must call
 * `verifyHeaderMac` separately, after deriving the key.
 *
 * Two-phase parse-then-verify keeps the parser usable for tooling that
 * inspects encrypted files without holding the key.
 *
 * parseHeader does not verify the header MAC. For non-KEM suites
 * (0x01 aes-gcm-v1, 0x02 xchacha-v1), callers MUST call
 * verifyHeaderMac BEFORE doing anything with parsed.suitePayload,
 * including length checks, field extraction, or downstream parsing.
 * KEM suites (0x03 pq-hybrid-v1) cannot follow this rule by
 * construction; see spec/format-v1.md § "0x03 — pq-hybrid" for the
 * required ordering and security argument.
 *
 * Cross-field consistency (totalChunks / chunkSize / plaintextSize) is
 * enforced here via `assertHeaderConsistency`. The same helper runs in
 * `validateHeaderInputs` so encode and decode share one source of
 * truth; both paths MUST stay in sync.
 */
export function parseHeader(input: Uint8Array): ParsedHeader & {
  unauthenticatedBytes: Uint8Array
  mac: Uint8Array
} {
  if (input.length < HEADER_FIXED_PREFIX_LENGTH + HEADER_SIZES.HEADER_MAC) {
    throw new HeaderError('header_too_short')
  }

  // Magic
  for (let i = 0; i < FORMAT_MAGIC_LENGTH; i += 1) {
    if (input[i] !== FORMAT_MAGIC[i]) {
      throw new HeaderError('bad_magic')
    }
  }

  let offset = FORMAT_MAGIC_LENGTH

  const suite = input[offset]!
  offset += HEADER_SIZES.SUITE
  if (!VALID_SUITES.has(suite)) {
    throw new HeaderError('unknown_suite')
  }

  const flags = input[offset]!
  offset += HEADER_SIZES.FLAGS
  if (flags !== 0x00) {
    throw new HeaderError('reserved_flags_set')
  }

  const fileId = input.slice(offset, offset + HEADER_SIZES.FILE_ID)
  offset += HEADER_SIZES.FILE_ID

  const chunkSize = readUint32BE(input, offset)
  offset += HEADER_SIZES.CHUNK_SIZE
  if (chunkSize === 0 || chunkSize > MAX_CHUNK_SIZE) {
    throw new HeaderError('chunk_size_out_of_range')
  }

  const totalChunks = readUint64BE(input, offset)
  offset += HEADER_SIZES.TOTAL_CHUNKS
  if (totalChunks > MAX_TOTAL_CHUNKS) {
    throw new HeaderError('total_chunks_out_of_range')
  }

  const plaintextSize = readUint64BE(input, offset)
  offset += HEADER_SIZES.PLAINTEXT_SIZE

  assertHeaderConsistency({ chunkSize, totalChunks, plaintextSize })

  const suitePayloadLen = readUint16BE(input, offset)
  offset += HEADER_SIZES.SUITE_PAYLOAD_LEN

  if (offset + suitePayloadLen + HEADER_SIZES.HEADER_MAC > input.length) {
    throw new HeaderError('header_truncated')
  }

  const suitePayload = input.slice(offset, offset + suitePayloadLen)
  offset += suitePayloadLen

  const macStart = offset
  const mac = input.slice(macStart, macStart + HEADER_SIZES.HEADER_MAC)
  offset += HEADER_SIZES.HEADER_MAC

  const unauthenticatedBytes = input.slice(0, macStart)

  return {
    suite: suite as SuiteId,
    flags,
    fileId,
    chunkSize,
    totalChunks,
    plaintextSize,
    suitePayload,
    headerLength: offset,
    unauthenticatedBytes,
    mac,
  }
}

/**
 * Verify the parsed header's MAC under the supplied content key.
 * Throws on failure; returns the parsed header on success.
 */
export async function verifyHeaderMac(
  parsed: ReturnType<typeof parseHeader>,
  contentKey: Uint8Array,
): Promise<void> {
  const macKey = await deriveHeaderMacKey(contentKey, parsed.fileId)
  const ok = await hmacSha256Verify(
    macKey,
    parsed.unauthenticatedBytes,
    parsed.mac,
  )
  if (!ok) {
    throw new HeaderError('header_mac_mismatch')
  }
}

/**
 * Build the AAD bound into every chunk's AEAD: domain || index || total || is_final.
 */
export function buildChunkAad(
  chunkIndex: number,
  totalChunks: number,
  isFinal: boolean,
): Uint8Array {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
    throw new RangeError('buildChunkAad: chunkIndex out of range')
  }
  if (!Number.isSafeInteger(totalChunks) || totalChunks < 0) {
    throw new RangeError('buildChunkAad: totalChunks out of range')
  }
  const out = new Uint8Array(CHUNK_AAD_LENGTH)
  out.set(CHUNK_AAD_DOMAIN_BYTES, 0)
  out.set(uint64BE(chunkIndex), CHUNK_AAD_DOMAIN_BYTES.length)
  out.set(uint64BE(totalChunks), CHUNK_AAD_DOMAIN_BYTES.length + 8)
  out[CHUNK_AAD_DOMAIN_BYTES.length + 16] = isFinal ? 0x01 : 0x00
  return out
}

function validateHeaderInputs(input: HeaderInputs): void {
  if (!VALID_SUITES.has(input.suite)) {
    throw new HeaderError('unknown_suite')
  }
  if (!(input.fileId instanceof Uint8Array)) {
    throw new TypeError('fileId must be a Uint8Array')
  }
  if (input.fileId.length !== HEADER_SIZES.FILE_ID) {
    throw new HeaderError('file_id_wrong_length')
  }
  if (
    !Number.isSafeInteger(input.chunkSize) ||
    input.chunkSize <= 0 ||
    input.chunkSize > MAX_CHUNK_SIZE
  ) {
    throw new HeaderError('chunk_size_out_of_range')
  }
  if (
    !Number.isSafeInteger(input.totalChunks) ||
    input.totalChunks < 0 ||
    input.totalChunks > MAX_TOTAL_CHUNKS
  ) {
    throw new HeaderError('total_chunks_out_of_range')
  }
  if (
    !Number.isSafeInteger(input.plaintextSize) ||
    input.plaintextSize < 0
  ) {
    throw new HeaderError('plaintext_size_out_of_range')
  }
  if (!(input.suitePayload instanceof Uint8Array)) {
    throw new TypeError('suitePayload must be a Uint8Array')
  }
  if (input.suitePayload.length > 0xffff) {
    throw new HeaderError('suite_payload_too_large')
  }
  assertHeaderConsistency({
    chunkSize: input.chunkSize,
    totalChunks: input.totalChunks,
    plaintextSize: input.plaintextSize,
  })
}

/**
 * Assert the cross-field invariant tying total_chunks, chunk_size, and
 * plaintext_size together. Shared by `parseHeader` (decode path) and
 * `validateHeaderInputs` (encode path) so both layers reject the same
 * malformed combinations with the same error codes.
 */
function assertHeaderConsistency(fields: {
  chunkSize: number
  totalChunks: number
  plaintextSize: number
}): void {
  const { chunkSize, totalChunks, plaintextSize } = fields
  if (totalChunks === 0 && plaintextSize !== 0) {
    throw new HeaderError('total_chunks_zero_with_plaintext')
  }
  if (totalChunks > 0) {
    const minPlaintext = (totalChunks - 1) * chunkSize + 1
    const maxPlaintext = totalChunks * chunkSize
    if (plaintextSize < minPlaintext || plaintextSize > maxPlaintext) {
      throw new HeaderError('plaintext_size_inconsistent')
    }
  }
}

/** Recognizable error class so callers can catch parse failures specifically */
export class HeaderError extends Error {
  readonly code: string
  constructor(code: string) {
    super(`shieldfive-crypto: header error: ${code}`)
    this.name = 'HeaderError'
    this.code = code
  }
}
