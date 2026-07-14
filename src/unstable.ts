/**
 * Unstable API surface.
 *
 * NOT covered by @shieldfive/crypto's semantic-versioning stability promise.
 * Everything re-exported here — the low-level v1 header builders/parser and
 * the runtime crypto helpers — may change signature or be removed in ANY
 * release, including minor and patch. It is exposed for advanced callers who
 * reimplement or introspect the wire format and accept that churn.
 *
 * Application code should prefer the stable per-suite APIs
 * (`@shieldfive/crypto/pq-hybrid-v1`, `/aes-gcm-v2`, etc.).
 */

// Low-level v1 header construction / parsing.
export {
  buildAuthenticatedHeader,
  buildChunkAad,
  buildHeaderUnauthenticated,
  deriveHeaderMacKey,
  parseHeader,
  verifyHeaderMac,
} from './format/header.js'

// Runtime crypto helpers.
export { constantTimeEqual, randomBytes, zeroize } from './internal/runtime.js'
