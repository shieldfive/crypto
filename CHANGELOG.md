# Changelog

All notable changes to `@shieldfive/crypto` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0-alpha.12 — 2026-06-09

### Documentation

- README: corrected the test-suite badge and prose from 171 to
  **182** tests. The 11 additional tests are the offline single-file
  decryptor example suite that landed after the badge was last
  refreshed; `npm test` now reports 182/182.
- README: the cipher-suite table and the "four suites" wording now
  match the package exports. Suite 0x04 `aes-gcm-v2` shipped in
  alpha.11 but the README published with that release still listed
  only three suites.
- No source changes in this release — documentation only.

## 1.0.0-alpha.11 — 2026-05-21

### Added

- Cipher suite 0x04 `aes-gcm-v2`: 8-byte HKDF-derived nonce prefix
  + 4-byte BE chunk counter. Widens the cross-file IV-collision
  space from 2^32 to 2^64 while keeping the IV at 12 bytes. v1
  (suite 0x01) stays decrypt-only on the umbrella export.
- Optional sender-attribution signatures (`src/identity/sign.ts`).
  Detached Ed25519 (alg 0x01) over
  `header_unauthenticated_bytes || concat(chunk_macs)`, appended as
  a trailing signature block. Legacy files without the block keep
  decrypting unchanged; the streaming API returns
  `{signature: null}` in that case. Algorithm 0x02 is reserved for
  ML-DSA-65.

### Notes

- Default cipher suite is still PQ-hybrid
  (`SUITE.PQ_HYBRID_XCHACHA_MLKEM1024_V1`). aes-gcm-v2 is opt-in
  via the dedicated subpath import.
- Wire format updates documented in `spec/format-v1.md`.

## [1.0.0-alpha.9] — 2026-05

### Documentation

- docs(security): align SECURITY.md bug-bounty section with
  shieldfive.com/security/bug-bounty. The previous wording said no
  paid bounty existed for the open-source crypto library; the
  operator-run program at shieldfive.com/security/bug-bounty has
  always covered this library with €1000/€500/€250 tiers, so
  SECURITY.md now points there instead of contradicting it. Audit
  punch-list item P0-4.

### Changed

- chore(package): drop "audited-ready" from the npm description.
  No external audit has been performed; the project's audit
  posture is documented in SECURITY.md and continues to be
  "self-reviewed, external audit deferred". Audit punch-list
  item P1-D.
- chore(license): replace "Copyright 2026 ShieldFive" with
  "Copyright 2026 Cho Garcia" in LICENSE (Apache-2.0 attribution
  block). Audit punch-list item P1-C.
- chore(crypto): bump `SHIELDFIVE_CRYPTO_VERSION` constant in
  `src/index.ts` to match the published package version
  (previously stale at 1.0.0-alpha.6).

## [1.0.0-alpha.8] — 2026-05

### Fixed

- fix(pq-hybrid-v1): re-export `generateMlKemKeypair` and
  `deriveMlKemKeypair` from the public subpath so the README quick-start
  compiles.

## [1.0.0-alpha.7] — 2026-05

### Dependencies

- Bump `@noble/post-quantum` from `^0.5.3` (resolved 0.5.4) to
  `^0.6.0` (resolves to 0.6.1). The upstream maintainer self-audit
  released alongside 0.6.1 (April 2026) covers the line ShieldFive
  now ships; the 0.5.x line predates the self-audit. The pinned
  `10_ml_kem_keypair_derivation` test vector in
  `tests/vectors/vectors.json` is byte-identical under 0.6.1 and
  0.5.4 (both implement final FIPS 203 ML-KEM-1024), so no vector
  refresh was required. Wire format and on-disk format are
  byte-identical to prior alphas for the same plaintext, key, and
  file_id inputs.

### Documentation

- README dependency acknowledgement rewritten to accurately
  describe the noble-post-quantum version (^0.6.0, resolving to
  0.6.1) and audit status (upstream self-audit April 2026; no
  independent external audit of either the upstream library or
  the ShieldFive PQ-hybrid construction on top of it). Closes the
  audit punch-list item under `audit/launch/cho-deep-audit-2026-05-19`
  § P0-7.

## [1.0.0-alpha.6] — 2026-05

### Added

- `./streams/pq-hybrid-v1` — `createPqHybridV1DecryptStream` now accepts
  a pre-derived 32-byte combined key K via a new `combinedKey` option,
  in lieu of the `recipientSecretKey` + `envelopeKey` pair. When present,
  the stream skips ML-KEM decapsulation and uses K directly for header
  MAC verification and per-chunk AEAD. The header MAC check still
  cryptographically gates the rest of the stream, so a wrong K fails
  fast. Unblocks Suite 0x03 share-link recipients: they unwrap K under
  the share-link password and never touch ML-KEM material. The
  `PqHybridV1DecryptStreamOptions` type is now a discriminated union
  over the two key-input modes; existing callers that pass
  `recipientSecretKey` + `envelopeKey` are unaffected.
- `./pq-hybrid-v1` (and `pqHybridV1` namespace on the umbrella entry) —
  `decapsulateFromHeader`, `encapsulateForRecipient`, and the
  `PQ_HYBRID_V1_SUITE_PAYLOAD_LENGTH` constant are now publicly
  re-exported from the suite's public surface (`api.ts`). The previous
  release exposed them only on the internal `index.js` path. Lets
  callers that hold the parsed `suite_payload` + KEM material (e.g.,
  share-link generators that need to derive K out-of-band) reach the
  primitives without importing from a deep internal path.

## [1.0.0-alpha.5] — 2026-05

### Added

- `./streams/pq-hybrid-v1` — TransformStream factory for streaming
  encrypt/decrypt under Suite 0x03 (ML-KEM-1024 + XChaCha20-Poly1305).
  Same shape as `./streams/aes-gcm-v1`, suite primitive swapped. Unblocks
  the web app's Phase 3 implementation (Step 14) per the design doc at
  `web/docs/phase3-design.md`.

## [1.0.0-alpha.4] — 2026-05

### Changed

- Threat model (`spec/threat-model.md`) expanded to cover gaps surfaced
  by internal review Task 3: explicit TLS-termination boundary in A2,
  HKDF-structural splice-resistance prose (replacing the incorrect
  "file_id AAD" wording that paralleled Task 1 Finding 1.1),
  legacy-v0 AEAD-invariant carve-out under A2, A3
  current-deployment-status subsection + comparison-table footnote
  (suite `0x03` not yet wired into the web client), new "Trust
  principals" section enumerating share-link recipients, expanded
  metadata-leakage list, and a recovery-key-compromise paragraph
  under "Out of scope". See
  [crypto#4](https://github.com/shieldfive/crypto/commit/bb967cb) for the
  detailed diff. Docs-only; no wire-format or code changes.

## [1.0.0-alpha.3] — 2026-05

### Fixed

- Repository URLs in `package.json`, README, and CHANGELOG now correctly
  point at github.com/shieldfive/crypto. The previous metadata referenced
  github.com/shieldfive-labs, which was never actually created.
  Metadata-only fix; no code changes.

## [1.0.0-alpha.2] — 2026-05

### Fixed

- **Migration bridge accepts the production wire-name `process`.** The
  v0 bridge previously only accepted `{ type: 'chunk_request', index }`
  for chunk requests, but the existing ShieldFive production worker
  uses `{ type: 'process', index }`. This made the bridge silently
  drop messages from unmodified production callers — a Phase 1
  regression. The bridge now accepts both names; `process` is the
  canonical/documented wire name and `chunk_request` is preserved as
  an alias for back-compat. Caught during the Phase 1 migration in
  the ShieldFive main repository before any production rollout.

### Added

- `./package.json` is now exposed via `exports`, so consumers can
  read the package version with `require('@shieldfive/crypto/package.json')`
  or `import('@shieldfive/crypto/package.json')`.

## [1.0.0-alpha.1] — 2026-05

The first public release.

### Added

- **Format v1**: self-describing on-disk encrypted-file format with
  cipher-suite agility, file-id-bound chunk AAD, and authenticated header
  MAC. Specification at `spec/format-v1.md`.
- **Suite 0x01 — `aes-256-gcm-v1`**: WebCrypto-only AES-256-GCM AEAD with
  per-chunk file-id-bound AAD. No WASM dependency.
- **Suite 0x02 — `xchacha20-poly1305-v1`**: XChaCha20-Poly1305 AEAD via
  libsodium (optional peer dependency).
- **Suite 0x03 — `pq-hybrid-xchacha-mlkem1024-v1`** (default): hybrid
  ML-KEM-1024 + XChaCha20-Poly1305 with HKDF-SHA-256 share combination.
- **Legacy v0 reader**: read-only support for the pre-v1 ShieldFive
  production format. There is no v0 writer.
- **Auto-routing decryptor**: `autoDecryptBlob` dispatches to the correct
  suite based on the header.
- **Threat model document** at `spec/threat-model.md`.
- **64 tests** covering: round-trip encryption for all suites, truncation
  detection, per-chunk tampering, header tampering, chunk reordering,
  cross-file splice prevention, wrong-key rejection, and parser edge cases.
- Apache 2.0 license.
- `SECURITY.md` with safe-harbor clause and disclosure timelines.

### Security architecture

- Every chunk's AEAD authenticator binds chunk index, total chunk count,
  final-chunk flag, and file_id. Truncation, reordering, and cross-file
  splice attacks fail at the AEAD layer.
- Header MAC is keyed by HKDF-derived material from the content key. A
  successful header MAC verification proves the right content key was
  supplied before any chunk is processed.
- Post-quantum hybrid construction: an adversary must break both
  ML-KEM-1024 _and_ the classical wrap to compromise a file. ML-KEM-1024
  is FIPS 203 (NIST PQC standard, security category 5).

### Known limitations

- The streaming API (`src/streams/`) is not yet implemented; current API
  reads/writes whole blobs.
- A formal third-party security audit has not yet been performed; planned
  for v1.0.0 stable.
- No file-size obfuscation (padding) is applied. Padding may be added as
  an optional flag in a future minor format version.
- ML-KEM keypair derivation from the user master secret is deterministic
  via HKDF-SHA-256; this is an availability-vs-defense-in-depth tradeoff
  documented in `spec/threat-model.md`.

[1.0.0-alpha.1]: https://github.com/shieldfive/crypto/releases/tag/v1.0.0-alpha.1
[1.0.0-alpha.2]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.1...v1.0.0-alpha.2
[1.0.0-alpha.3]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.2...v1.0.0-alpha.3
[1.0.0-alpha.4]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.3...v1.0.0-alpha.4
[1.0.0-alpha.5]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.4...v1.0.0-alpha.5
[1.0.0-alpha.6]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.5...v1.0.0-alpha.6
[1.0.0-alpha.7]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.6...v1.0.0-alpha.7
[1.0.0-alpha.9]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.8...v1.0.0-alpha.9
[Unreleased]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.7...HEAD
