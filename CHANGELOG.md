# Changelog

All notable changes to `@shieldfive/crypto` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security

- **Sender-attribution signatures now commit to ciphertext content, not just
  AEAD tags.** The optional Ed25519 signature block previously signed
  `header_unauthenticated_bytes || concat(per-chunk AEAD tags)`. Because an
  AEAD tag (GHASH / Poly1305) is forgeable by a holder of the content key, a
  recipient/collaborator could rewrite chunk ciphertext while keeping every
  tag byte-identical, so `decrypt` returned attacker-modified plaintext while
  `metadata.signature.verified` stayed `true` — a sender-attribution bypass
  affecting both the `aes-256-gcm-v1` and `pq-hybrid-xchacha-mlkem1024-v1`
  stream suites. Reported via the bug bounty program (Mudit Raj). The signed
  message is now the SHA-256 digest of a domain-separated, length-framed
  transcript over the header and **every chunk's full ciphertext** (see
  `spec/format-v1.md § "Signature block"`), hashed incrementally so signing
  stays O(1) in memory. `verified: true` now means the signer signed exactly
  the ciphertext presented.

  **Breaking (signature profile only):** this redefines what algorithm `0x01`
  signs. Signatures produced by earlier versions no longer verify (they are
  reported `verified: false`, fail-closed). Unsigned/legacy files are
  unaffected and decrypt unchanged (`signature: null`); confidentiality,
  `header_mac`, and per-chunk AEAD integrity are unchanged. The signing
  feature was optional and unused by any production deployment, so no
  interoperable signed files exist under the old transcript.

### Changed

- `src/identity/sign.ts`: removed `signHeaderAndMacs` / `verifyHeaderAndMacs`
  (which signed the tag-only transcript); added `SenderSigTranscript`,
  `signSenderTranscript`, and `verifySenderTranscript`. New direct dependency
  on `@noble/hashes` for the incremental SHA-256 transcript.

## 1.0.0-beta.3 — 2026-07-02

> Re-release of `1.0.0-beta.2` through the tag-triggered CI pipeline so the
> published tarball carries a verified npm **provenance** attestation. There
> are **no** functional, cryptographic, API, or wire-format changes from
> `1.0.0-beta.2`; the source is identical. `1.0.0-beta.2` was published
> manually while CI credentials were being set up and therefore lacks the
> provenance badge — this release supersedes it on the `beta` channel.

### Changed

- Bump version and `SHIELDFIVE_CRYPTO_VERSION` to `1.0.0-beta.3`; publish via
  CI with provenance. No code changes relative to `1.0.0-beta.2`.

## 1.0.0-beta.2 — 2026-07-02

> Reader-consistency hardening for the streaming decrypt paths. The two
> streaming decryptors now enforce the same `suite_payload` structure their
> whole-blob and KEM counterparts already require, so every reader mode of a
> suite agrees on what a well-formed file is. No wire-format, key-derivation,
> or public-API change: files produced by earlier versions decrypt identically
> in every mode, and all prior test vectors are unchanged.

### Fixed

- **`0x03` PQ-hybrid stream, combined-key mode** now rejects a header whose
  24-byte reserved `classical_wrapped` pad is non-zero (M6, `spec/format-v1.md`
  § `0x03`), matching `parsePqHybridV1SuitePayload`, `decryptBlob`, and the KEM
  stream path. The combined-key reader previously skipped this structural check.
- **`0x01` AES-GCM stream** now rejects a `suite_payload` whose length is not
  72 bytes, matching `parseAesGcmV1SuitePayload` and `decryptBlob`.
- Both streaming **encryptors** now reject a malformed caller-supplied
  `suite_payload`, so the library never emits a file its own readers refuse.

### Security

- These are canonical-parsing / reader-consistency fixes, **not** a
  confidentiality or integrity break. `suite_payload` is covered by the header
  MAC, so an accepted malformed file already required the content/combined key;
  no forgery, key-recovery, or plaintext-recovery vector was present. Reported
  by avaragebughunter@gmail.com.

## 1.0.0-beta.1 — 2026-06-19

> Promotes the library from alpha to **beta**. There are no functional,
> cryptographic, or wire-format changes since `1.0.0-alpha.14`; this release
> records that the v1 on-disk format and the public TypeScript API are now
> considered stable enough to leave alpha. `1.0.0` stable remains gated on
> the planned external third-party audit.

### Changed

- **Status: alpha → beta.** The `0x03` PQ-hybrid share-bundle hardening
  (audit findings H2/M6, doc M5) shipped in `1.0.0-alpha.14` and is unchanged
  here. The wire format stays frozen; existing `cipher_version-3` files and
  hardened (`SF5S` v2) share bundles remain valid.
- `SHIELDFIVE_CRYPTO_VERSION`, the status badge, the README/SECURITY status
  notes, and the example decryptor updated to `1.0.0-beta.1`.

### Notes

- Beta means the v1 wire format is frozen and the public API is stable; minor,
  backward-compatible API additions remain possible before `1.0.0` stable, but
  breaking changes are not planned.
- This is **not** a security release — no vulnerabilities were fixed between
  `1.0.0-alpha.14` and `1.0.0-beta.1`. The library has still **not** had an
  external cryptographic audit.

## 1.0.0-alpha.14 — 2026-06-10

> Pre-launch security hardening of the `0x03` PQ-hybrid share bundle. The
> share-bundle wire format changes; the on-disk file format and the `0x03`
> file decryption path are unchanged, so existing `cipher_version-3` files
> remain decryptable.

### Changed (BREAKING — share-bundle wire format only)

- **Share bundle (`0x03`) re-keyed and versioned (audit H2).** The share
  transport key is now derived from the KEM/envelope secret under a dedicated
  HKDF label `shieldfive/v1/share-transport` instead of reusing the
  file-combiner label `shieldfive/v1/pq-hybrid/combine`, so a share transport
  key can never equal a file's combined key. The combined key is now wrapped
  with XChaCha20-Poly1305 whose AAD authenticates the **whole** bundle
  (`magic || uint32_be(pq_len) || pq_payload || wrap_nonce`) rather than an
  AAD-less secretbox that authenticated only the 32-byte key — PQ material
  can no longer be substituted or stripped undetected. The bundle now carries
  a `"SF5S"` + version-2 magic prefix so the hardened format is
  distinguishable from (and not confusable with) the earlier unversioned one.
  Share bundles produced by earlier alpha builds are rejected and must be
  re-issued; no real shares exist pre-launch, so this is a clean break. See
  `spec/format-v1.md` § "Share bundle".

### Security

- **Reserved-pad enforcement (`0x03`, audit M6).** The `0x03` suite-payload
  parser now rejects a non-zero reserved pad in `classical_wrapped` (the 24
  bytes after the 48-byte secretbox), closing a malleable unauthenticated
  field. The default suite combine label and file path are unchanged.

### Documentation

- README/spec: corrected the "cross-file splice prevention (file_id AAD)"
  table cell and prose — `file_id` is NOT in the chunk AAD; splice resistance
  is structural via `file_id` as the HKDF salt in the chunk-key derivation
  (audit INFO). Noted that the "no parallel implementation" scope is the
  file-content cipher suites; the keyring/envelope layer uses WebCrypto
  AES-GCM/HMAC directly.
- **Planned (not in this release): suite-id binding in `0x03` chunk derivation
  (audit M5).** The `0x03` chunk-key / nonce-prefix derivations reuse the
  `0x02` xchacha HKDF labels and do not bind the suite id. This is **not
  exploitable** (the header MAC authenticates the suite byte) and is left
  **unchanged** — production `cipher_version-3` files depend on it and would
  become undecryptable if altered. A future suite version (a new suite id,
  not `0x03`) will bind the suite id into the chunk derivation. Recorded in
  `spec/format-v1.md` and `spec/key-derivation.md`.

### Tests

- Added share-bundle PQ-substitution/forgery, dedicated-transport-key,
  non-zero reserved-pad rejection, and share-bundle version-marker tests
  (182 → 188 passing).

## 1.0.0-alpha.13 — 2026-06-09

### Fixed

- `SHIELDFIVE_CRYPTO_VERSION` now reports the actual package version
  (it was pinned at `1.0.0-alpha.11`). The constant is informational
  only — it is never written into file output or any test vector.
- Corrected a backwards source comment in the `aes-gcm-v2` suite: the
  cross-file nonce-prefix space *widens* from 2^32 to 2^64 (the comment
  previously said "shrinks"). No behavior change — the README and
  CHANGELOG already described it correctly as widening.

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
