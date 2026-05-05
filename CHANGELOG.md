# Changelog

All notable changes to `@shieldfive/crypto` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  ML-KEM-1024 *and* the classical wrap to compromise a file. ML-KEM-1024
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
[Unreleased]: https://github.com/shieldfive/crypto/compare/v1.0.0-alpha.3...HEAD
