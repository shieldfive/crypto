# @shieldfive/crypto

> Post-quantum-hybrid client-side encryption with a self-describing,
> cipher-suite-agile on-disk format. The cryptographic core of
> [ShieldFive](https://shieldfive.com), released as a standalone library.

[![npm](https://img.shields.io/npm/v/@shieldfive/crypto?logo=npm&color=cb3837)](https://www.npmjs.com/package/@shieldfive/crypto)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-259%2F259-brightgreen.svg)](tests/)
[![npm provenance](https://img.shields.io/badge/npm-provenance-blue?logo=npm)](https://www.npmjs.com/package/@shieldfive/crypto)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/shieldfive/crypto/badge)](https://securityscorecards.dev/viewer/?uri=github.com/shieldfive/crypto)
[![Status](https://img.shields.io/badge/status-beta-yellow.svg)](#status)
<!-- Once registered at https://www.bestpractices.dev, add the earned badge:
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>) -->


## Status & honest scope

This library is **beta**, and "beta" here means one specific thing: the
public TypeScript API may still make minor adjustments before `1.0.0`. The
v1 **wire format is frozen** — files written today will decrypt on every
future v1 release. Leaving beta is an *API-stability* decision; `1.0.0`
means the API is stable under semantic versioning, **not** that the code
has been audited. Those are two separate axes and we track them separately
(see [Status](#status)).

**Audit status:** this library has **not** received a paid third-party
cryptographic audit, and `1.0.0` will not claim one. An external audit is
on the roadmap (we are pursuing grant-funded options); it is not a
prerequisite for leaving beta. [Status](#status) states exactly what has
and has not been reviewed, and what you can verify yourself without
trusting us.

The design choices documented in [`spec/`](spec/) are deliberate and
reviewable. The implementation is covered by 259 passing tests including
truncation, reordering, splice, and tampering detection across all four
suites. That is enough for internal dogfooding and for building on with
eyes open. It is **not** enough to claim "most secure crypto library" —
that claim requires external review this library has not yet received.

When this library says it avoids a parallel cryptographic implementation,
that scope is the file-content cipher suites. The keyring/envelope layer
that wraps content keys is built directly on WebCrypto AES-GCM and HMAC
(via `crypto.subtle`), not on a second hand-rolled implementation.

## Design positions

This library makes specific design choices that differ from existing
open-source client-side encryption libraries in the encrypted-cloud-storage
space. The table below summarizes those positions; each row links to the
spec section that documents the choice.

| Property                                   | This library | Proton OpenPGP.js | Internxt SDK | MEGA SDK |
| ------------------------------------------ | :----------: | :---------------: | :----------: | :------: |
| Post-quantum hybrid by default             |      ✅      |        ⚠️         |      ⚠️      |    ❌    |
| ML-KEM-1024 (NIST PQC level 5)             |      ✅      |        ❌         |  ❌ (Kyber-512) |    ❌    |
| Self-describing on-disk file format        |      ✅      |        ✅         |      ⚠️      |    ⚠️    |
| Cipher-suite agile (one byte selects)      |      ✅      |        ⚠️         |      ❌      |    ❌    |
| Truncation detection bound to AEAD         |      ✅      |        ✅         |      ❌      |    ❌    |
| Cross-file splice prevention (file_id via HKDF salt) | ✅ |        ✅         |      ❌      |    ❌    |
| Streaming AEAD with random-access chunks   |      ✅      |        ⚠️         |      ✅      |    ✅    |
| WebCrypto-only path (no WASM required)     |      ✅      |        ❌         |      ❌      |    ❌    |
| Apache 2.0 (patent grant)                  |      ✅      |        ⚠️ (LGPL)  |      ⚠️      |    ⚠️    |

⚠️ = partial or feature-flagged. See [`spec/threat-model.md`](spec/threat-model.md)
for the comparison methodology and source citations. Proton OpenPGP.js
added optional post-quantum (ML-KEM + ECC hybrid) support via OpenPGP v6
in May 2026 (proton.me/blog/introducing-post-quantum-encryption); it is
opt-in, not default — hence ⚠️ rather than ✅ in the table. Comparison
cells reflect publicly available specifications and audit reports as of
2026-05-18 and will be updated as upstreams change.

## Quick start

```bash
npm install @shieldfive/crypto
# Optional, only if you use suites 0x02 or 0x03:
npm install libsodium-wrappers-sumo
```

### Encrypt a file with the post-quantum hybrid suite (default)

```ts
import {
  encryptBlob,
  decryptBlob,
  generateMlKemKeypair,
} from '@shieldfive/crypto/pq-hybrid-v1'

// Recipient generates a long-lived ML-KEM-1024 keypair (typically derived
// from their master secret — see deriveMlKemKeypair).
const { publicKey, secretKey } = generateMlKemKeypair()

// A classical envelope key (e.g. the user's vault key, 32 bytes).
const envelopeKey = crypto.getRandomValues(new Uint8Array(32))

// Encrypt
const file = new File([myData], 'document.pdf')
const result = await encryptBlob({
  blob: file,
  recipientPublicKey: publicKey,
  envelopeKey,
})

// Upload result.blob to your storage backend. It is self-describing.

// Later, decrypt
const plaintext = await decryptBlob({
  blob: result.blob,
  recipientSecretKey: secretKey,
  envelopeKey,
})
```

### Encrypt with the WebCrypto-only suite (no WASM dependency)

Use `aes-gcm-v2` — the current AES-GCM **write** path (also WASM-free). The
`aes-gcm-v1` subpath is decrypt-only for files written before `v2` existed;
don't write new files with it.

```ts
import { encryptBlob, decryptBlob } from '@shieldfive/crypto/aes-gcm-v2'

const result = await encryptBlob({ blob: file })
// result.contentKey is your 32-byte fresh per-file key — store it wrapped
// under your envelope key.

const plaintext = await decryptBlob({
  blob: result.blob,
  contentKey: result.contentKey,
})
```

### Auto-routing decryptor

If you accept files written by any v1 suite and don't know which in advance:

```ts
import { autoDecryptBlob } from '@shieldfive/crypto'

const plaintext = await autoDecryptBlob({
  blob: encryptedBlob,
  contentKey,           // for aes-gcm-v1 / xchacha-v1
  recipientSecretKey,   // for pq-hybrid-v1
  envelopeKey,          // for pq-hybrid-v1
})
```

### Reading legacy v0 files

The pre-v1 ShieldFive production format is supported read-only:

```ts
import { decryptV0 } from '@shieldfive/crypto/legacy-v0'

const plaintext = await decryptV0({
  blob: legacyBlob,
  contentKey,
  noncePrefix,    // 4 bytes, from the database
  chunkSize,      // 5 * 1024 * 1024 typically
})
```

There is no `encryptV0`. New writes must use a v1 suite.

### Decrypting an exported ShieldFive backup

A ShieldFive user can export their account at any time and
decrypt the resulting bundle offline using this library plus the
small Node script that ships at
[shieldfive.com/export](https://shieldfive.com/export). The
recipe walks the key hierarchy (master password → user key →
root key → folder keys → per-file content keys), re-derives the
ML-KEM-1024 secret for Suite 0x03 files deterministically from
the root key (per `spec/key-derivation.md`), and feeds each blob
into `autoDecryptBlob` here.

The recipe lives at [shieldfive.com/export](https://shieldfive.com/export)
and the script ships in this repository as
[`examples/decrypt-one.mjs`](examples/decrypt-one.mjs), kept in
lock-step with the API surface; this library is the decryption
primitive the script depends on. If
you want to reproduce the path from first principles (with no
ShieldFive code in the loop), `spec/format-v1.md` and
`spec/key-derivation.md` together describe everything needed.

## File format

The complete v1 wire format is documented in
[`spec/format-v1.md`](spec/format-v1.md). The short version:

```
header := magic(5)           = "SF5\x01\x00"
       || suite(1)            = 0x01 | 0x02 | 0x03 | 0x04
       || flags(1)            = 0x00 (reserved)
       || file_id(16)         = random per-file
       || chunk_size(4)       = uint32 BE
       || total_chunks(8)     = uint64 BE
       || plaintext_size(8)   = uint64 BE
       || suite_payload_len(2)
       || suite_payload(variable)
       || header_mac(32)      = HMAC-SHA-256, keyed from content key

chunk_i := length_prefix(4) || AEAD-ciphertext-with-tag
```

Every chunk's AEAD authenticator binds the chunk index, total chunk count,
and final-chunk flag. The `file_id` is NOT part of the AAD; cross-file
splice resistance is structural, coming from the suite-specific chunk-key
and nonce-prefix derivations that mix `file_id` in as the HKDF salt/IKM.
Together these make truncation, reordering, and cross-file splicing
detectable by the AEAD rather than by application-layer hashes.

## Cipher suites

| ID   | Name                                | Default | Notes                                  |
| ---- | ----------------------------------- | ------- | -------------------------------------- |
| 0x01 | `aes-256-gcm-v1`                    |         | WebCrypto-only, hardware-accelerated   |
| 0x02 | `xchacha20-poly1305-v1`             |         | libsodium, 192-bit nonces              |
| 0x03 | `pq-hybrid-xchacha-mlkem1024-v1`    | ✅      | XChaCha20-Poly1305 + ML-KEM-1024 hybrid |
| 0x04 | `aes-256-gcm-v2`                    |         | WebCrypto-only, 8-byte nonce prefix    |

Suite `0x04` is the current AES-GCM write path: identical to `0x01` except
the 12-byte GCM IV uses an 8-byte file-derived nonce prefix and a 4-byte
counter (rather than 4 + 8), widening the cross-file IV-collision margin.
`0x01` remains defined for reading files written before `0x04` existed.
See [`spec/format-v1.md`](spec/format-v1.md) for the per-suite derivations.

ML-KEM-1024 is FIPS 203 (NIST PQC standard, security level 5). Files
encrypted with suite 0x03 remain confidential against an adversary who
breaks *either* the classical or the post-quantum primitive — only a
break of *both* compromises the file.

## Threat model

Documented at length in [`spec/threat-model.md`](spec/threat-model.md). The
short summary: this library protects file confidentiality and integrity
against an honest-but-curious server, an active network adversary, and a
"harvest now, decrypt later" quantum adversary. It does *not* protect
against malicious client delivery, endpoint compromise, side channels in
the host crypto runtime, or metadata leakage at the storage layer. Those
are addressed by the host application, not the crypto layer.

## Performance

Benchmarks live in `bench/throughput.ts`. Run them on your hardware:

```bash
npx tsx bench/throughput.ts
```

Throughput depends heavily on CPU model, AES-NI availability, and Node
version. The PQ KEM is a constant per-file cost (~ML-KEM-1024 keygen +
encapsulation latency), independent of file size. Streaming chunk
throughput tracks the underlying classical AEAD.

We do not publish reference numbers here because numbers without source
hardware are misleading; numbers with source hardware get cherry-picked.
Run the benchmark on your target hardware and report what you see.

## Building from source

```bash
npm install
npm test
npm run build   # emits dist/
```

Requires Node 20+.

## Status

**Beta — API stabilizing, format frozen.** This section tracks two
independent axes; please don't conflate them.

**API stability.** The v1 wire format is frozen — files written today
decrypt on every future v1 release. The public TypeScript API may make
small adjustments before `1.0.0`. `1.0.0` means the API is stable under
semantic versioning: breaking changes will require a major-version bump.
It does **not** mean "audited."

**Audit status (scoped to `v1.0.0-beta.4`).** `@shieldfive/crypto` has
**not** had a paid third-party security audit. The novel part of the
design — the post-quantum-hybrid KEM combiner
`K = HKDF-SHA-256(classical_share ‖ ml_kem_share, salt = file_id)`
(see [`spec/key-derivation.md`](spec/key-derivation.md)) — uses the same
concatenation-KDF hybrid pattern as X-Wing and HPKE, but has not yet
received external cryptographic review. An external audit is on the
roadmap (grant-funded options are being pursued) and is **not** a
prerequisite for leaving beta. When an audit lands it will be cited here
with the firm, the date, and the exact commit/version reviewed — and this
notice stays in place for any version that predates that review.

**What you can verify without trusting us:**

```bash
npm audit signatures   # npm provenance: tarball ↔ this source commit + CI run
npm test               # 259 tests incl. deterministic KATs + adversarial vectors
```

The [`tests/vectors/`](tests/vectors/) directory publishes reproducible vectors
any independent implementation can check against: **positive** known-answer
vectors ([`vectors.json`](tests/vectors/vectors.json)) that a conforming
implementation must reproduce bit-for-bit, and **negative / adversarial** vectors
([`adversarial-vectors.json`](tests/vectors/adversarial-vectors.json)) — tampered
files a conforming decoder MUST reject (bad magic, suite confusion, header/chunk
tampering, reordering, truncation, cross-file splice), each self-checked against
this implementation at generation time.

Plus a published [threat model](spec/threat-model.md) with explicit
non-goals, a complete [wire-format spec](spec/format-v1.md), and
reproducible [test vectors](tests/vectors/vectors.json) any independent
implementation can check against.

## License

[Apache 2.0](LICENSE). The Apache 2.0 patent grant is important for a
crypto library; we chose it over MIT for that reason.

## Reporting vulnerabilities

See [`SECURITY.md`](SECURITY.md). Coordinate with us at
`security@shieldfive.com` (see SECURITY.md for the encrypted-channel
process). 72-hour acknowledgement,
30-day target patch window for high-severity issues. Researchers acting
in good faith are protected under the safe-harbor clause.

## Acknowledgements

- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
  by Paul Miller — clean, minimal ML-KEM-1024 (FIPS 203)
  implementation. ShieldFive pins `^0.6.0`, which resolves to the 0.6.1
  release. Upstream completed a maintainer self-audit at 0.6.1 in
  April 2026 (see the
  ["Security"](https://github.com/paulmillr/noble-post-quantum#security)
  section of the upstream README) and has **not** been independently
  audited by an external firm. ShieldFive's PQ-hybrid construction on
  top of the library — the HKDF-SHA-256 combiner that mixes the
  classical and ML-KEM shares — has also not received an independent
  external audit. A third-party audit of the ShieldFive layer is on the
  roadmap (see [Status](#status)); it is tracked separately from, and is
  not a prerequisite for, the `1.0.0` API-stability milestone.
- [libsodium](https://github.com/jedisct1/libsodium) — XChaCha20-Poly1305
  and XSalsa20-Poly1305 secretbox.
- The NIST PQC competition and FIPS 203 authors.

— Cho Garcia, maintainer
