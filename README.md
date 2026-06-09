# @shieldfive/crypto

> Post-quantum-hybrid client-side encryption with a self-describing,
> cipher-suite-agile on-disk format. The cryptographic core of
> [ShieldFive](https://shieldfive.com), released as a standalone library.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-182%2F182-brightgreen.svg)](tests/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

## Status & honest scope

This library is **alpha**. The wire format is frozen for the v1 release;
the public TypeScript API may make minor adjustments before v1.0.0 stable.
It has **not** undergone external cryptographic audit. Until it does,
treat this library as a serious work-in-progress rather than a finished
product.

The design choices documented in [`spec/`](spec/) are deliberate and
reviewable. The implementation is covered by 182 passing tests including
truncation, reordering, splice, and tampering detection across all four
suites. That is enough for internal dogfooding. It is **not** enough to
claim "most secure crypto library" — that claim requires external review
this library has not yet received.

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
| Cross-file splice prevention (file_id AAD) |      ✅      |        ✅         |      ❌      |    ❌    |
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

```ts
import { encryptBlob, decryptBlob } from '@shieldfive/crypto/aes-gcm-v1'

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

The recipe and the script live in the web repository so that the
documented version stays in lock-step with the API surface; this
library is the decryption primitive the script depends on. If
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
final-chunk flag, and file_id. This makes truncation, reordering, and
cross-file splicing structurally detectable rather than relying on
application-layer hashes.

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

**Alpha.** The wire format is frozen for the v1 release, but the public
TypeScript API may make small adjustments before 1.0.0 stable. Test
coverage is comprehensive (182 tests, all four suites, all architectural
guarantees verified). A formal third-party security audit is planned for
the 1.0.0 stable milestone — until that audit lands, treat this library
as a serious work-in-progress rather than a finished product.

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
  external audit. A third-party audit of the ShieldFive layer is
  planned for the v1.0.0 stable milestone.
- [libsodium](https://github.com/jedisct1/libsodium) — XChaCha20-Poly1305
  and XSalsa20-Poly1305 secretbox.
- The NIST PQC competition and FIPS 203 authors.

— Cho Garcia, maintainer
