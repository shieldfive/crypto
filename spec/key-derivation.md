# ShieldFive Crypto — Key Derivation

This document specifies how application-level keys (envelope keys, ML-KEM
keypairs, header MAC keys, chunk keys) are derived from the user's master
secret. It is normative for the v1 release.

## Master secret

The library does not generate or manage the master secret directly. The
host application is responsible for producing 32 bytes of high-entropy
secret material — typically by stretching a user passphrase through
Argon2id, by reading a hardware token, or by combining the two.

This document assumes the master secret has been derived. From there:

```
master_secret  ∈ bytes[32]
```

Everything below is a deterministic function of this secret.

## Derivation tree

All derivations are HKDF-SHA-256. The `info` string is a printable
domain separator. When the salt is omitted in the definitions below,
its canonical form is `zeros(32)` per RFC 5869's "absent salt"
convention (a string of `HashLen` zero octets, where `HashLen = 32` for
SHA-256). Implementations MUST use this form; under HMAC-SHA-256 a
zero-length salt yields the same HKDF-Extract output because HMAC
zero-pads short keys to its 64-byte block size, but the canonical form
is required so that cross-implementation test vectors pin a single
shape. Keys are 32 bytes unless otherwise stated. Test vectors for the
nonce-prefix absent-salt derivation are at `tests/vectors/vectors.json`
(group `09_nonce_prefix_absent_salt`).

```
master_secret
├── envelope_key            = HKDF(master, info="shieldfive/v1/envelope-key")
│
├── metadata_key            = HKDF(master, info="shieldfive/v1/metadata-key")
│   (used to encrypt filenames, folder names — outside this library's scope)
│
└── ml_kem_seed             = HKDF(master, info="shieldfive/v1/pq-hybrid/ml-kem-1024-seed", L=64)
    └── (ml_kem_pk, ml_kem_sk) = ML-KEM-1024.KeyGen(ml_kem_seed)
```

The function `deriveMlKemKeypair(masterSecret)` exported from
`@shieldfive/crypto/pq-hybrid-v1` performs the seed derivation and the
ML-KEM keygen step in one call.

## Why deterministic ML-KEM keys?

ML-KEM-1024 secret keys are 3168 bytes. Asking the user to back up an
extra 3168 bytes alongside their master secret would create a new failure
mode: losing the PQ key while still holding the master secret would mean
losing access to PQ-hybrid files.

Instead, we derive the PQ keypair from the master secret. The user backs
up only the master secret (or, more typically, only their passphrase plus
the Argon2id parameters). Everything else regenerates deterministically.

The cost of this choice: a future cryptanalytic break in HKDF-SHA-256's
seed expansion would propagate to the PQ keypair. We accept this because
HKDF-SHA-256 is conservative, and the alternative (separate PQ key
backup) has a worse failure mode (data loss).

## Per-file key derivation (recap from format-v1.md)

Once the envelope key is in hand, per-file keys are derived as:

```
content_key      = randomBytes(32)         (fresh per file, never derived)
file_id          = randomBytes(16)         (fresh per file, never derived)

header_mac_key   = HKDF(content_key, salt=file_id,
                        info="shieldfive/v1/header-mac")

chunk_key        = HKDF(content_key, salt=file_id,
                        info="shieldfive/v1/<suite>/chunk-key")

nonce_prefix     = HKDF(file_id,
                        info="shieldfive/v1/<suite>/nonce-prefix",
                        L = 4 (AES-GCM) or 16 (XChaCha))

iv / nonce_i     = nonce_prefix || uint64_be(chunk_index)
```

For the PQ-hybrid suite, `content_key` is replaced by the combined key
`K = HKDF(classical_share || pq_share, salt=file_id,
info="shieldfive/v1/pq-hybrid/combine", L=32)`. The chunk-key and
nonce-prefix derivations are then identical to the XChaCha suite's,
with `K` in the role of `content_key` and the same info strings
(`shieldfive/v1/xchacha/chunk-key` and
`shieldfive/v1/xchacha/nonce-prefix`). Reuse of those info strings
across the two suites is safe because the IKM space is partitioned:
XChaCha uses a fresh random `content_key` per file, PQ-hybrid uses the
file-bound HKDF output `K`. Both are 32 bytes of uniformly random or
pseudorandom material per file; cross-suite output collision
probability is `2^-256`.

## Forbidden cross-context usage

These domain strings are consumed by the crypto layer. The host
application MUST NOT reuse any of them for unrelated purposes:

```
shieldfive/v1/header-mac
shieldfive/v1/aes-gcm/chunk-key
shieldfive/v1/aes-gcm/nonce-prefix
shieldfive/v1/xchacha/chunk-key
shieldfive/v1/xchacha/nonce-prefix
shieldfive/v1/pq-hybrid/combine
shieldfive/v1/pq-hybrid/ml-kem-1024-seed
shieldfive/v1/argon2id/salt-compression
```

### Reserved for future use

These strings are reserved by this specification but are NOT yet
consumed by the reference implementation. They MUST NOT be reused by
host applications for unrelated purposes, since a future minor
revision of this spec may begin consuming them:

```
shieldfive/v1/envelope-key
shieldfive/v1/metadata-key
```

Interpretation note: the forbidden-list framing above scopes to
strings the library actually consumes today. The two entries here are
spec-only reservations carried over from the derivation tree, kept
separate so the forbidden list can be cross-checked against
`HKDF_INFO` in `src/internal/types.ts` without phantom entries.

If the host application needs a new derived key, it MUST use a fresh
domain string of the form `<application>/<version>/<purpose>` to ensure
domain separation from this library's keys.

## Test vectors

Deterministic test vectors for each derivation step live in
`tests/vectors/key-derivation.json`. They are used by
`tests/integration/key-derivation.test.ts` to ensure cross-implementation
consistency.

A reference vector:

```
master_secret   = 0000…0000 (32 bytes of zero)
envelope_key    = (computed) — see tests/vectors/key-derivation.json
ml_kem_seed     = (computed)
ml_kem_pk[0..7] = (computed first 8 bytes)
```

These vectors are committed to the repository so that any reimplementation
of the v1 spec can self-check.
