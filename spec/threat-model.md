# ShieldFive Crypto Threat Model

This document scopes what the v1 format protects against, what it does not,
and how it differs from comparable products.

## Adversary model

We model three adversaries:

### A1 — Honest-but-curious server

Has full access to the storage backend, the application database, network
logs, and the deployed application server. Cannot modify the client code
delivered to the user's browser. Cannot compromise the user's device.

A1 can observe:

- All ciphertext.
- File sizes, upload timestamps, IP addresses, account identifiers.
- Encrypted metadata payloads.
- Folder/file structural relationships.

A1 cannot recover:

- Plaintext file content.
- Unwrapped content keys.
- Plaintext filenames or folder names protected by the metadata layer.

### A2 — Active network adversary

Sits between the client and the server. Can drop, reorder, replay, or
modify any byte. Cannot break TLS.

TLS is terminated at the edge platform (Vercel/Cloudflare) and a fresh
TLS session is used to talk to Supabase and B2. The AEAD layer is
end-to-end client-to-blob, so an attacker controlling the TLS
termination is effectively A1 (sees ciphertext, not plaintext). A2's
"cannot break TLS" is therefore a statement about the client↔edge leg
specifically.

A2 cannot:

- Recover plaintext (TLS + AEAD).
- Inject ciphertext that decrypts to attacker-chosen plaintext (AEAD
  authentication).
- **Truncate a file undetectably** (final-chunk AAD `is_final` flag).
- **Reorder chunks undetectably** (chunk-index AAD).
- **Splice chunks across files** (chunk_key and nonce_prefix are
  derived from file_id via HKDF; see
  [`format-v1.md` § "Suite payloads"](./format-v1.md#suite-payloads)
  for each suite's derivations. file_id is NOT in chunk AAD; the
  binding is structural — see
  [crypto PR #1](https://github.com/shieldfive/crypto/commit/f3f52ba) for the
  test vector pinning this behavior).

#### Legacy v0 data

Files encrypted with the v0 wire format (predating this specification —
see
[`format-v0.md` § "Limitations of v0"](./format-v0.md#limitations-of-v0-addressed-in-v1))
do NOT carry the AEAD-bound integrity properties above. Specifically,
v0 files have no chunk AAD, no `file_id` binding, and no truncation
detection. Defense-in-depth for v0 files relies on the application's
stored per-chunk SHA-1 hashes (`cipher_parts_sha1`), verified on
download. Migration to v1 is required to gain the AEAD-bound integrity
properties documented above. As of 2026-05-17, the v1 PQ-hybrid
writer (Suite 0x03) is the production default for new uploads;
existing v0 files remain readable indefinitely and in-place migration
is tracked separately.

### A3 — Future quantum adversary

Holds today's ciphertext. Eventually obtains a cryptographically relevant
quantum computer. Wants to recover plaintext from "harvest now, decrypt
later" attacks.

A3 cannot recover plaintext from files encrypted with suite `0x03`
(`pq-hybrid-xchacha-mlkem1024-v1`) unless they break **both**:

- ML-KEM-1024 (NIST PQC standard, security level 5, equivalent to AES-256
  against quantum search), AND
- XChaCha20-Poly1305 (256-bit key, 128-bit security against Grover-like
  speedups).

A3 _can_ recover plaintext from files encrypted with classical-only suites
(`0x01`, `0x02`) once Shor-feasible quantum computers exist. Files
encrypted with classical-only suites SHOULD be re-encrypted with the
hybrid suite when migration is feasible.

#### Current deployment status

As of 2026-05-17, the production web client emits Suite `0x03`
(`pq-hybrid-xchacha-mlkem1024-v1`) for new uploads; files written
under the previous default (v0, Suite `0x01`) remain readable
indefinitely.

## Trust principals

### Share-link recipient

A third party in possession of a share URL and the share password is
given decrypt authority for exactly one file. Their reach is bounded
by:

- **One file.** Each share is scoped to a single `file_id`; share URLs
  do not enumerate folder contents or sibling files.
- **Bounded downloads.** `share_max_downloads` is enforced atomically.
- **Optional geo-lock and expiry.** Per-share allowed countries and
  expiry timestamp.
- **No key reach.** The share endpoint never returns `rk`, parent
  folder keys, or other CSKs.
- **Brute force.** Verification is rate limited per-share, per-IP, and
  per-burst; lockout state is tracked in `share_password_attempts`
  (Task 7). The brute-force defense wraps the verifier comparison the
  same way it previously wrapped the bcrypt comparison.

The recipient is a trusted third party for the single file shared; the
system makes no confidentiality guarantee against that recipient.

New shares use a **client-derived blind verifier**: the client derives
`verifier = Argon2id(share password, share_verifier_salt)` and the
creator stores only `SHA-256(verifier)` (`share_verifier_hash`). At
download the recipient re-derives the verifier locally and sends it; the
server `SHA-256`s the received verifier and constant-time compares it to
`share_verifier_hash`. The share password is never transmitted to the
server, so the server never holds the cleartext password alongside
`csk_pw_wrapped` and cannot decrypt the shared file. The verifier salt
is independent of `csk_pw_salt`, and the key-wrapping path (`csk_pw_*`)
is unchanged. Confidentiality against A1 is therefore unaffected (the
server has only `share_verifier_hash`, never the password).

The legacy bcrypt path (`share_password_hash`) is retained only for
shares created before the blind verifier; those shares still send the
cleartext password for the server-side bcrypt compare. New shares are
always verifier mode.

## Out of scope

This crypto layer does not protect against:

### Malicious client delivery

If the application server delivers a backdoored JavaScript bundle to the
user's browser, that bundle can capture the password before encryption
happens. The crypto library cannot detect this. Reproducible builds and
client integrity verification (Subresource Integrity, signed
extensions, audited desktop builds) are required to address this and are
the responsibility of the host application, not the crypto layer.

### Endpoint compromise

Malware on the user's device, malicious browser extensions, screen
recorders, and keyloggers all see plaintext. The crypto layer cannot help.

### Metadata leakage at the storage layer

A non-exhaustive list of metadata visible to anyone with database
access: file sizes, upload timestamps, access timestamps, folder
cardinality, deterministic per-user filename hashes (HMAC-SHA-256
keyed by a per-user secret), per-share viewer geography and per-share
hashed IP (HMAC-SHA-256 under a server secret), per-share lockout
state and download counts, per-file owner download counts, and
aggregate storage usage timestamps. The crypto layer encrypts file
content and the ciphertext form of filenames; it does not encrypt
access logs, search-hash material, or share metrics. Applications
requiring metadata protection beyond filename-content secrecy must
build it on top.

### Side channels in WebCrypto / WASM

Browsers' AES-GCM implementations are typically constant-time on hardware
with AES-NI. WASM-based ChaCha20 is constant-time by construction. We do
not defend against power analysis or fault injection attacks against the
underlying browser/runtime.

### User key loss

If the user loses their master password and there is no recovery key, the
data is unrecoverable. This is a feature.

### Recovery-key compromise

The recovery key is a 32-byte random value generated client-side at
signup and shown to the user exactly once (regeneration is supported
via in-app UI). Possession of the recovery key is functionally
equivalent to knowing the password — it unwraps the same `rk` via a
different wrapping key. The threat model treats recovery-key theft as
out of scope (the host application's recovery-key UX, Task 19, is
responsible for guiding users to a secure backup channel);
confidentiality against A1 still holds for users who back the recovery
key up to a non-leaked location. If a user backs the recovery key up
to a leaked location (email plaintext, screenshot in cloud-synced
photos, paper in an insecure environment), an attacker reaching that
backup obtains the same access as the user.

## Comparison with comparable products

| Product                          | File AEAD                                   | PQ                            | Truncation detection                            | Format self-describing |
| -------------------------------- | ------------------------------------------- | ----------------------------- | ----------------------------------------------- | ---------------------- |
| Proton Drive                     | AES-256-GCM (chunked)                       | Proton Mail (sibling product) added optional PQ via OpenPGP v6 in May 2026; Proton Drive's on-disk format had not adopted PQ as of 2026-05-18 | Application layer only                          | No (DB-side metadata)  |
| Internxt                         | AES-256-CTR + Kyber-512 hybrid              | Kyber-512 (≈AES-128 PQ)       | N/A (CTR is unauthenticated; integrity layered) | Partial                |
| MEGA                             | AES-128-CCM, Ed25519 sigs                   | None                          | Application layer                               | Partial                |
| Tresorit                         | AES-256-GCM, ECC                            | None (as of public docs)      | Application layer                               | Proprietary            |
| **ShieldFive (v1, suite 0x03)†** | **XChaCha20-Poly1305 + ML-KEM-1024 hybrid** | **ML-KEM-1024 (≈AES-256 PQ)** | **AEAD-bound**                                  | **Yes**                |

This table reflects publicly available specifications and audit reports as
of 2026-05-18 (last access date). It is updated when those specifications
change — for example, Proton Mail (sibling product to Proton Drive)
launched optional post-quantum encryption via OpenPGP v6 in May 2026
(proton.me/blog/introducing-post-quantum-encryption); the Proton Drive
on-disk wire format had not adopted PQ as of the access date. This is not
a security claim about which product is "best" — each makes different
tradeoffs — but it documents the design positions ShieldFive v1 takes
deliberately.

† As of 2026-05-17, the production web client emits Suite `0x03`
(`pq-hybrid-xchacha-mlkem1024-v1`) for new uploads; files written
under the previous default (v0, Suite `0x01`) remain readable
indefinitely. See § "Current deployment status" under A3.

## Known limitations of v1

These are intentional tradeoffs documented for transparency:

1. **Per-file random nonce prefix is derived, not stored.** Under correct
   use this is safer (no risk of replay due to RNG failure during write).
   Under incorrect use (key reuse across files), it offers no defense
   beyond what AES-GCM/XChaCha already provide. This is acceptable because
   the crypto layer enforces fresh per-file content keys.

2. **No padding for size obfuscation.** A 5MB ciphertext implies a ~5MB
   plaintext (within chunk granularity). Applications wanting size privacy
   must pad at a higher layer. v2 may introduce optional plaintext padding.

3. **No traffic analysis resistance.** Upload/download timing is observable
   to the storage server. This is out of scope.

4. **HMAC-SHA-256 for header authentication, not Poly1305.** Chosen because
   HMAC-SHA-256 is universally available in WebCrypto without WASM. The
   security claim is unchanged: 128-bit MAC strength.

5. **ML-KEM keys are derived deterministically from user master secret.**
   This is an availability tradeoff — the user does not need to back up a
   separate PQ keypair. The cost is that ML-KEM key generation is
   deterministic with respect to the master secret, which means a future
   weakness in the deterministic seed expansion (HKDF-SHA-256) propagates
   to PQ key generation. We accept this because (a) HKDF is conservative,
   (b) the alternative is requiring users to back up PQ keys separately,
   which has a worse failure mode (data loss).

## Reporting

Cryptographic vulnerabilities should be reported to
`security@shieldfive.com` encrypted with the PGP key in `SECURITY.md`. We
acknowledge within 72 hours and target a patch within 30 days for
high-severity issues. Researchers acting in good faith are protected under
the safe-harbor clause in `SECURITY.md`.
