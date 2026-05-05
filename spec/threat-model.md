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

A2 cannot:

- Recover plaintext (TLS + AEAD).
- Inject ciphertext that decrypts to attacker-chosen plaintext (AEAD
  authentication).
- **Truncate a file undetectably** (final-chunk AAD `is_final` flag).
- **Reorder chunks undetectably** (chunk-index AAD).
- **Splice chunks across files** (file_id AAD).

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

A3 *can* recover plaintext from files encrypted with classical-only suites
(`0x01`, `0x02`) once Shor-feasible quantum computers exist. Files
encrypted with classical-only suites SHOULD be re-encrypted with the
hybrid suite when migration is feasible.

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

File sizes, upload patterns, access timestamps, and folder cardinality are
visible to anyone with database access. This crypto layer encrypts file
*content* and *names*; it does not pad sizes or randomize upload timing.
Applications requiring metadata protection beyond name encryption must
build it on top.

### Side channels in WebCrypto / WASM

Browsers' AES-GCM implementations are typically constant-time on hardware
with AES-NI. WASM-based ChaCha20 is constant-time by construction. We do
not defend against power analysis or fault injection attacks against the
underlying browser/runtime.

### User key loss

If the user loses their master password and there is no recovery key, the
data is unrecoverable. This is a feature.

## Comparison with comparable products

| Product       | File AEAD                      | PQ                       | Truncation detection      | Format self-describing |
| ------------- | ------------------------------ | ------------------------ | ------------------------- | ---------------------- |
| Proton Drive  | AES-256-GCM (chunked)          | None (as of audit dates) | Application layer only    | No (DB-side metadata)  |
| Internxt      | AES-256-CTR + Kyber-512 hybrid | Kyber-512 (≈AES-128 PQ)  | N/A (CTR is unauthenticated; integrity layered) | Partial          |
| MEGA          | AES-128-CCM, Ed25519 sigs      | None                     | Application layer         | Partial                |
| Tresorit      | AES-256-GCM, ECC               | None (as of public docs) | Application layer         | Proprietary            |
| **ShieldFive (v1, suite 0x03)** | **XChaCha20-Poly1305 + ML-KEM-1024 hybrid** | **ML-KEM-1024 (≈AES-256 PQ)**  | **AEAD-bound**            | **Yes**                |

This table reflects publicly available specifications and audit reports as
of the v1 specification date. It is updated when those specifications
change. This is not a security claim about which product is "best" — each
makes different tradeoffs — but it documents the design positions ShieldFive
v1 takes deliberately.

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
