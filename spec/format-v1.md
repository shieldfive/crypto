# ShieldFive Crypto File Format v1

This document is the canonical specification for the v1 ShieldFive encrypted
file format. The implementation in this repository is a reference, not the
specification — when in doubt, this document governs.

## Goals

The v1 format is designed to satisfy these properties simultaneously:

1. **Self-describing.** A reviewer with only the encrypted blob and the
   decryption key (no out-of-band metadata) can decrypt the file.
2. **AEAD-bound chunk position.** Truncation, reordering, and chunk-mixing
   between files are detected by the AEAD authenticator, not by application
   logic.
3. **Cipher-suite agile.** A single byte selects which cipher suite the file
   was encrypted with. Adding a new suite does not change the parser.
4. **Post-quantum hybrid by default.** The default suite combines a classical
   AEAD with ML-KEM-1024 key encapsulation. Files encrypted today survive a
   future cryptographically-relevant quantum computer for the duration of
   the AEAD's classical security.
5. **Streaming-friendly.** A reader can decrypt chunk N without buffering
   chunks 0..N-1 in memory, and a writer can emit chunk N without buffering
   future chunks.

## Wire format

All multi-byte integers are big-endian. All byte counts are in octets.

```
encrypted_file := header || chunk_0 || chunk_1 || ... || chunk_n
              || signature_block?      (optional, see § "Signature block")
```

### Header

```
header := magic               (5 bytes)  = "SF5\x01\x00"
       || suite               (1 byte)   = cipher suite identifier
       || flags               (1 byte)   = reserved, must be 0x00
       || file_id             (16 bytes) = random per-file identifier
       || chunk_size          (4 bytes)  = uint32, plaintext bytes per chunk
       || total_chunks        (8 bytes)  = uint64, total chunk count
       || plaintext_size      (8 bytes)  = uint64, total plaintext bytes
       || suite_payload_len   (2 bytes)  = uint16, length of suite_payload
       || suite_payload       (variable) = suite-specific bytes (see below)
       || header_mac          (32 bytes) = HMAC-SHA-256 over all above bytes
                                            keyed with derived header_mac_key
```

The first 5 bytes `53 46 35 01 00` (`"SF5\x01\x00"`) are the file magic. The
fourth byte is the format major version (0x01). The fifth is reserved for
future minor-version bumps that remain backward-compatible.

`suite` is one of:

| Value  | Suite                                  | Status   |
| ------ | -------------------------------------- | -------- |
| `0x00` | (reserved, never assigned)             | invalid  |
| `0x01` | `aes-256-gcm-v1`                       | required |
| `0x02` | `xchacha20-poly1305-v1`                | required |
| `0x03` | `pq-hybrid-xchacha-mlkem1024-v1`       | default  |
| `0x04` | `aes-256-gcm-v2`                       | required |
| `0x80` | (reserved, custom-suite range begins)  | reserved |

`flags` is reserved; readers MUST reject any header with a non-zero flags
byte. Future versions may introduce flags such as
`0x01 = compressed-plaintext` or `0x02 = sparse-file-encoding`.

`file_id` is 16 cryptographically random bytes generated per file. It is
mixed into every chunk's key and nonce derivation (see the per-suite
definitions below) to bind ciphertext to its file. `file_id` is NOT
present in the AAD itself; the cross-file splice resistance is
structural, via the suite-specific HKDF salt. Future implementers MUST
NOT add `file_id` to the AAD bytes — doing so would break wire
compatibility with already-shipped v1 files.

`plaintext_size` is the exact number of plaintext bytes. It allows a reader
to detect truncation of the final chunk before AEAD verification, and to
allocate output buffers correctly.

`suite_payload` is suite-specific. See "Suite payloads" below.

`header_mac` authenticates the entire header (everything before the
`header_mac` field itself) under a key derived from the content key:

```
header_mac_key := HKDF-SHA-256(
    ikm  = content_key,
    salt = file_id,
    info = "shieldfive/v1/header-mac",
    L    = 32
)
```

For suites whose header MAC key is not derived from `suite_payload`
(currently `0x01` aes-gcm-v1, `0x02` xchacha-v1, `0x04` aes-gcm-v2),
readers MUST verify `header_mac` before parsing `suite_payload` or any
chunk. KEM suites
(currently `0x03` pq-hybrid-v1) verify `header_mac` after decapsulation
per their suite-specific decryption flow; see § "`0x03` — pq-hybrid"
below for the required ordering and security argument. A header_mac
failure means the wrong content key was supplied or the header has been
tampered with.

### Chunks

```
chunk_i := length        (4 bytes)  = uint32, length of ciphertext field
        || ciphertext    (variable) = AEAD output (includes auth tag)
```

The AEAD inputs for chunk `i` are:

```
nonce = chunk_nonce(suite, file_id, i)
aad   = "shieldfive/v1/chunk"  ||  uint64_be(i)  ||  uint64_be(total_chunks)
        ||  uint8(is_final)
key   = chunk_key(suite, content_key, file_id)
```

where:

- `is_final` is `0x01` for chunk `i = total_chunks - 1`, otherwise `0x00`.
- `chunk_nonce` and `chunk_key` are defined per suite.
- `aad` is a fixed-length 36 bytes (19 bytes domain string + 8 + 8 + 1).

Note: the AAD is exactly the 36 bytes defined above. Do not extend it.
Cross-file splice resistance is provided by the suite-specific
chunk-key and nonce-prefix derivations, which use `file_id` as HKDF
salt and IKM respectively.

The plaintext input is:

- For all chunks except the final: exactly `chunk_size` plaintext bytes.
- For the final chunk: between 1 and `chunk_size` plaintext bytes such that
  the sum of all chunks' plaintext lengths equals `plaintext_size`.

A chunk with zero plaintext bytes is invalid. A file with `plaintext_size`
of zero MUST be encoded with `total_chunks = 0` and zero chunks; it is the
caller's choice whether to permit empty plaintexts at all.

### Length-prefix vs. fixed-size chunks

The length prefix exists because some suites (notably any future
length-extending suite) may emit ciphertext that is not exactly
`chunk_size + tag_size` bytes. For the suites defined in this version,
length is always `chunk_size + suite.tag_size` for non-final chunks. Readers
SHOULD validate this invariant.

## Suite payloads

### `0x01` — `aes-256-gcm-v1`

```
suite_payload := wrapped_key   (60 bytes) = AES-GCM-wrapped 32-byte content key
              || wrap_iv       (12 bytes) = AES-GCM IV used for wrapping
```

- `chunk_key(content_key, file_id)` =
  `HKDF-SHA-256(ikm=content_key, salt=file_id, info="shieldfive/v1/aes-gcm/chunk-key", L=32)`
- `chunk_nonce(file_id, i)` =
  `HKDF-SHA-256(ikm=file_id, salt=zeros(32), info="shieldfive/v1/aes-gcm/nonce-prefix", L=4)`
  `|| uint64_be(i)`

  The salt is the RFC 5869 "absent salt" convention: a 32-byte all-zero
  string (the SHA-256 output length). Implementations MUST use this
  canonical form, even though HMAC-SHA-256 happens to produce an
  identical HKDF-Extract output for any salt that zero-pads to 64 bytes.

The nonce prefix is derived from `file_id` so that two files encrypted with
the same content key (which never happens under correct use, but defense in
depth) cannot collide on a `(prefix, counter)` pair.

The wrapped content key is wrapped with the *parent envelope key* (folder
key, vault key, etc.) using AES-256-GCM. This wrapping is OUT OF SCOPE for
the on-disk file format and is the responsibility of the application's
keyring module. The fields above are for files that choose to embed the
wrapped key inline (e.g. exported files). When the wrapped key is stored
out-of-band (e.g. in the ShieldFive vault database), all 72 bytes of
`suite_payload` (60-byte `wrapped_key` + 12-byte `wrap_iv`) are set to
zero. Readers MUST accept all-zero `suite_payload` bytes in this case
and obtain the wrapped key from the out-of-band channel. Whether the
field is inline or zero-filled is a deploy decision; either way the
field length is fixed at 72 bytes.

### `0x02` — `xchacha20-poly1305-v1`

```
suite_payload := wrapped_key   (72 bytes) = secretbox-wrapped 32-byte content key
              || wrap_nonce    (24 bytes) = XSalsa20 nonce for wrapping
```

- `chunk_key(content_key, file_id)` =
  `HKDF-SHA-256(ikm=content_key, salt=file_id, info="shieldfive/v1/xchacha/chunk-key", L=32)`
- `chunk_nonce(file_id, i)` =
  `HKDF-SHA-256(ikm=file_id, salt=zeros(32), info="shieldfive/v1/xchacha/nonce-prefix", L=16)`
  `|| uint64_be(i)`

  Salt convention is the RFC 5869 absent-salt zero-fill (32 zero bytes),
  identical to the AES-GCM suite above.

XChaCha20's 24-byte nonce gives us a 16-byte random prefix and an 8-byte
counter, which is structurally safer than AES-GCM's 4+8 split.

As with the AES-GCM suite, when the wrapped key is stored out-of-band
(e.g. in the ShieldFive vault database), all 96 bytes of `suite_payload`
(72-byte `wrapped_key` + 24-byte `wrap_nonce`) are set to zero. Readers
MUST accept all-zero `suite_payload` bytes in this case and obtain the
wrapped key from the out-of-band channel. The field length is fixed at
96 bytes whether inline or zero-filled.

### `0x03` — `pq-hybrid-xchacha-mlkem1024-v1` (default)

```
suite_payload := mlkem_ciphertext  (1568 bytes) = ML-KEM-1024 ciphertext
              || classical_wrapped (72 bytes)   = 48-byte secretbox-wrapped
                                                   classical share || 24-byte
                                                   reserved pad
              || classical_nonce   (24 bytes)   = secretbox nonce for classical wrap
```

`classical_wrapped` is a fixed 72 bytes: the first 48 are the
XSalsa20-Poly1305 secretbox of the 32-byte classical share, and the
trailing 24 bytes are a reserved pad that MUST be all-zero. Readers MUST
reject a suite payload whose reserved pad is non-zero, so the field
cannot be used as a malleable, unauthenticated side channel.

The recipient holds:

- A classical key `K_c` (32 bytes), wrapped at the envelope layer like the
  XChaCha suite.
- An ML-KEM-1024 keypair `(pk_pq, sk_pq)` derived deterministically from
  the user's master secret (see `spec/key-derivation.md`).

Encryption:

1. Sender generates a 32-byte classical share `S_c` randomly.
2. Sender encapsulates against `pk_pq` to get `(mlkem_ciphertext, S_pq)`.
   `S_pq` is a 32-byte shared secret.
3. Combined content key `K = HKDF-SHA-256(ikm = S_c || S_pq, salt = file_id,
   info = "shieldfive/v1/pq-hybrid/combine", L = 32)`.
4. Sender wraps `S_c` with `K_c` using XSalsa20-Poly1305 secretbox to
   produce the 48-byte secretbox, then left-pads it into the 72-byte
   `classical_wrapped` field with a 24-byte all-zero reserved pad. (The PQ
   share is recovered from `mlkem_ciphertext` via decapsulation; only the
   classical share needs wrapping.)
5. Subsequent chunks use the XChaCha20-Poly1305 chunk format with `K`,
   but with chunk key and nonce prefix derived under DEDICATED 0x03 HKDF
   labels (not the 0x02 xchacha labels), with the suite id folded into the
   IKM:

   ```
   chunk_key    = HKDF(0x03 || K, salt=file_id,
                       info="shieldfive/v1/pq-hybrid/chunk-key", L=32)
   nonce_prefix = HKDF(0x03 || file_id,
                       info="shieldfive/v1/pq-hybrid/nonce-prefix", L=16)
   ```

   This keeps the 0x03 chunk-key/nonce domain disjoint from 0x02 even when
   the same content key and `file_id` are supplied to both suites. See
   `spec/key-derivation.md`.

Decryption:

1. Reader decapsulates `mlkem_ciphertext` with `sk_pq` to recover `S_pq`.
2. Reader unwraps `classical_wrapped` with `K_c` to recover `S_c`.
3. Reader recomputes `K = HKDF-SHA-256(ikm = S_c || S_pq, ...)`.
4. Reader verifies `header_mac` (which uses `K`).
5. Reader processes chunks.

#### Security argument for pre-MAC decapsulation

The decapsulation in step 1 operates on unauthenticated
`mlkem_ciphertext` bytes — the header MAC cannot yet be verified at
that point, because the MAC key is the combined key K, which requires
both decapsulation and classical unwrap to compute. Safety of this
construction rests on three properties:

1. **ML-KEM-1024 is IND-CCA2-secure** (FIPS 203). Decapsulation of
   malformed or adversarial ciphertext does not leak the encapsulated
   secret `S_pq` and does not leak the secret key `sk_pq`. An attacker
   who modifies `mlkem_ciphertext` bytes obtains a different `S_pq`
   (computationally indistinguishable from random under IND-CCA2), but
   learns nothing about the underlying key material.

2. **The classical share is wrapped with XSalsa20-Poly1305 secretbox.**
   The unwrap in step 2 is an AEAD operation over attacker-influenced
   `classical_wrapped` bytes. Any modification of those bytes causes
   the secretbox tag check to fail, raising before plaintext is
   produced. An attacker who modifies the classical share cannot
   silently substitute a different `S_c`.

3. **The recombined key K is verified via `header_mac`.** The
   encryptor's `header_mac` is a valid HMAC-SHA-256 tag under the
   encryptor's K over the encryptor's header bytes. An attacker who
   modifies any bytes covered by the MAC (header fields,
   `suite_payload`, or both) and whose modified inputs cause
   decapsulation and classical unwrap to yield some K' would then
   need to forge an HMAC-SHA-256 tag under K' over the modified
   bytes — which contradicts HMAC's EUF-CMA security. Equivalently:
   the only way to pass MAC verification under any K' is to leave
   the MAC-covered bytes unchanged, in which case the encryption
   succeeds against the unmodified ciphertext (not an attack).

An attacker modifying `suite_payload` bytes therefore either (a) gets a
different combined key K and fails `header_mac` verification, or (b)
fails at secretbox tag check during classical unwrap, or (c) learns
nothing under ML-KEM IND-CCA2. In no case is plaintext revealed.
Implementations MAY surface a distinct error for case (b) (secretbox
failure) versus case (a) (MAC failure) since case (b) is reachable with
smaller attacker effort and may be useful for telemetry; they MUST NOT
leak the value of K, S_c, or S_pq in any error path.

This construction is IND-CCA2 against an adversary who breaks *either* the
classical wrap *or* the PQ KEM, but not both. As long as one primitive
remains secure, the file is secure. Under correct use, both must be broken
to recover the plaintext.

Unlike the AES-GCM and XChaCha suites, the all-zero `suite_payload`
convention does NOT apply to PQ-hybrid: `mlkem_ciphertext` is part of
decryption (the PQ shared secret is recovered from it via
decapsulation) and therefore cannot be stored out-of-band. The full
1664-byte `suite_payload` MUST be present inline in every PQ-hybrid
file.

#### Share bundle (re-encrypting `K` to another recipient)

Sharing a `0x03` file with an additional recipient does not re-encrypt the
chunks. The owner recovers the file's combined key `K` and produces a
per-recipient *share bundle* that re-wraps `K` to the recipient's ML-KEM
public key + envelope key. The share bundle is an application-layer record
(it has no `SF5` magic and is not part of the on-disk file), but its wire
format is specified here because it carries `0x03` key material.

```
share_bundle := pq_len            (4 bytes)   = uint32 BE, length of pq_payload (= 1664)
             || pq_payload        (1664 bytes) = a 0x03 suite_payload encapsulated to the recipient
             || wrap_nonce        (24 bytes)   = XChaCha20-Poly1305 nonce
             || wrapped_key        (48 bytes)  = AEAD(K) = 32-byte K + 16-byte tag
```

Construction:

1. The owner encapsulates to the recipient (ML-KEM + classical wrap under
   the recipient's envelope key), yielding `pq_payload` and a transport
   secret `T` (the `0x03` combined key for the recipient, derived under
   `info="shieldfive/v1/pq-hybrid/combine"`).
2. The wrapping key is domain-separated from `T` — it is NOT `T` directly,
   so a share key can never equal a file's combined key:

   ```
   share_transport_key = HKDF(ikm=T, salt=file_id,
                              info="shieldfive/v1/share-transport", L=32)
   ```
3. `K` is wrapped with XChaCha20-Poly1305 under `share_transport_key`, with
   the AAD authenticating the WHOLE bundle prefix so PQ material cannot be
   substituted or stripped:

   ```
   aad         = uint32_be(pq_len) || pq_payload || wrap_nonce
   wrapped_key = XChaCha20-Poly1305-Encrypt(key=share_transport_key,
                     nonce=wrap_nonce, aad=aad, plaintext=K)
   ```

The recipient reverses this: parse the bundle (rejecting a non-zero
reserved pad in `pq_payload`), decapsulate to recover `T`, derive
`share_transport_key`, reconstruct `aad`, and AEAD-open `wrapped_key`. Any
modification to `pq_len`, `pq_payload`, or `wrap_nonce` breaks the tag.

> **Wire-format change (alpha):** earlier alpha builds derived the wrapping
> key directly from `T` (reusing the file-combiner label) and wrapped `K`
> with an XSalsa20-Poly1305 secretbox that authenticated only `K` (no AAD
> over `pq_payload`). Share bundles produced by those builds are NOT
> readable by this construction and must be re-issued.

### `0x04` — `aes-256-gcm-v2`

```
suite_payload := wrapped_key   (60 bytes) = AES-GCM-wrapped 32-byte content key
              || wrap_iv       (12 bytes) = AES-GCM IV used for wrapping
```

`0x04` is a WebCrypto-only AEAD suite (no WASM dependency) that differs
from `0x01` in exactly one respect: the split of the 12-byte AES-GCM IV.
It is the suite new AES-GCM writes use; `0x01` remains defined so that
files written before `0x04` existed stay readable.

- `chunk_key(content_key, file_id)` =
  `HKDF-SHA-256(ikm=content_key, salt=file_id, info="shieldfive/v1/aes-gcm/chunk-key", L=32)`

  This is bit-for-bit identical to the `0x01` chunk-key derivation — same
  HKDF `info` string (`shieldfive/v1/aes-gcm/chunk-key`), same inputs. A
  `0x01` file and a `0x04` file sharing a `content_key` and `file_id`
  derive the same chunk key. They never collide on AEAD inputs, because
  the nonce-prefix derivation below uses a distinct `info` string, giving
  the two suites disjoint `(prefix, counter)` spaces.

- `chunk_nonce(file_id, i)` =
  `HKDF-SHA-256(ikm=file_id, salt=zeros(32), info="shieldfive/v1/aes-gcm-v2/nonce-prefix", L=8)`
  `|| uint32_be(i)`

  The 12-byte GCM IV is an 8-byte file-derived prefix followed by a 4-byte
  big-endian chunk counter — the inverse of `0x01`'s split, which is a
  4-byte prefix and an 8-byte counter. Widening the prefix shrinks the
  cross-file `(prefix, counter)` collision space (for two files that reuse
  a `content_key` — which never happens under correct use, but defense in
  depth) from 2^32 to 2^64. The trade is a per-file chunk ceiling of 2^32
  chunks rather than 2^64; this is far above the format's
  `MAX_TOTAL_CHUNKS` bound (1e9), so it is not a practical constraint.
  Readers MUST reject a `0x04` file whose `total_chunks` exceeds 2^32. The
  salt is the RFC 5869 absent-salt zero-fill (32 zero bytes), identical to
  the `0x01` and `0x02` suites.

The wrapped-content-key field and the all-zero `suite_payload` convention
for out-of-band key storage are identical to `0x01`: the field is a fixed
72 bytes (60-byte `wrapped_key` + 12-byte `wrap_iv`), zero-filled when the
wrapped key is stored out-of-band (e.g. in the ShieldFive vault database).
Readers MUST accept all-zero `suite_payload` bytes in that case and obtain
the wrapped key from the out-of-band channel.

## Signature block

The signature block is an OPTIONAL trailing structure that carries a
detached sender signature over `header_unauthenticated_bytes ||
concat(per-chunk MAC tags)`. It provides *sender attribution*: a
recipient who trusts a sender's public key can verify the file was
produced by that sender. It does NOT add confidentiality or chunk
integrity — those are provided by the per-suite AEAD and by
`header_mac` regardless of whether a signature block is present.

```
signature_block := algorithm        (1 byte)  = signature algorithm identifier
                || pubkey_len       (2 bytes) = uint16 BE, length of public_key
                || public_key       (variable) = sender's verifying key
                || signature_len    (2 bytes) = uint16 BE, length of signature
                || signature        (variable) = detached signature bytes
```

`algorithm` is one of:

| Value  | Algorithm     | Public key | Signature | Status   |
| ------ | ------------- | ---------- | --------- | -------- |
| `0x00` | (reserved)    | —          | —         | invalid  |
| `0x01` | Ed25519       | 32 bytes   | 64 bytes  | defined  |
| `0x02` | ML-DSA-65     | 1952 bytes | 3309 bytes | reserved (not yet implemented) |
| `0x80` | (reserved, custom-algorithm range begins) | — | — | reserved |

The message signed for `0x01 = Ed25519` is the byte string

```
signed_message := header_unauthenticated_bytes
               || concat(chunk_0_mac, chunk_1_mac, ..., chunk_{n-1}_mac)
```

where `header_unauthenticated_bytes` is exactly the bytes covered by
`header_mac` (i.e. everything in the header before the `header_mac`
field itself), and each `chunk_i_mac` is the suite's AEAD authenticator
tag for chunk `i`. For all suites defined in this version the AEAD tag
is the trailing 16 bytes of the chunk's ciphertext field (AES-GCM-128
and Poly1305 both append a 16-byte tag).

The signature block is OPTIONAL. Implementations:

- **Writers MAY** append a signature block. Writers MUST NOT emit more
  than one. The block, if present, MUST appear immediately after the
  final chunk's ciphertext field and MUST NOT be followed by any further
  bytes.
- **Readers MUST** treat a file with no bytes after the last chunk as
  unsigned (signature absent). Readers MUST treat any trailing bytes as
  a signature block and MUST reject the file if those bytes do not parse
  as a well-formed block or are followed by trailing garbage.
- **Readers SHOULD** expose the parsed block (algorithm, public key,
  signature) to callers so an application-level identity policy can
  decide whether the file is acceptable.
- **Readers MAY** verify the signature against a caller-supplied public
  key. A signature block whose `algorithm` is unknown to the reader is
  treated as unverifiable; the reader returns the block to the caller
  without raising and lets the application policy decide.

A signature block does not weaken the format's existing security
guarantees: an attacker who tampers with any byte covered by `header_mac`
fails MAC verification under the content key, and an attacker who
tampers with any chunk ciphertext fails per-chunk AEAD verification. The
signature is a separate, application-level trust layer.

## Versioning policy

- **Format major version (4th byte of magic)** changes when the parser
  changes incompatibly. Old readers MUST refuse to read newer major
  versions.
- **Format minor version (5th byte of magic)** changes when fields are
  added in ways that older readers can ignore. Currently 0x00. Old readers
  encountering a minor version they don't recognize MUST refuse to decrypt
  unless explicitly configured to ignore unknown minor versions.
- **Suite identifier** is independent of format version. New suites can be
  added without changing the format version.

## Compatibility with v0 (legacy production format)

The current ShieldFive production upload format predates this
specification. It is referred to as "v0" and is described in
`spec/format-v0.md`. v0 files do not have the SF5 magic; they are detected
by the absence of magic and by the presence of the database-stored
`cipher_version = 1` flag. ShieldFive applications MUST be able to read
v0 indefinitely; v0 writes are deprecated and SHOULD be migrated to v1.

v0 and v1 cannot be silently confused in either direction. A v1 blob fed
to the v0 reader fails AES-GCM authentication on chunk 0 (the v1
magic/suite/file_id bytes do not form a valid GCM tag). A v0 blob fed to
`parseHeader` fails the magic-byte check with probability `1 - 2^-40`
per file. Application dispatchers MUST route by an explicit version
field (e.g. a database column) and MUST NOT auto-detect across formats.
The library does not expose cross-format auto-detection.

## Test vectors

Implementations MUST produce identical bit-for-bit output for the test
vectors in `tests/vectors/`. These vectors are computed from a fixed seed
and committed to the repository.
