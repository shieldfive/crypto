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
| `0x80` | (reserved, custom-suite range begins)  | reserved |

`flags` is reserved; readers MUST reject any header with a non-zero flags
byte. Future versions may introduce flags such as
`0x01 = compressed-plaintext` or `0x02 = sparse-file-encoding`.

`file_id` is 16 cryptographically random bytes generated per file. It is
mixed into every chunk's AAD to bind ciphertext to its file. This prevents
chunk-mixing attacks where chunks from one file are spliced into another
file with the same content key.

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

Readers MUST verify `header_mac` before parsing `suite_payload` or any
chunk. A header_mac failure means the wrong content key was supplied or the
header has been tampered with.

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
  `truncate12(HKDF-SHA-256(ikm=file_id, salt="", info="shieldfive/v1/aes-gcm/nonce-prefix", L=12))[0..3]`
  `|| uint64_be(i)`

The nonce prefix is derived from `file_id` so that two files encrypted with
the same content key (which never happens under correct use, but defense in
depth) cannot collide on a `(prefix, counter)` pair.

The wrapped content key is wrapped with the *parent envelope key* (folder
key, vault key, etc.) using AES-256-GCM. This wrapping is OUT OF SCOPE for
the on-disk file format and is the responsibility of the application's
keyring module. The 60-byte field above is for files that choose to embed
the wrapped key inline (e.g. exported files); files stored in the
ShieldFive vault store the wrapped key in the database and set this field
to 60 bytes of zero. Whether the field is inline or zero-filled is a deploy
decision; either way the field length is fixed.

### `0x02` — `xchacha20-poly1305-v1`

```
suite_payload := wrapped_key   (72 bytes) = secretbox-wrapped 32-byte content key
              || wrap_nonce    (24 bytes) = XSalsa20 nonce for wrapping
```

- `chunk_key(content_key, file_id)` =
  `HKDF-SHA-256(ikm=content_key, salt=file_id, info="shieldfive/v1/xchacha/chunk-key", L=32)`
- `chunk_nonce(file_id, i)` =
  `truncate24(HKDF-SHA-256(ikm=file_id, salt="", info="shieldfive/v1/xchacha/nonce-prefix", L=24))[0..15]`
  `|| uint64_be(i)`

XChaCha20's 24-byte nonce gives us a 16-byte random prefix and an 8-byte
counter, which is structurally safer than AES-GCM's 4+8 split.

### `0x03` — `pq-hybrid-xchacha-mlkem1024-v1` (default)

```
suite_payload := mlkem_ciphertext  (1568 bytes) = ML-KEM-1024 ciphertext
              || classical_wrapped (72 bytes)   = secretbox-wrapped classical share
              || classical_nonce   (24 bytes)   = secretbox nonce for classical wrap
```

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
   produce `classical_wrapped`. (The PQ share is recovered from
   `mlkem_ciphertext` via decapsulation; only the classical share needs
   wrapping.)
5. Subsequent chunks use the XChaCha20-Poly1305 chunk format with `K`.

Decryption:

1. Reader decapsulates `mlkem_ciphertext` with `sk_pq` to recover `S_pq`.
2. Reader unwraps `classical_wrapped` with `K_c` to recover `S_c`.
3. Reader recomputes `K = HKDF-SHA-256(ikm = S_c || S_pq, ...)`.
4. Reader verifies `header_mac` (which uses `K`).
5. Reader processes chunks.

This construction is IND-CCA2 against an adversary who breaks *either* the
classical wrap *or* the PQ KEM, but not both. As long as one primitive
remains secure, the file is secure. Under correct use, both must be broken
to recover the plaintext.

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

## Test vectors

Implementations MUST produce identical bit-for-bit output for the test
vectors in `tests/vectors/`. These vectors are computed from a fixed seed
and committed to the repository.
