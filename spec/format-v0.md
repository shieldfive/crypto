# ShieldFive Crypto File Format v0 (legacy)

This document describes the **legacy** ShieldFive production file format,
present in production from project inception through the v1 transition.
It is included here so that v1-aware readers can read v0 files indefinitely.

**v0 is read-only as of the v1 release.** New encryptions MUST use v1.

## Wire format

v0 files are stored as the concatenation of independently-encrypted
AES-256-GCM chunks:

```
v0_file := chunk_0 || chunk_1 || ... || chunk_n
chunk_i := AES-GCM(key=content_key, iv=iv_i, aad=∅, plaintext=plain_i)
```

Each chunk's ciphertext includes its 16-byte GCM authentication tag.

There is **no on-disk header**. Decryption requires the following
out-of-band metadata, retrieved from the application database:

```
cipher_version      = 1                              (uint, currently always 1)
cipher_chunk_size   = 5*1024*1024 or 8*1024*1024     (uint, plaintext bytes per chunk)
cipher_nonce_prefix = base64(4 random bytes)         (per-file)
csk_wrapped         = base64(AES-GCM-wrapped 32-byte content key)
csk_iv              = base64(12-byte IV used for wrapping)
cipher_parts_sha1   = [SHA-1(chunk_0), ..., SHA-1(chunk_n)]   (storage integrity)
```

The IV for chunk `i` is:

```
iv_i := nonce_prefix (4 bytes) || uint64_be(i)
```

The content key is unwrapped with the parent folder/root key using
AES-GCM. The wrapped key and wrap IV are stored in the database, not in
the file.

## Limitations of v0 (addressed in v1)

These are the reasons v0 is being retired in favor of v1:

1. **No on-disk version byte.** A v0 file is indistinguishable from
   arbitrary ciphertext without out-of-band context.
2. **No file_id binding.** Chunks can be spliced between two files
   encrypted with the same content key (which should not occur, but is
   not structurally prevented).
3. **No truncation detection.** Trailing chunks can be removed and the
   reader will produce a valid (truncated) plaintext. v0 deployments
   detect this at the application layer using `cipher_parts_sha1`, not in
   the AEAD.
4. **No AAD on chunks.** Chunk index, total chunks, and is-final flag are
   not authenticated. Reordering is detected only because the IV depends
   on the index, but reordering does not produce a clear error message.
5. **No post-quantum protection.**
6. **Suite is hardcoded.** Future cipher upgrades require a new
   `cipher_version` and a database migration, not a per-file decision.

## Migration path

v1-aware applications:

- MUST be able to decrypt v0 files indefinitely.
- SHOULD migrate stored v0 files to v1 in the background as users
  download/re-upload them or via batch re-encryption.
- MUST NOT issue new v0 writes once a v1 deployment is live.

The reference v0 implementation lives in `src/suites/aes-gcm-v0/` and
exposes only a `decryptV0` function. There is no `encryptV0` exported
symbol; this is intentional.

## Security note

v0 is not broken. It is an older design with weaker structural guarantees
than v1. Files encrypted with v0 remain confidential under the original
threat model (server compromise, network interception). The v1 upgrade
adds defense-in-depth, not a fix to a known v0 vulnerability.
