# Migration guide — ShieldFive in-repo crypto → `@shieldfive/crypto`

This document maps each piece of crypto code currently living in the
ShieldFive main repository to its replacement in this library. It is
written for the engineer doing the swap; it is not part of the library's
public documentation.

## Inventory of files to replace

The current ShieldFive repository (`shieldfive-main/`) has cryptographic
code in these locations:

| Current location                          | Replacement                                                |
| ----------------------------------------- | ---------------------------------------------------------- |
| `public/workers/sf-crypto-worker.js`      | `@shieldfive/crypto/aes-gcm-v1` (write) + `legacy-v0` (read) |
| `utils/crypto.ts`                         | `@shieldfive/crypto/xchacha-v1` if still used; otherwise delete |
| `utils/keyCrypto.ts`                      | `@shieldfive/crypto` envelope helpers                       |
| `utils/sfCryptoWorker.ts`                 | thin wrapper around the library; can stay or be removed    |
| `utils/metadataClient.ts`                 | application-layer (metadata encryption is out of scope)    |
| `utils/ciphertextHash.ts`                 | application-layer (storage integrity is out of scope)      |
| `utils/uploadProofClient.ts`              | application-layer (audit logs are out of scope)            |
| `utils/uploadProofFormat.ts`              | application-layer                                          |

`utils/metadataClient.ts`, `utils/ciphertextHash.ts`, and the upload-proof
files are **not** cryptographic primitives in the sense this library
covers — they orchestrate higher-level features (metadata encryption,
storage hashing, upload audit trails). They will continue to live in the
main repository and call into this library where they need primitives.

## Migration phases

### Phase 1 — Drop-in (no format change)

Replace the worker's encryption code with the library's `aes-gcm-v1` suite
without changing the wire format on disk. Existing files remain
v0-formatted (no SF5 magic; metadata in the database). New uploads also
use v0 formatting via a temporary "v0 writer" that wraps the library —
this is the only situation in which v0 writing is permitted.

This is the lowest-risk first step. Server changes: zero.

```ts
// Before (production worker)
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv },
  key,
  plaintext,
)

// After (still v0 format on disk, library handles correctness)
import { encryptChunkV0 } from './internal-v0-writer.ts' // private bridge
const ciphertext = await encryptChunkV0({ key, prefix, index, plaintext })
```

The `internal-v0-writer.ts` is a private, non-exported bridge — it lets
the main repository emit v0 files for one release while it migrates
readers to the library. It MUST be deleted in Phase 2.

### Phase 2 — v1 writer for new uploads

Switch new uploads to suite `0x01` (`aes-256-gcm-v1`) of the v1 format.
v0 files remain readable indefinitely via `@shieldfive/crypto/legacy-v0`.

Server changes:

- Add a column `crypto_format` to the `files` table: `0` = v0, `1` = v1.
- Default new rows to `1`. Existing rows stay at `0`.
- The download endpoint picks the decryptor based on this column.

Client changes:

```ts
// Old upload path (utils/sfCryptoWorker.ts)
import { encryptInWorker } from './sfCryptoWorker'

// New upload path
import { encryptBlob } from '@shieldfive/crypto/aes-gcm-v1'
const result = await encryptBlob({ blob: file, chunkSize: 4 * 1024 * 1024 })
// result.contentKey: wrap with envelopeKey via /keyCrypto helpers
// result.fileId: store in DB
// result.blob: upload as before
```

### Phase 3 — Default to PQ-hybrid

Switch new uploads to suite `0x03` (PQ-hybrid). At this point:

- Each user generates an ML-KEM-1024 keypair on first login after the
  release. The keypair is derived deterministically from the master
  secret via `deriveMlKemKeypair` — no separate backup required.
- The user's public key is published to the server (per-user record);
  the secret key remains client-only.
- Sharing files with another user uses *their* public key for the PQ
  encapsulation. Server keeps a public-key directory.

Server changes:

- Add a `users.ml_kem_public_key` column (1568 bytes, BLOB).
- Add a public-key publishing endpoint and a sharing endpoint that
  resolves the recipient's PQ public key.

Client changes:

```ts
import { encryptBlob, deriveMlKemKeypair } from '@shieldfive/crypto/pq-hybrid-v1'

// One-time setup per user, on first PQ-aware login
const masterSecret = await deriveMasterFromPassphrase(...)
const { publicKey, secretKey } = await deriveMlKemKeypair(masterSecret)
await api.publishMlKemPublicKey(publicKey)

// Per upload (own files: encrypt to your own PQ public key)
const result = await encryptBlob({
  blob: file,
  recipientPublicKey: publicKey,
  envelopeKey: classicalEnvelopeKey,
})

// Sharing: encrypt once per recipient — fetch their public key first.
```

### Phase 4 — Background migration of v0 → v1 hybrid

Optional but recommended. A background worker re-encrypts older files
into v1 hybrid format as the user accesses them, or on a low-priority
queue when the app is idle. v0 reader stays available indefinitely so
the migration can be paused at any point without data loss.

## Tests to add to the main repo

After each phase, verify:

1. Files uploaded in the previous format still download successfully.
2. The format byte in the database matches the on-disk magic for every
   new upload.
3. Downloads route to the correct decryptor based on `crypto_format`.
4. The library's tests still pass when run in the main repo's bundler.

## Files to delete after Phase 2

- `utils/crypto.ts` (the legacy XChaCha module — never made it to
  production anyway, per the audit)
- `public/workers/sf-crypto-worker.js` legacy code paths

Files to keep (they wrap the library, not replace it):

- `utils/keyCrypto.ts` — envelope key wrapping; thin wrapper over the
  library's `wrapContentKey` / `unwrapContentKey`.
- `utils/sfCryptoWorker.ts` — Web Worker shell that calls into the
  library. Useful for keeping crypto off the main thread.

## Rollback plan

Each phase is independently reversible:

- Phase 1 → Phase 0: revert the bridge module; production resumes the
  inline AES-GCM calls.
- Phase 2 → Phase 1: stop writing v1 (set `crypto_format` default back
  to 0). v1 files written during Phase 2 remain readable forever.
- Phase 3 → Phase 2: stop writing PQ-hybrid (set `crypto_format` default
  back to 1). Hybrid files remain readable forever.

At every phase, the database `crypto_format` column is the single source
of truth for routing.
