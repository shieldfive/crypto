# Vault key chain, name envelopes and agent grants

Implemented in `src/vault/index.ts` (`@shieldfive/crypto/vault`). The first
two formats already exist in the ShieldFive web app's database. This file
specifies them so that any client can interoperate. The third, agent grants,
is new.

## 1. Key chain

Each folder has a 32-byte folder key (FK). A top-level folder's FK is
wrapped under the vault root key (RK). Every other FK is wrapped under its
parent's FK. A file's content key is wrapped under the key of the folder that
contains it, or under RK for a file at the vault root.

```
wrapped = AES-256-GCM(key = parent key, iv = 12 random bytes, aad = none, pt = child key)
stored  = base64(ciphertext || 16-byte tag), base64(iv)
```

Columns: `folders.fk_wrapped/fk_iv`, `files.csk_wrapped/csk_iv`,
`files.pqk_fk_wrapped/pqk_fk_iv`.

For suite 0x03 (PQ-hybrid) files, `csk_wrapped` holds only the classical
envelope key. The key that decrypts the file is the combined key, which also
needs the owner's ML-KEM secret key. `pqk_fk_wrapped` is the combined key
wrapped under the parent FK. The owner's client writes it only when a share
or grant needs it.

## 2. Name envelopes

```json
{"v": 4 | 6, "ct": b64, "iv": b64(12), "tag": b64(16), "salt": b64(16), "kdf": "interactive" | "moderate"}
```

```
name key = Argon2id13(password = UTF-8 of base64(parent key), salt,
                      interactive: ops=2 mem=64 MiB | moderate: ops=3 mem=256 MiB, 32 bytes)
v4: AES-256-GCM(name key, iv, aad = none,               pt = UTF-8 name)
v6: AES-256-GCM(name key, iv, aad = UTF-8 of row UUID,  pt = UTF-8 name)
```

If `kdf` is missing, a reader tries interactive first and then moderate.
Writers always emit v6 with `kdf: "interactive"`. The password already
carries 256 bits of entropy, so the cost level only exists for compatibility.

v3 (fragment-keyed) and the server-keyed `v2|…` shape are outside this
module.

## 3. Agent grants

A grant lets a local agent open a subtree of the vault without the root key.

```
connection string = "sf-grant-v1:" grant_id "." b64url(token) "." b64url(secret) "." hex(sha256(ml_kem_pk))
token   = 32 random bytes. It is the bearer credential, and the server stores hex(sha256(token)).
secret  = 32 random bytes. It never leaves a client.
GK      = HKDF-SHA-256(ikm = secret, salt = UTF-8(grant_id), info = "shieldfive/v1/agent-grant/wrap", L = 32)
wrap    = AES-256-GCM(GK, iv = 12 random bytes,
                      aad = UTF-8("sf-grant-v1|" grant_id "|" kind "|" object_id), pt = key)
kind    = "folder"  a folder key
        | "file"    the key csk_wrapped holds (the classical envelope key for suite 0x03)
        | "file_pq" the combined content key of a suite-0x03 file
        | "name"    the derived key of ONE name envelope
```

`file`, `file_pq` and `name` are issued only for objects whose parent key
the grant does not hold: the scope roots' own names, and files at the vault
root when the grant covers the whole vault. A `name` wrap opens one envelope.
It is useless for writing a new name under the same parent.

The AAD stops a server from presenting one object's wrap as another's. The
public-key fingerprint lets a grant that writes files detect a substituted
ML-KEM public key.

Security properties and limits:

- Leaking the secret without the token gives nothing. The server returns no
  wraps without the token.
- Leaking both gives the grant's subtree only. It never gives RK, the master
  secret or the ML-KEM secret key.
- Revocation is enforced by the server. It does not re-key, so wraps and
  ciphertext fetched before revocation stay decryptable by whoever holds
  the secret.

Vectors: `tests/vectors/vault-vectors.json`.
