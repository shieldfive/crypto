# Intake link signing-key pin (`#f=`)

Used by the ShieldFive web app's request links (`/r/<slug>`) and form links
(`/form/<slug>`). The reference implementation is `utils/inboundIntake.ts` in
`shieldfive/web` (`signingKeyPin`, `signingKeyPinFromHash`,
`buildIntakeFragment`, `checkSigningKeyPin`, `encryptFileForRequest`). This
library does not implement it. This file specifies it so that any client that
mints or opens intake links can interoperate.

## 1. Threat

A guest who opens an intake link fetches the firm's key bundle from the
server: an ML-KEM public key, an X25519 public key, an Ed25519 signing public
key and a signature over the encryption keys. All four come from one server
response. Checking the signature against the signing key from that same
response proves nothing. Anyone who can write the request or form row (a
compromised server, a database attacker, an insider) can put in their own
keys signed with their own signing key, and the guest would encrypt to them.

The pin anchors the signing key outside the server. The URL fragment is never
sent to the server, so the firm's browser puts a digest of the firm's signing
key there when it mints or copies a link. It computes the pin from the firm
identity key it holds locally, never from the database row. The guest
refuses to encrypt unless the served signing key hashes to the pin.

Out of scope:

- An attacker who can change the link itself before the guest opens it (for
  example in the email or chat that carries it). That attacker can also
  replace `k=`.
- An attacker who serves a modified web app to the guest. The check runs in
  the page the server delivers.
- Legacy links with no `f=` (section 5).

## 2. Pin

```
domain = UTF-8("shieldfive/inbound/signing-key-pin/v1")      // 37 bytes, no terminator
pk     = Ed25519 signing public key, raw                     // 32 bytes
pin    = base64url_nopad( SHA-256( domain || pk ) )          // 43 chars
```

- `||` is plain concatenation. There is no length prefix and no separator.
  The input is always 69 bytes.
- `base64url_nopad` is RFC 4648 section 5 (`-` and `_` in place of `+` and
  `/`) with the `=` padding removed. A 32-byte digest always encodes to
  exactly 43 characters.
- The key bundle carries the signing key as standard base64. Decode it to the
  raw 32 bytes before hashing. Never hash the base64 text.

A valid pin matches `^[A-Za-z0-9_-]{43}$`.

The pin covers the signing (identity) key only, not the encryption keys. The
firm can replace its encryption keys under the same identity by signing the
new keys with the pinned key, and links already sent keep working.

## 3. Link fragment

```
/r/<slug>#f=<pin>&k=<fragment key>
/form/<slug>#f=<pin>&k=<fragment key>
```

New links put `f=` before `k=`. If a chat client truncates the link, it cuts
`k=` before it can cut `f=`. A link with no `k=` is refused outright, so
truncation can never turn a pinned link into an unpinned one.

To parse, take the value after the first `f=` that follows `#` or `&`, up to
the next `&` or the end. The result is one of:

| State       | Condition                                       |
|-------------|-------------------------------------------------|
| `absent`    | No `f=` parameter                               |
| `pinned`    | `f=` value matches `^[A-Za-z0-9_-]{43}$`        |
| `malformed` | `f=` present, any other value (including empty) |

A malformed pin is a failed check. It is never treated as `absent`, because
only the firm puts an `f=` in a link, so anything else means the link was
altered.

## 4. Check

The guest computes the pin from the served signing key and compares it with
the link's pin:

| Link state  | Served key                                       | Verdict    |
|-------------|--------------------------------------------------|------------|
| `absent`    | any                                              | `unpinned` |
| `malformed` | any                                              | `mismatch` |
| `pinned`    | missing, not a string, or not decodable          | `mismatch` |
| `pinned`    | pin of served key equals link pin                | `verified` |
| `pinned`    | pin of served key differs                        | `mismatch` |

The comparison is over the 43-character strings and does not exit early.
Both sides are public, so this is habit, not a secrecy requirement.

The check runs in two places:

1. When the page loads, after the bundle is resolved and before any file is
   chosen or any form field is typed. On `mismatch` the request page shows an
   error and disables upload. The form page refuses to render the form.
2. Inside the encrypt call (`encryptFileForRequest`, and the form-answer
   sealing that calls the same check). The pin argument is required. On
   `mismatch` the call throws `SigningKeyPinMismatchError` before it touches
   the plaintext, so a page that skips the first check still cannot encrypt
   to a substituted bundle.

After `verified` or `unpinned`, the Ed25519 signature on the encryption keys
is verified against the served signing key as before. Under `verified`, that
signature now binds the encryption keys to the firm's identity.

## 5. Legacy links

Links minted before pinning have no `f=`. They give `unpinned`. Uploads and
form answers still work. The request page tells the guest that the firm's key
could not be confirmed. Against a server that replaces the whole bundle, the
signature check alone proves nothing for these links. Copying a link again
from the firm's dashboard produces a pinned link.

## 6. Test vectors

| Signing public key (hex)                                           | SHA-256 input digest (hex)                                         | Pin                                           |
|--------------------------------------------------------------------|--------------------------------------------------------------------|-----------------------------------------------|
| `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` | `e4bb2fc925069ec2d6e24bf42f144047482b99c5e6fda485397011ec59320f94` | `5LsvySUGnsLW4kv0LxRAR0grmcXm_aSFOXAR7FkyD5Q` |
| `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `27d8d54994db80a1e2c09f07961f1e6bcc85032f9a5ab956284f7803cce6df15` | `J9jVSZTbgKHiwJ8Hlh8ea8yFAy-aWrlWKE94A8zm3xU` |

The digest column is `SHA-256(domain || pk)`. The first vector is asserted
against the reference implementation in `shieldfive/web`
`tests/inboundKeyPinning.test.ts`. As carried in a key bundle, its key is
`AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`.
