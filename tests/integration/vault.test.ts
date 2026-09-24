/**
 * Behaviour of src/vault beyond the fixed vectors: round trips, tamper
 * resistance, AAD binding, and the scope property a grant relies on — a grant
 * holding one folder's key opens that subtree and nothing beside it.
 */

import { strict as assert } from "node:assert";
import test from "node:test";

import { randomBytes } from "../../src/internal/runtime.js";
import {
  buildUploadProofV3,
  createGrantCredential,
  decryptName,
  decryptNameWithKey,
  unwrapGrantSecret,
  wrapGrantSecret,
  deriveNameKeyForEnvelope,
  deriveGrantWrapKey,
  encryptNameV6,
  formatConnectionString,
  parseConnectionString,
  parseNameEnvelope,
  unwrapChainKey,
  unwrapKeyForGrant,
  VaultCryptoError,
  wrapChainKey,
  wrapKeyForGrant,
} from "../../src/vault/index.js";

const uuid = () => globalThis.crypto.randomUUID();

async function rejects(p: Promise<unknown>, code: VaultCryptoError["code"]) {
  await assert.rejects(
    p,
    (e: unknown) => e instanceof VaultCryptoError && e.code === code,
  );
}

test("chain wrap round-trips and refuses a wrong key or a flipped bit", async () => {
  const parent = randomBytes(32);
  const child = randomBytes(32);
  const w = await wrapChainKey(parent, child);
  assert.deepEqual(await unwrapChainKey(parent, w), child);
  await rejects(unwrapChainKey(randomBytes(32), w), "unwrap_failed");
  const bytes = Buffer.from(w.wrapped, "base64");
  bytes[3] = (bytes[3] ?? 0) ^ 1;
  await rejects(
    unwrapChainKey(parent, { ...w, wrapped: bytes.toString("base64") }),
    "unwrap_failed",
  );
});

test("v6 names are bound to their row", async () => {
  const folderKey = randomBytes(32);
  const rowId = uuid();
  const env = await encryptNameV6({
    name: "Invoice #42.pdf",
    folderKey,
    rowId,
  });
  const parsed = parseNameEnvelope(JSON.stringify(env));
  assert.ok(parsed);
  assert.equal(
    await decryptName({ envelope: parsed, folderKey, rowId }),
    "Invoice #42.pdf",
  );
  await rejects(
    decryptName({ envelope: parsed, folderKey, rowId: uuid() }),
    "name_decrypt_failed",
  );
  await rejects(
    decryptName({ envelope: parsed, folderKey: randomBytes(32), rowId }),
    "name_decrypt_failed",
  );
  await rejects(decryptName({ envelope: parsed, folderKey }), "invalid_input");
});

test("parseNameEnvelope rejects non-envelopes", () => {
  for (const raw of [
    null,
    "",
    "plain.txt",
    '{"v":3,"ct":"","iv":"","tag":""}',
    '{"v":6}',
    "[]",
    '{"v":6,"ct":"a","iv":"b","tag":"c","salt":"d","kdf":"fast"}',
  ]) {
    assert.equal(parseNameEnvelope(raw as string), null, String(raw));
  }
});

test("connection strings round-trip and reject malformed input", () => {
  const cred = createGrantCredential({
    grantId: uuid(),
    mlKemPublicKey: randomBytes(1568),
  });
  const s = formatConnectionString(cred);
  const back = parseConnectionString(`  ${s}\n`);
  assert.equal(back.grantId, cred.grantId);
  assert.deepEqual(back.secret, cred.secret);
  assert.deepEqual(back.token, cred.token);
  for (const bad of [
    "",
    "sf-grant-v2:" + s.slice(12),
    s + ".x",
    s.replace(cred.grantId, "nope"),
    s.slice(0, -2),
  ]) {
    assert.throws(() => parseConnectionString(bad), VaultCryptoError, bad);
  }
});

test("a grant wrap only opens for the same grant, kind and object", async () => {
  const grantId = uuid();
  const folderId = uuid();
  const secret = randomBytes(32);
  const gk = await deriveGrantWrapKey(secret, grantId);
  const key = randomBytes(32);
  const wrapped = await wrapKeyForGrant({
    grantWrapKey: gk,
    grantId,
    kind: "folder",
    objectId: folderId,
    key,
  });
  assert.deepEqual(
    await unwrapKeyForGrant({
      grantWrapKey: gk,
      grantId,
      kind: "folder",
      objectId: folderId,
      wrapped,
    }),
    key,
  );
  await rejects(
    unwrapKeyForGrant({
      grantWrapKey: gk,
      grantId,
      kind: "file",
      objectId: folderId,
      wrapped,
    }),
    "unwrap_failed",
  );
  await rejects(
    unwrapKeyForGrant({
      grantWrapKey: gk,
      grantId,
      kind: "folder",
      objectId: uuid(),
      wrapped,
    }),
    "unwrap_failed",
  );
  const otherGrant = uuid();
  await rejects(
    unwrapKeyForGrant({
      grantWrapKey: await deriveGrantWrapKey(secret, otherGrant),
      grantId: otherGrant,
      kind: "folder",
      objectId: folderId,
      wrapped,
    }),
    "unwrap_failed",
  );
  await rejects(
    unwrapKeyForGrant({
      grantWrapKey: await deriveGrantWrapKey(randomBytes(32), grantId),
      grantId,
      kind: "folder",
      objectId: folderId,
      wrapped,
    }),
    "unwrap_failed",
  );
});

test("a name-key wrap opens exactly one envelope", async () => {
  const rk = randomBytes(32);
  const rowId = uuid();
  const env = await encryptNameV6({
    name: "root-level.pdf",
    folderKey: rk,
    rowId,
  });
  const other = await encryptNameV6({
    name: "other.pdf",
    folderKey: rk,
    rowId: uuid(),
  });
  const nameKey = await deriveNameKeyForEnvelope({
    envelope: env,
    parentKey: rk,
    rowId,
  });
  assert.equal(
    await decryptNameWithKey({ envelope: env, nameKey, rowId }),
    "root-level.pdf",
  );
  await rejects(
    decryptNameWithKey({ envelope: other, nameKey, rowId }),
    "name_decrypt_failed",
  );
});

test("a grant on folder A opens A’s subtree and not its sibling B", async () => {
  // RK ─┬─ A ── A1 ── file f
  //     └─ B ── file g
  const rk = randomBytes(32);
  const fkA = randomBytes(32),
    fkA1 = randomBytes(32),
    fkB = randomBytes(32);
  const cskF = randomBytes(32),
    cskG = randomBytes(32);
  const wA1 = await wrapChainKey(fkA, fkA1);
  const wF = await wrapChainKey(fkA1, cskF);
  const wB = await wrapChainKey(rk, fkB);
  const wG = await wrapChainKey(fkB, cskG);

  const grantId = uuid(),
    idA = uuid();
  const gk = await deriveGrantWrapKey(randomBytes(32), grantId);
  const grantA = await wrapKeyForGrant({
    grantWrapKey: gk,
    grantId,
    kind: "folder",
    objectId: idA,
    key: fkA,
  });

  const a = await unwrapKeyForGrant({
    grantWrapKey: gk,
    grantId,
    kind: "folder",
    objectId: idA,
    wrapped: grantA,
  });
  const a1 = await unwrapChainKey(a, wA1);
  assert.deepEqual(await unwrapChainKey(a1, wF), cskF);

  // Every key the grant can reach fails on the sibling branch.
  for (const k of [gk, a, a1]) {
    await rejects(unwrapChainKey(k, wB), "unwrap_failed");
    await rejects(unwrapChainKey(k, wG), "unwrap_failed");
  }
});

test("the owner copy of a grant secret opens only for the exact scope, and only under RK", async () => {
  const rk = randomBytes(32);
  const secret = randomBytes(32);
  const scope = {
    grantId: uuid(),
    scopeAll: false,
    includeMedia: false,
    rootIds: [uuid(), uuid()],
    trashFolderId: uuid(),
    excludedIds: [uuid()],
    excludedKeyFingerprints: ["a".repeat(64)],
  };
  const wrapped = await wrapGrantSecret({ rootKey: rk, scope, secret });
  assert.deepEqual(
    await unwrapGrantSecret({
      rootKey: rk,
      scope: { ...scope, rootIds: [...scope.rootIds].reverse() },
      wrapped,
    }),
    secret,
  );
  for (const tampered of [
    { ...scope, scopeAll: true },
    { ...scope, includeMedia: true },
    { ...scope, rootIds: [...scope.rootIds, uuid()] },
    { ...scope, trashFolderId: null },
    { ...scope, excludedIds: [] },
    { ...scope, excludedKeyFingerprints: [] },
    { ...scope, grantId: uuid() },
  ]) {
    await rejects(
      unwrapGrantSecret({ rootKey: rk, scope: tampered, wrapped }),
      "unwrap_failed",
    );
  }
  await rejects(
    unwrapGrantSecret({ rootKey: randomBytes(32), scope, wrapped }),
    "unwrap_failed",
  );
  // Domain separation: a plain chain wrap under RK (a folder key) is not accepted as a secret.
  const folderWrap = await wrapChainKey(rk, randomBytes(32));
  await rejects(
    unwrapGrantSecret({ rootKey: rk, scope, wrapped: folderWrap }),
    "unwrap_failed",
  );
  // …and the secret wrap does not open as a chain key under RK.
  await rejects(unwrapChainKey(rk, wrapped), "unwrap_failed");
});

test("malformed base64url in a connection string is a typed error, never a crash", () => {
  const s = formatConnectionString(
    createGrantCredential({
      grantId: uuid(),
      mlKemPublicKey: randomBytes(1568),
    }),
  );
  const parts = s.split(".");
  for (const bad of [
    [parts[0], "a", parts[2], parts[3]],
    [parts[0], parts[1], "ab!c", parts[3]],
  ]) {
    assert.throws(
      () => parseConnectionString(bad.join(".")),
      (e: unknown) =>
        e instanceof VaultCryptoError && e.code === "invalid_connection_string",
    );
  }
});

test("the upload proof frame matches an independent implementation of the spec", async () => {
  // Independent: node:crypto's HMAC over the bytes the SERVER says it MACs
  // (web utils/uploadProof.ts verifyPqHybridV1Proof), assembled here by hand.
  // If buildUploadProofV3 ever drifts from that frame, uploads start failing
  // verification in production and this test is what catches it first.
  const { createHmac } = await import("node:crypto");
  const { encryptStreamPqHybridV1 } =
    await import("../../src/streams/pq-hybrid-v1.js");
  const { generateMlKemKeypair } =
    await import("../../src/suites/pq-hybrid-v1/index.js");

  const identity = generateMlKemKeypair();
  const plaintext = new Uint8Array(40_000).fill(7);
  const { ciphertext } = await encryptStreamPqHybridV1(
    new Blob([plaintext]).stream(),
    {
      recipientPublicKey: identity.publicKey,
      envelopeKey: randomBytes(32),
      plaintextSize: plaintext.length,
    },
  );
  const bytes = new Uint8Array(await new Response(ciphertext).arrayBuffer());

  const proofKeyHex = Buffer.from(randomBytes(32)).toString("hex");
  const proof = await buildUploadProofV3({ proofKeyHex, ciphertext: bytes });

  const { parseHeader } = await import("../../src/format/header.js");
  const headerLength = parseHeader(bytes).headerLength;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunkZero = view.getUint32(headerLength, false);
  const end = headerLength + 4 + chunkZero;
  const expected = createHmac("sha256", Buffer.from(proofKeyHex, "hex"))
    .update(
      Buffer.concat([Buffer.from([3, 3]), Buffer.from(bytes.subarray(0, end))]),
    )
    .digest();

  const decoded = Buffer.from(proof, "base64");
  assert.equal(decoded.length, 34, "two prefix bytes then a SHA-256 MAC");
  assert.equal(decoded[0], 3);
  assert.equal(decoded[1], 3);
  assert.deepEqual(decoded.subarray(2), expected);

  // A different key, or a single flipped ciphertext byte, is a different proof.
  const other = await buildUploadProofV3({
    proofKeyHex: Buffer.from(randomBytes(32)).toString("hex"),
    ciphertext: bytes,
  });
  assert.notEqual(other, proof);
  const tampered = Uint8Array.from(bytes);
  tampered[headerLength + 8] ^= 0xff;
  assert.notEqual(
    await buildUploadProofV3({ proofKeyHex, ciphertext: tampered }),
    proof,
  );
});

test("the upload proof rejects a first chunk the server verifier would reject", async () => {
  const { encryptStreamPqHybridV1 } =
    await import("../../src/streams/pq-hybrid-v1.js");
  const { generateMlKemKeypair } =
    await import("../../src/suites/pq-hybrid-v1/index.js");
  const { parseHeader } = await import("../../src/format/header.js");

  const { ciphertext } = await encryptStreamPqHybridV1(
    new Blob([new Uint8Array(100).fill(1)]).stream(),
    {
      recipientPublicKey: generateMlKemKeypair().publicKey,
      envelopeKey: randomBytes(32),
      plaintextSize: 100,
    },
  );
  const bytes = new Uint8Array(await new Response(ciphertext).arrayBuffer());
  const headerLength = parseHeader(bytes).headerLength;
  const proofKeyHex = Buffer.from(randomBytes(32)).toString("hex");

  // A chunk_0 length of 16 (tag only, no ciphertext byte) passed here before
  // but the server rejects it; the builder now fails closed with it.
  const short = Uint8Array.from(bytes);
  new DataView(short.buffer).setUint32(headerLength, 16, false);
  await rejects(
    buildUploadProofV3({ proofKeyHex, ciphertext: short }),
    "invalid_input",
  );
});

test("the upload proof refuses a bad key or a truncated container", async () => {
  const bytes = new Uint8Array(64);
  await rejects(
    buildUploadProofV3({ proofKeyHex: "not-hex", ciphertext: bytes }),
    "invalid_input",
  );
});

test("a stored kdf cannot raise the Argon2id cost of an honest name", async () => {
  const folderKey = randomBytes(32);
  const rowId = uuid();
  const honest = await encryptNameV6({ name: "w2.pdf", folderKey, rowId });
  assert.equal(honest.kdf, "interactive");
  const t0 = performance.now();
  const name = await decryptName({
    envelope: { ...honest, kdf: "moderate" },
    folderKey,
    rowId,
  });
  const elapsed = performance.now() - t0;
  assert.equal(name, "w2.pdf");
  // Opens at the interactive level; a moderate derivation alone costs ~1 s.
  const t1 = performance.now();
  await decryptName({ envelope: honest, folderKey, rowId });
  assert.ok(elapsed < (performance.now() - t1) * 3 + 100);
});

test("malformed envelope fields stay inside the VaultCryptoError contract", async () => {
  const folderKey = randomBytes(32);
  const rowId = uuid();
  const good = await encryptNameV6({ name: "a", folderKey, rowId });
  for (const f of ["ct", "iv", "tag", "salt"] as const) {
    await rejects(
      decryptName({
        envelope: { ...good, [f]: "not!base64!" },
        folderKey,
        rowId,
      }),
      "unsupported_envelope",
    );
    await rejects(
      decryptNameWithKey({
        envelope: { ...good, [f]: "not!base64!" },
        nameKey: randomBytes(32),
        rowId,
      }),
      f === "salt" ? "name_decrypt_failed" : "unsupported_envelope",
    );
  }
  await rejects(
    decryptName({ envelope: { ...good, iv: "AAAA" }, folderKey, rowId }),
    "unsupported_envelope",
  );
});

test("upload proof rejects a malformed header as invalid_input", async () => {
  const proofKeyHex = "ab".repeat(32);
  await rejects(
    buildUploadProofV3({ proofKeyHex, ciphertext: new Uint8Array(64) }),
    "invalid_input",
  );
  const junk = randomBytes(256);
  junk.set([0x00, 0x00, 0x00, 0x00], 0);
  await rejects(
    buildUploadProofV3({ proofKeyHex, ciphertext: junk }),
    "invalid_input",
  );
});

test("connection strings have exactly one spelling per token", () => {
  const cred = createGrantCredential({
    grantId: uuid(),
    mlKemPublicKey: randomBytes(1568),
  });
  const s = formatConnectionString(cred);
  assert.deepEqual(parseConnectionString(s).token, cred.token);
  const parts = s.split(".");
  const tokenIdx = parts.length - 3;
  const tok = parts[tokenIdx] as string;
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let accepted = 0;
  for (const c of alphabet) {
    const variant = [...parts];
    variant[tokenIdx] = tok.slice(0, -1) + c;
    try {
      const parsed = parseConnectionString(variant.join("."));
      if (Buffer.from(parsed.token).equals(Buffer.from(cred.token)))
        accepted += 1;
    } catch (e) {
      assert.ok(
        e instanceof VaultCryptoError && e.code === "invalid_connection_string",
      );
    }
  }
  assert.equal(accepted, 1);
});
