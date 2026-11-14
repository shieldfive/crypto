/**
 * Guard for spec/format-v1.md (suite 0x04): the 0x01 and 0x04 IV spaces
 * overlap. A 0x01 IV is P1[4] || uint64_be(i); a 0x04 IV is
 * P2[8] || uint32_be(i). When P2 == P1 || 00000000 the two IV sequences
 * coincide for every chunk index, and both suites use the same chunk key.
 * The spec must describe this as a 2^-64 bound under caller key reuse,
 * never as "disjoint".
 */

import { strict as assert } from "node:assert";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { HKDF_INFO } from "../../src/internal/types.js";
import { uint32BE, uint64BE } from "../../src/internal/encoding.js";

function v1Iv(p1: Uint8Array, i: number): Uint8Array {
  const iv = new Uint8Array(12);
  iv.set(p1, 0);
  iv.set(uint64BE(i), 4);
  return iv;
}

function v2Iv(p2: Uint8Array, i: number): Uint8Array {
  const iv = new Uint8Array(12);
  iv.set(p2, 0);
  iv.set(uint32BE(i), 8);
  return iv;
}

test("0x01 and 0x04 share the chunk-key label", () => {
  // Both suites read HKDF_INFO.AES_GCM_CHUNK_KEY; only the nonce labels differ.
  assert.notEqual(
    HKDF_INFO.AES_GCM_NONCE_PREFIX,
    HKDF_INFO.AES_GCM_V2_NONCE_PREFIX,
  );
});

test("0x01 and 0x04 IV layouts coincide when P2 == P1 || 0^4", () => {
  const p1 = new Uint8Array([0x0e, 0x07, 0x46, 0x63]);
  const p2 = new Uint8Array([...p1, 0, 0, 0, 0]);
  for (const i of [0, 1, 7, 0xffff, 0xffffffff]) {
    assert.deepEqual(v1Iv(p1, i), v2Iv(p2, i));
  }
});

test("spec does not claim the 0x01/0x04 nonce spaces are disjoint", () => {
  const md = readFileSync(
    fileURLToPath(new URL("../../spec/format-v1.md", import.meta.url)),
    "utf8",
  );
  assert.ok(!/never collide on AEAD inputs/.test(md));
  assert.ok(!/disjoint `\(prefix, counter\)` spaces/.test(md));
  assert.match(md, /\*\*not disjoint\*\*/);
});
