/**
 * Guard: keep `spec/key-derivation.md`'s "Forbidden cross-context usage"
 * list in one-to-one correspondence with the HKDF labels the library
 * actually consumes (`HKDF_INFO` in src/internal/types.ts).
 *
 * A label that is consumed but missing from the forbidden list is a real
 * domain-separation gap: a spec-following host could reuse it for an
 * unrelated derivation and collide with a library key (audit finding —
 * the three `shieldfive/v1/inbound/*` labels were omitted). This test
 * fails if the two ever drift, in either direction.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { HKDF_INFO } from '../../src/internal/types.js'

function fencedBlockAfterHeading(md: string, heading: string): string[] {
  const headingIdx = md.indexOf(heading)
  assert.ok(headingIdx !== -1, `heading not found: ${heading}`)
  const fenceStart = md.indexOf('```', headingIdx)
  assert.ok(fenceStart !== -1, `no code fence after: ${heading}`)
  const bodyStart = md.indexOf('\n', fenceStart) + 1
  const fenceEnd = md.indexOf('```', bodyStart)
  assert.ok(fenceEnd !== -1, `unterminated code fence after: ${heading}`)
  return md
    .slice(bodyStart, fenceEnd)
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
}

test('spec forbidden-list is exactly the consumed HKDF_INFO labels', () => {
  const specPath = fileURLToPath(
    new URL('../../spec/key-derivation.md', import.meta.url),
  )
  const md = readFileSync(specPath, 'utf8')

  const forbidden = new Set(
    fencedBlockAfterHeading(md, '## Forbidden cross-context usage'),
  )
  const consumed = Object.values(HKDF_INFO)

  // Every consumed label MUST be forbidden (no domain-separation gap).
  for (const label of consumed) {
    assert.ok(
      forbidden.has(label),
      `HKDF_INFO label "${label}" is consumed but missing from the spec's forbidden list`,
    )
  }

  // And the forbidden list carries no phantom entries the library never
  // consumes (that is what the "Reserved for future use" block is for).
  const consumedSet = new Set<string>(consumed)
  for (const label of forbidden) {
    assert.ok(
      consumedSet.has(label),
      `spec forbidden list has "${label}" but HKDF_INFO never consumes it (move it to "Reserved for future use")`,
    )
  }

  assert.equal(
    forbidden.size,
    consumedSet.size,
    'forbidden list and HKDF_INFO must be one-to-one',
  )
})

test('spec reserved-for-future labels are NOT consumed by HKDF_INFO', () => {
  const specPath = fileURLToPath(
    new URL('../../spec/key-derivation.md', import.meta.url),
  )
  const md = readFileSync(specPath, 'utf8')

  const reserved = fencedBlockAfterHeading(md, '### Reserved for future use')
  const consumed = new Set<string>(Object.values(HKDF_INFO))

  for (const label of reserved) {
    assert.ok(
      !consumed.has(label),
      `"${label}" is listed as reserved-for-future but HKDF_INFO already consumes it`,
    )
  }
})
