import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import { SHIELDFIVE_CRYPTO_VERSION } from '../../src/index.js'

// Guard against shipping a stale hand-maintained version string. The release
// workflow only checks package.json against the git tag, so without this the
// exported SHIELDFIVE_CRYPTO_VERSION can silently diverge from the real version
// (as it did in 1.0.0-beta.4, published still reporting beta.3). Since the
// release CI runs the test suite, this fails the release if the two disagree.
test('SHIELDFIVE_CRYPTO_VERSION matches package.json version', () => {
  const pkg = JSON.parse(
    readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
  ) as { version: string }
  assert.equal(SHIELDFIVE_CRYPTO_VERSION, pkg.version)
})
