#!/usr/bin/env node
/**
 * Keep the `SHIELDFIVE_CRYPTO_VERSION` constant in `src/index.ts` in sync
 * with `package.json`'s version.
 *
 * Run automatically by npm's `version` lifecycle (see the "version" script
 * in package.json): `npm version <bump>` updates package.json, then runs
 * this, then commits — so the constant update lands in the SAME version
 * commit. Without it the constant drifts, the `version-constant` guard
 * test fails, and the release workflow skips the npm publish (as happened
 * on the first rc.4 attempt).
 *
 * Idempotent: a no-op when already in sync. Exits non-zero if the constant
 * can't be found, so a rename can't silently break the release.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = new URL('../', import.meta.url)
const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'))
const indexPath = fileURLToPath(new URL('src/index.ts', root))

const src = readFileSync(indexPath, 'utf8')
const re = /(export const SHIELDFIVE_CRYPTO_VERSION = ')[^']*(')/

if (!re.test(src)) {
  console.error(
    'sync-version: SHIELDFIVE_CRYPTO_VERSION not found in src/index.ts — ' +
      'the constant may have been renamed; update scripts/sync-version.mjs.',
  )
  process.exit(1)
}

const updated = src.replace(re, `$1${pkg.version}$2`)
if (updated === src) {
  console.log(`sync-version: SHIELDFIVE_CRYPTO_VERSION already ${pkg.version}`)
} else {
  writeFileSync(indexPath, updated)
  console.log(`sync-version: SHIELDFIVE_CRYPTO_VERSION -> ${pkg.version}`)
}
