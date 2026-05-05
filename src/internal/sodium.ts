/**
 * Lazy loader for libsodium-wrappers-sumo.
 *
 * libsodium is loaded on demand only when a suite that needs it (XChaCha,
 * PQ hybrid, password-based KDF) is actually used. Consumers using only
 * AES-256-GCM never load the WASM blob.
 *
 * libsodium is declared as an optional peer dependency in package.json.
 * Bundlers should treat it as side-effect-free.
 */

let cachedSodium: any | null = null
let pendingInit: Promise<any> | null = null

export async function getSodium(): Promise<any> {
  if (cachedSodium) return cachedSodium

  if (!pendingInit) {
    pendingInit = (async () => {
      let sodium: any
      try {
        // Dynamic import keeps libsodium out of bundles that don't use it.
        sodium = (await import('libsodium-wrappers-sumo')).default
      } catch (err) {
        throw new Error(
          'shieldfive-crypto: libsodium-wrappers-sumo is required for ' +
            'this cipher suite. Install it as a dependency.',
          { cause: err as Error },
        )
      }
      await sodium.ready
      cachedSodium = sodium
      return sodium
    })()
  }

  return pendingInit
}
