import {
  generateX25519KeyPair,
  exportX25519PrivateKey,
  importX25519PrivateKey,
  generateXWingKeyPair,
  KEY_BOX_SUITE_X25519,
  KEY_BOX_SUITE_XWING,
  type KeyBoxSuite,
} from '@chronolog/crypto'
import { bytesToHex } from '@chronolog/authority'

export { KEY_BOX_SUITE_X25519, KEY_BOX_SUITE_XWING, type KeyBoxSuite }

export interface WrapKeyPair { readonly publicKey: string; readonly privateKey: Uint8Array }
export interface PqWrapKeyPair { readonly publicKey: string; readonly secretKey: Uint8Array }

/** A long-lived X25519 key-wrap key pair. Keep the PKCS#8 private bytes with the device or agent signer, never in authored assets. */
export async function createWrapKeyPair(): Promise<WrapKeyPair> {
  const pair = await generateX25519KeyPair()
  return { publicKey: bytesToHex(pair.publicKeyBytes), privateKey: await exportX25519PrivateKey(pair.privateKey) }
}
export function importWrapPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return importX25519PrivateKey(pkcs8, false)
}

/** A long-lived hybrid post-quantum X-Wing (ML-KEM-768 + X25519) key-wrap key pair (1216B public, 32B secret seed). */
export function createPqWrapKeyPair(seed?: Uint8Array): PqWrapKeyPair {
  const pair = generateXWingKeyPair(seed)
  return { publicKey: bytesToHex(pair.publicKey), secretKey: pair.secretKey }
}
