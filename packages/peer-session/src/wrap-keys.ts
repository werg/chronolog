import { generateX25519KeyPair, exportX25519PrivateKey, importX25519PrivateKey } from '@chronolog/crypto'
import { bytesToHex } from '@chronolog/authority'
export interface WrapKeyPair { readonly publicKey: string; readonly privateKey: Uint8Array }
/** A long-lived X25519 key-wrap key pair. Keep the PKCS#8 private bytes with the device or agent signer, never in authored assets. */
export async function createWrapKeyPair(): Promise<WrapKeyPair> { const pair = await generateX25519KeyPair(); return { publicKey: bytesToHex(pair.publicKeyBytes), privateKey: await exportX25519PrivateKey(pair.privateKey) } }
export function importWrapPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> { return importX25519PrivateKey(pkcs8, false) }
