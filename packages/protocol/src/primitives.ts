import { perfCount, sha256 } from '@chronolog/canonical'
import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'

import { concatBytes, utf8 } from './bytes.js'
import { ProtocolError, protocolInvariant } from './errors.js'

export const DOMAINS = {
  transaction: 'chronolog/transaction-core/v1',
  materializedLog: 'chronolog/materialized-log/v1',
  celldApplicationInvitation: 'chronolog/celld/application-invitation/v1',
  celldWorkspacePublication: 'chronolog/celld/workspace-publication/v1',
  publication: 'chronolog/publication/v1',
  materializedSnapshot: 'chronolog/materialized-snapshot/v3',
} as const

export type ProtocolDomain = (typeof DOMAINS)[keyof typeof DOMAINS]

export function domainSeparatedBytes(domain: ProtocolDomain, payload: Uint8Array): Uint8Array {
  return concatBytes(utf8(domain), Uint8Array.of(0), payload)
}

export async function hashDomain(domain: ProtocolDomain, payload: Uint8Array): Promise<Uint8Array> {
  return sha256(domainSeparatedBytes(domain, payload))
}

export interface Ed25519KeyPair {
  readonly publicKey: CryptoKey
  readonly privateKey: CryptoKey
  readonly publicKeyBytes: Uint8Array
}

const ED25519: AlgorithmIdentifier = { name: 'Ed25519' }

function bufferSource(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer
}

export async function generateEd25519KeyPair(extractable = true): Promise<Ed25519KeyPair> {
  const pair = await globalThis.crypto.subtle.generateKey(ED25519, extractable, ['sign', 'verify']) as CryptoKeyPair
  const publicKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey))
  return { publicKey: pair.publicKey, privateKey: pair.privateKey, publicKeyBytes }
}

export async function importEd25519PublicKey(raw: Uint8Array): Promise<CryptoKey> {
  protocolInvariant(raw.length === 32, 'INVALID_KEY', 'Ed25519 public key must contain 32 bytes')
  try {
    return await globalThis.crypto.subtle.importKey('raw', bufferSource(raw), ED25519, true, ['verify'])
  } catch {
    throw new ProtocolError('INVALID_KEY', 'Unable to import Ed25519 public key')
  }
}

export async function importEd25519PrivateKey(pkcs8: Uint8Array, extractable = true): Promise<CryptoKey> {
  try {
    return await globalThis.crypto.subtle.importKey('pkcs8', bufferSource(pkcs8), ED25519, extractable, ['sign'])
  } catch {
    throw new ProtocolError('INVALID_KEY', 'Unable to import Ed25519 private key')
  }
}

export async function exportEd25519PrivateKey(privateKey: CryptoKey): Promise<Uint8Array> {
  try {
    return new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', privateKey))
  } catch {
    throw new ProtocolError('INVALID_KEY', 'Ed25519 private key is not extractable')
  }
}

export async function signDomain(
  domain: ProtocolDomain,
  payload: Uint8Array,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  perfCount('ed25519.sign')
  try {
    const signature = await globalThis.crypto.subtle.sign(ED25519, privateKey, bufferSource(domainSeparatedBytes(domain, payload)))
    return new Uint8Array(signature)
  } catch {
    throw new ProtocolError('INVALID_KEY', 'Unable to sign with Ed25519 key')
  }
}

ed.hashes.sha512 = (message: Uint8Array) => sha512(message) as Uint8Array<ArrayBuffer>

/**
 * Chronolog's single Ed25519 verification rule set (RFC 8032 / FIPS 186-5 strict, noble `zip215: false`):
 * canonical `A` and `R` encodings (`y < p`), `S < L`, small-order public keys rejected, cofactored
 * group equation. Operation signatures, host attestations, authority records, reducers
 * (`chronolog:crypto`) and blind hosts all verify with exactly this function, so signature acceptance
 * is a deterministic function of the bytes on every runtime (WebCrypto is never consulted).
 */
export function verifyEd25519Sync(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false
  perfCount('ed25519.verify')
  try {
    return ed.verify(signature, message, publicKey, { zip215: false })
  } catch {
    return false
  }
}

/** Raw public key bytes per imported verification `CryptoKey` (one export per key object). */
const rawKeys = new WeakMap<CryptoKey, Promise<Uint8Array | null>>()
function rawPublicKey(key: CryptoKey): Promise<Uint8Array | null> {
  let raw = rawKeys.get(key)
  if (raw === undefined) {
    raw = globalThis.crypto.subtle.exportKey('raw', key).then(buf => new Uint8Array(buf), () => null)
    rawKeys.set(key, raw)
  }
  return raw
}

/**
 * Async convenience over `verifyEd25519Sync` that also accepts an extractable `CryptoKey`
 * (a non-extractable key cannot be verified and returns false).
 */
export async function verifyEd25519(
  publicKey: CryptoKey | Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const raw = publicKey instanceof Uint8Array ? publicKey : await rawPublicKey(publicKey)
  return raw !== null && verifyEd25519Sync(raw, message, signature)
}

export async function verifyDomain(
  domain: ProtocolDomain,
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: CryptoKey | Uint8Array,
): Promise<boolean> {
  return verifyEd25519(publicKey, domainSeparatedBytes(domain, payload), signature)
}
