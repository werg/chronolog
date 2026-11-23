import { sha256 } from '@chronolog/canonical'

import { concatBytes, utf8 } from './bytes.js'
import { ProtocolError, protocolInvariant } from './errors.js'

export const DOMAINS = {
  transaction: 'chronolog/transaction-core/v1',
  materializedLog: 'chronolog/materialized-log/v1',
  peerDescriptor: 'chronolog/peer-generation/descriptor/v1',
  celldApplicationInvitation: 'chronolog/celld/application-invitation/v1',
  celldWorkspacePublication: 'chronolog/celld/workspace-publication/v1',
  peerSchema: 'chronolog/peer-generation/schema/v1',
  peerPublication: 'chronolog/publication/v1',
  peerControl: 'chronolog/peer-generation/control/v1',
  peerGeneration: 'chronolog/peer-generation/generation/v1',
  peerTransition: 'chronolog/peer-generation/transition/v1',
  peerAttempt: 'chronolog/peer-generation/attempt/v1',
  peerOrder: 'chronolog/peer-generation/order/v1',
  peerCoverage: 'chronolog/peer-generation/coverage/v1',
  peerConnection: 'chronolog/peer-generation/connection/v1',
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
  try {
    const signature = await globalThis.crypto.subtle.sign(ED25519, privateKey, bufferSource(domainSeparatedBytes(domain, payload)))
    return new Uint8Array(signature)
  } catch {
    throw new ProtocolError('INVALID_KEY', 'Unable to sign with Ed25519 key')
  }
}

export async function verifyDomain(
  domain: ProtocolDomain,
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: CryptoKey | Uint8Array,
): Promise<boolean> {
  if (signature.length !== 64) return false
  try {
    const key = publicKey instanceof Uint8Array ? await importEd25519PublicKey(publicKey) : publicKey
    return await globalThis.crypto.subtle.verify(
      ED25519,
      key,
      bufferSource(signature),
      bufferSource(domainSeparatedBytes(domain, payload)),
    )
  } catch {
    return false
  }
}
