import { bytesToHex, hexToBytes, sha256 } from '@chronolog/canonical'
import {
  exportEd25519PrivateKey, generateEd25519KeyPair, importEd25519PrivateKey,
  signDomain, verifyDomain, type ProtocolDomain,
} from '@chronolog/protocol'
import type { PeerIdentity, Signed } from './control-types.js'

export { bytesToHex, hexToBytes }
export class PeerGenerationError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'PeerGenerationError' }
}
export function check(condition: unknown, code: string): asserts condition {
  if (!condition) throw new PeerGenerationError(code)
}
export function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null), 'PEER_RECORD_INVALID')
  const record = value as Record<string, unknown>
  check(Object.keys(record).length === keys.length && keys.every(key => Object.hasOwn(record, key)), 'PEER_RECORD_FIELDS_INVALID')
  return record
}
export function boundedText(value: unknown, max = 512): asserts value is string {
  check(typeof value === 'string' && value.length > 0 && value.length <= max && [...value].every(character => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127), 'PEER_TEXT_INVALID')
}
export function hex(value: unknown, bytes = 32): asserts value is string {
  check(typeof value === 'string' && value.length === bytes * 2 && /^[0-9a-f]+$/u.test(value), 'PEER_HEX_INVALID')
}
export function uint(value: unknown, maximum = Number.MAX_SAFE_INTEGER): asserts value is number {
  check(Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= maximum, 'PEER_INTEGER_INVALID')
}
function canonical(value: unknown, depth: number): string {
  check(depth <= 24, 'PEER_RECORD_TOO_DEEP')
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') { check(Number.isSafeInteger(value), 'PEER_INTEGER_INVALID'); return JSON.stringify(value) }
  if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(',')}]`
  check(typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype, 'PEER_RECORD_INVALID')
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonical(record[key], depth + 1)}`).join(',')}}`
}
export function encodePeerValue(value: unknown): Uint8Array {
  const bytes = new TextEncoder().encode(canonical(value, 0))
  check(bytes.length <= 32 * 1024 * 1024, 'PEER_RECORD_TOO_LARGE')
  return bytes
}
export function decodePeerValue<T>(bytes: Uint8Array): T {
  check(bytes.length <= 32 * 1024 * 1024, 'PEER_RECORD_TOO_LARGE')
  const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  check(bytesToHex(encodePeerValue(value)) === bytesToHex(bytes), 'PEER_RECORD_NOT_CANONICAL')
  return value as T
}
export function samePeerValue(left: unknown, right: unknown): boolean { return canonical(left, 0) === canonical(right, 0) }
export async function peerDigest(value: unknown): Promise<string> { return bytesToHex(await sha256(encodePeerValue(value))) }
export async function bytesDigest(value: Uint8Array): Promise<string> { return bytesToHex(await sha256(value)) }
export async function signPeerValue<T>(domain: ProtocolDomain, payload: T, identity: PeerIdentity): Promise<Signed<T>> {
  const captured = structuredClone(payload)
  return { payload: captured, signature: bytesToHex(await signDomain(domain, encodePeerValue(captured), identity.privateKey)) }
}
export async function verifyPeerValue<T>(domain: ProtocolDomain, value: Signed<T>, publicKey: string): Promise<void> {
  object(value, ['payload', 'signature']); hex(value.signature, 64); hex(publicKey)
  check(await verifyDomain(domain, encodePeerValue(value.payload), hexToBytes(value.signature), hexToBytes(publicKey)), 'PEER_SIGNATURE_INVALID')
}
export async function createPeerIdentity(): Promise<PeerIdentity> {
  const pair = await generateEd25519KeyPair()
  return { publicKey: bytesToHex(pair.publicKeyBytes), privateKey: pair.privateKey }
}
export async function exportPeerIdentity(identity: PeerIdentity): Promise<{ publicKey: string; privateKey: string }> {
  return { publicKey: identity.publicKey, privateKey: bytesToHex(await exportEd25519PrivateKey(identity.privateKey)) }
}
export async function importPeerIdentity(value: { readonly publicKey: string; readonly privateKey: string }): Promise<PeerIdentity> {
  object(value, ['publicKey', 'privateKey']); hex(value.publicKey)
  check(typeof value.privateKey === 'string' && /^[0-9a-f]{96,512}$/u.test(value.privateKey), 'PEER_PRIVATE_KEY_INVALID')
  const identity = { publicKey: value.publicKey, privateKey: await importEd25519PrivateKey(hexToBytes(value.privateKey)) }
  const test = new TextEncoder().encode('chronolog/peer-identity/check')
  const signature = await signDomain('chronolog/peer-generation/descriptor/v1', test, identity.privateKey)
  check(await verifyDomain('chronolog/peer-generation/descriptor/v1', test, signature, hexToBytes(identity.publicKey)), 'PEER_IDENTITY_KEY_MISMATCH')
  return identity
}

export class Serial {
  #tail: Promise<void> = Promise.resolve()
  async run<T>(task: () => Promise<T>): Promise<T> {
    const prior = this.#tail
    let release!: () => void
    this.#tail = new Promise(resolve => { release = resolve })
    await prior
    try { return await task() } finally { release() }
  }
}

/** Boolean guard avoids widening typed readonly lists to any[]. */
export function isArray(value: unknown): boolean { return Array.isArray(value) }
