import { bytesToHex, hexToBytes, equalBytes, sha256 } from '@chronolog/canonical'
import { generateEd25519KeyPair, exportEd25519PrivateKey, importEd25519PrivateKey, verifyEd25519Sync } from '@chronolog/protocol'
export { bytesToHex, hexToBytes }
export interface SigningIdentity { readonly publicKey: string; readonly privateKey: CryptoKey }
export interface Signed<T> { readonly payload: T; readonly signer: string; readonly signature: string }
export function check(condition: unknown, code: string): asserts condition { if (!condition) throw Object.assign(new Error(code), { code }) }
export function hex(value: unknown, length = 32): asserts value is string { check(typeof value === 'string' && new RegExp(`^[0-9a-f]{${length * 2}}$`, 'u').test(value), 'AUTHORITY_HEX_INVALID') }
function normalized(value: unknown, depth = 0): unknown {
  check(depth < 32, 'RECORD_DEPTH_LIMIT')
  if (value instanceof Uint8Array) return { $bytes: bytesToHex(value) }
  if (typeof value === 'bigint') return { $integer: value.toString() }
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') { check(Number.isSafeInteger(value), 'RECORD_INTEGER_INVALID'); return value }
  if (Array.isArray(value)) return value.map(item => normalized(item, depth + 1))
  check(value !== null && typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null), 'RECORD_INVALID')
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, normalized((value as Record<string, unknown>)[key], depth + 1)]))
}
export function encodeRecord(value: unknown): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify(normalized(value)))
  check(bytes.length <= 32 * 1024 * 1024, 'RECORD_BYTES_LIMIT'); return bytes
}
export function decodeRecord<T>(bytes: Uint8Array): T {
  check(bytes.length <= 32 * 1024 * 1024, 'RECORD_BYTES_LIMIT')
  const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes), (_key, item: unknown) => {
    if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
      const record = item as Record<string, unknown>
      if (Object.keys(record).length === 1 && typeof record.$bytes === 'string') { check(/^(?:[0-9a-f]{2})*$/u.test(record.$bytes), 'RECORD_BYTES_INVALID'); return hexToBytes(record.$bytes) }
      if (Object.keys(record).length === 1 && typeof record.$integer === 'string') { check(/^-?(?:0|[1-9][0-9]*)$/u.test(record.$integer), 'RECORD_INTEGER_INVALID'); return BigInt(record.$integer) }
    }
    return item
  })
  check(equalRecord(value, decodeUncanonical(bytes)), 'RECORD_INVALID')
  check(equalBytes(encodeRecord(value), bytes), 'RECORD_NOT_CANONICAL')
  return value as T
}
function decodeUncanonical(bytes: Uint8Array): unknown { return JSON.parse(new TextDecoder().decode(bytes)) as unknown }
export function equalRecord(a: unknown, b: unknown): boolean { return equalBytes(encodeRecord(a), encodeRecord(b)) }
export async function recordDigest(value: unknown): Promise<string> { return bytesToHex(await sha256(encodeRecord(value))) }
function signedBytes(domain: string, payload: unknown): Uint8Array { return encodeRecord(['chronolog/authored/v1', domain, payload]) }
export async function signRecord<T>(domain: string, payload: T, identity: SigningIdentity): Promise<Signed<T>> {
  hex(identity.publicKey)
  const captured = structuredClone(payload)
  const signature = bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', identity.privateKey, Uint8Array.from(signedBytes(domain, captured)).buffer)))
  const result = { payload: captured, signer: identity.publicKey, signature }
  await verifyRecord(domain, result, identity.publicKey); return result
}
export async function verifyRecord<T>(domain: string, signed: Signed<T>, expectedSigner?: string): Promise<void> {
  hex(signed.signer); hex(signed.signature, 64)
  check(expectedSigner === undefined || signed.signer === expectedSigner, 'AUTHORITY_SIGNER_MISMATCH')
  check(verifyEd25519Sync(hexToBytes(signed.signer), signedBytes(domain, signed.payload), hexToBytes(signed.signature)), 'AUTHORITY_SIGNATURE_INVALID')
}
export async function createSigningIdentity(): Promise<SigningIdentity> { const pair = await generateEd25519KeyPair(); return { publicKey: bytesToHex(pair.publicKeyBytes), privateKey: pair.privateKey } }
export async function exportSigningIdentity(identity: SigningIdentity): Promise<{ publicKey: string; privateKey: string }> { return { publicKey: identity.publicKey, privateKey: bytesToHex(await exportEd25519PrivateKey(identity.privateKey)) } }
export async function importSigningIdentity(value: { readonly publicKey: string; readonly privateKey: string }): Promise<SigningIdentity> { hex(value.publicKey); return { publicKey: value.publicKey, privateKey: await importEd25519PrivateKey(hexToBytes(value.privateKey)) } }
