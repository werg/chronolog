import { SignalError } from './types.js'
import type { EphemeralSignal, SignalIdentity, SignalPayload } from './types.js'

/** Live messages use their own envelope, not a Chronolog record or transaction codec. */
const PREFIX = new TextEncoder().encode('signal/1\n')
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true })
export const MAX_SIGNAL_BYTES = 16_384
type Fields = readonly [string, string, string, number, number, number, string, SignalPayload]

export function isSignalFrame(input: Uint8Array): boolean {
  return input.length >= PREFIX.length && PREFIX.every((byte, index) => input[index] === byte)
}

export function assertSignalName(value: unknown, kind: 'scope' | 'topic'): void {
  if (typeof value !== 'string' || value.length === 0 || encoder.encode(value).length > (kind === 'scope' ? 512 : 256) ||
      [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) throw new SignalError(`signal_${kind}_invalid`)
}

/** Validate and snapshot before asynchronous work, refusing JSON's lossy coercions. */
export function signalPayload(input: SignalPayload): SignalPayload {
  const seen = new Set<object>()
  let nodes = 0
  const copy = (value: SignalPayload, depth: number): SignalPayload => {
    if (depth > 32 || ++nodes > 4096) throw new SignalError('signal_payload_invalid')
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
    if (typeof value === 'number' && Number.isFinite(value)) return Object.is(value, -0) ? 0 : value
    if (typeof value !== 'object' || seen.has(value)) throw new SignalError('signal_payload_invalid')
    seen.add(value)
    try {
      if (Array.isArray(value)) {
        if (Reflect.ownKeys(value).length !== value.length + 1) throw new SignalError('signal_payload_invalid')
        const result: SignalPayload[] = []
        for (let i = 0; i < value.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(value, i)
          if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable) throw new SignalError('signal_payload_invalid')
          result.push(copy(descriptor.value as SignalPayload, depth + 1))
        }
        return result
      }
      if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new SignalError('signal_payload_invalid')
      if (Reflect.ownKeys(value).length !== Object.keys(value).length) throw new SignalError('signal_payload_invalid')
      const result: Record<string, SignalPayload> = Object.create(null) as Record<string, SignalPayload>
      for (const key of Object.keys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key)!
        if (!('value' in descriptor)) throw new SignalError('signal_payload_invalid')
        result[key] = copy(descriptor.value as SignalPayload, depth + 1)
      }
      return result
    } finally { seen.delete(value) }
  }
  return copy(input, 0)
}

export function signalAuthorId(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new SignalError('signal_identity_invalid')
  return toHex(bytes)
}
function toHex(bytes: Uint8Array): string { return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('') }
function fromHex(value: string): Uint8Array { return Uint8Array.from(value.match(/../gu)!, pair => Number.parseInt(pair, 16)) }
function signedBytes(fields: Fields): Uint8Array {
  const body = encoder.encode(JSON.stringify(fields)), result = new Uint8Array(PREFIX.length + body.length)
  result.set(PREFIX); result.set(body, PREFIX.length); return result
}
function fields(message: EphemeralSignal): Fields {
  return [message.scope, message.authorId, message.sessionId, message.sequence,
    message.issuedAtMs, message.expiresAtMs, message.topic, message.payload]
}

export async function encodeSignal(message: EphemeralSignal, identity: SignalIdentity): Promise<Uint8Array> {
  const body = fields(message), bytes = signedBytes(body)
  // A 64-byte signature is 128 hexadecimal characters, plus the JSON wrapper.
  if (bytes.length + 136 > MAX_SIGNAL_BYTES) throw new SignalError('signal_frame_too_large')
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', identity.privateKey, bytes.slice().buffer))
  const encoded = encoder.encode(JSON.stringify([body, toHex(signature)])), result = new Uint8Array(PREFIX.length + encoded.length)
  result.set(PREFIX); result.set(encoded, PREFIX.length)
  if (result.length > MAX_SIGNAL_BYTES) throw new SignalError('signal_frame_too_large')
  return result
}

export async function decodeSignal(input: Uint8Array): Promise<EphemeralSignal> {
  if (!(input instanceof Uint8Array) || input.length > MAX_SIGNAL_BYTES) throw new SignalError('signal_frame_too_large')
  if (!isSignalFrame(input)) throw new SignalError('signal_frame_invalid')
  let decoded: unknown
  try { decoded = JSON.parse(decoder.decode(input.subarray(PREFIX.length))) as unknown }
  catch { throw new SignalError('signal_frame_invalid') }
  if (!Array.isArray(decoded) || decoded.length !== 2 || !Array.isArray(decoded[0]) || decoded[0].length !== 8 ||
      typeof decoded[1] !== 'string' || !/^[0-9a-f]{128}$/u.test(decoded[1])) throw new SignalError('signal_frame_invalid')
  const body: unknown[] = decoded[0] as unknown[]
  const [scope, authorId, sessionId, sequence, issuedAtMs, expiresAtMs, topic, payload] = body
  if (typeof scope !== 'string' || typeof topic !== 'string' || typeof authorId !== 'string' || !/^[0-9a-f]{64}$/u.test(authorId) ||
      typeof sessionId !== 'string' || !/^[0-9a-f]{64}$/u.test(sessionId) ||
      typeof sequence !== 'number' || !Number.isSafeInteger(sequence) || sequence < 1 ||
      typeof issuedAtMs !== 'number' || !Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 ||
      typeof expiresAtMs !== 'number' || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= issuedAtMs) throw new SignalError('signal_frame_invalid')
  assertSignalName(scope, 'scope'); assertSignalName(topic, 'topic')
  const message = { scope, authorId, sessionId, sequence, issuedAtMs, expiresAtMs, topic, payload: signalPayload(payload as SignalPayload) }
  const key = await crypto.subtle.importKey('raw', fromHex(authorId).buffer as ArrayBuffer, 'Ed25519', false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, fromHex(decoded[1]).buffer as ArrayBuffer, signedBytes(fields(message)).buffer as ArrayBuffer)) {
    throw new SignalError('signal_signature_invalid')
  }
  return message
}

export async function generateSignalIdentity(): Promise<SignalIdentity> {
  const key = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])
  return { privateKey: key.privateKey, publicKeyBytes: new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey)) }
}
