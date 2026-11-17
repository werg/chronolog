import {
  CanonicalError,
  bytesToHex as sharedBytesToHex,
  compareBytes,
  concatBytes,
  copyBytes,
  decodeUtf8 as sharedDecodeUtf8,
  equalBytes,
  hexToBytes as sharedHexToBytes,
  utf8 as sharedUtf8,
} from '@chronolog/canonical'

import { ProtocolError, protocolInvariant } from './errors.js'

export { compareBytes, concatBytes, copyBytes, equalBytes }

function wrap<T>(operation: () => T): T {
  try { return operation() } catch (error) {
    if (error instanceof ProtocolError) throw error
    if (error instanceof CanonicalError) throw new ProtocolError(error.code as never, error.message, error.details)
    throw error
  }
}

export function utf8(value: string): Uint8Array { return wrap(() => sharedUtf8(value)) }
export function decodeUtf8(value: Uint8Array): string { return wrap(() => sharedDecodeUtf8(value)) }
export function bytesToHex(value: Uint8Array): string { return sharedBytesToHex(value) }
export function hexToBytes(value: string): Uint8Array { return wrap(() => sharedHexToBytes(value)) }

/** Canonical unpadded base64url using only APIs shared by browsers and Node. */
export function bytesToBase64Url(value: Uint8Array): string {
  let binary = ''
  for (let offset = 0; offset < value.length; offset += 16_384) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 16_384))
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

export function base64UrlToBytes(value: string): Uint8Array {
  protocolInvariant(/^[A-Za-z0-9_-]*$/u.test(value) && value.length % 4 !== 1,
    'SCHEMA_INVALID', 'Bytes must use canonical unpadded base64url')
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'))
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  protocolInvariant(bytesToBase64Url(bytes) === value, 'SCHEMA_INVALID', 'Bytes must use canonical unpadded base64url')
  return bytes
}

export function assertByteLength(value: Uint8Array, length: number, field: string): Uint8Array {
  protocolInvariant(value.length === length, 'SCHEMA_INVALID', `${field} must contain exactly ${length} bytes`, { field, expected: length, actual: value.length })
  return value
}
