import { bytesToHex, sha256 } from '@chronolog/canonical'

export function validatePayloadHash(hash: string): void {
  if (!/^[0-9a-f]{64}$/u.test(hash)) throw new Error('PAYLOAD_HASH_INVALID')
}

export async function payloadHash(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(bytes))
}

export async function verifyPayloadHash(hash: string, bytes: Uint8Array): Promise<void> {
  validatePayloadHash(hash)
  if (await payloadHash(bytes) !== hash) throw new Error('PAYLOAD_HASH_MISMATCH')
}
