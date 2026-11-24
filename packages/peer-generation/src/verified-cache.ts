import { readBytesMany, type BytesStore } from '@chronolog/records'
import { decryptEpochPayload } from '@chronolog/crypto'
import { decodeTransactionCore, encodeTransactionCore, type TransactionCore } from '@chronolog/protocol'
import { verifyAttempt } from './attempt.js'
import { verifyOrderReceipt, type PeerAuthority } from './control.js'
import { bytesDigest, bytesToHex, check, decodePeerValue, encodePeerValue, hex, hexToBytes, object, peerDigest } from './codec.js'
import type { OrderReceipt, PeerIdentity, SignedAttempt } from './types.js'

interface Verified {
  readonly core: TransactionCore
  readonly encoded: Uint8Array
  readonly source: string
  readonly control: string
  receipt: string | null
  dirty: boolean
}

function validateSource(attempt: SignedAttempt): void {
  object(attempt, ['payload', 'signature', 'id']); hex(attempt.id)
  object(attempt.payload, ['header', 'nonce', 'ciphertext'])
}

/** Local-only authenticated acceleration. Original bytes are still read and hashed on reopen. */
export class VerifiedReplayCache {
  readonly #prefetched = new Map<string, Uint8Array | null>()
  readonly #values = new Map<string, Verified>()
  readonly #owned = new WeakMap<SignedAttempt, Verified>()
  #key: Promise<CryptoKey | null> | undefined
  constructor(readonly store: BytesStore, readonly prefix: string, readonly device: PeerIdentity,
    readonly epochKeys: ReadonlyMap<number, Uint8Array>, readonly enabled = true) {}

  #sealKey(): Promise<CryptoKey | null> {
    return this.#key ??= (async () => {
      if (!this.enabled || !this.device.privateKey.extractable) return null
      const privateBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', this.device.privateKey))
      try {
        const key = await crypto.subtle.importKey('raw', privateBytes, 'HKDF', false, ['deriveKey'])
        return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(this.prefix),
          info: new TextEncoder().encode('chronolog/local-verified-replay-cache/v1') }, key, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify'])
      } finally { privateBytes.fill(0) }
    })().catch(() => null)
  }
  #aad(value: Pick<Verified, 'source' | 'control'>): Uint8Array<ArrayBuffer> {
    return new Uint8Array(encodePeerValue([this.prefix, this.device.publicKey, value.source, value.control]))
  }
  async prefetch(attempts: readonly SignedAttempt[]): Promise<void> {
    for (const attempt of attempts) validateSource(attempt)
    if (await this.#sealKey() === null) return
    const missing = attempts.filter(attempt => !this.#values.has(attempt.id))
    const values = await readBytesMany(this.store, missing.map(attempt => `${this.prefix}/verified/${attempt.id}`))
    for (let index = 0; index < missing.length; index++) this.#prefetched.set(missing[index]!.id, values[index]!)
  }
  async #checkKey(attempt: SignedAttempt, authority: PeerAuthority): Promise<void> {
    const key = this.epochKeys.get(attempt.payload.header.epoch)
    check(key !== undefined, 'PEER_EPOCH_KEY_UNAVAILABLE')
    check(await bytesDigest(key) === authority.controlAt(attempt.payload.header.controlRevision).payload.keyDigest, 'PEER_EPOCH_KEY_MISMATCH')
  }
  async attempt(attempt: SignedAttempt, authority: PeerAuthority): Promise<Verified> {
    validateSource(attempt)
    const owned = this.#owned.get(attempt)
    if (owned !== undefined) { await this.#checkKey(attempt, authority); return owned }
    const source = await bytesDigest(encodePeerValue(attempt))
    const control = await peerDigest(authority.controlAt(authority.generation(attempt.payload.header.generation).payload.controlRevision))
    const known = this.#values.get(attempt.id)
    if (known?.source === source && known.control === control) { await this.#checkKey(attempt, authority); this.#owned.set(attempt, known); return known }
    const key = await this.#sealKey()
    if (key !== null) {
      const stored = this.#prefetched.has(attempt.id) ? this.#prefetched.get(attempt.id)! : await this.store.get(`${this.prefix}/verified/${attempt.id}`)
      this.#prefetched.delete(attempt.id)
      if (stored !== null) {
        try {
          const attestation = decodePeerValue<{ receipt: string | null; mac: string }>(stored)
          check(attestation.receipt === null || typeof attestation.receipt === 'string' && /^[0-9a-f]{64}$/u.test(attestation.receipt), 'PEER_CACHE_INVALID')
          const authenticated = new Uint8Array(encodePeerValue([bytesToHex(this.#aad({ source, control })), attestation.receipt]))
          check(await crypto.subtle.verify('HMAC', key, new Uint8Array(hexToBytes(attestation.mac)), authenticated), 'PEER_CACHE_INVALID')
          await this.#checkKey(attempt, authority)
          const encoded = await decryptEpochPayload(this.epochKeys.get(attempt.payload.header.epoch)!, {
            epoch: BigInt(attempt.payload.header.epoch), nonce: hexToBytes(attempt.payload.nonce), ciphertext: hexToBytes(attempt.payload.ciphertext),
          }, encodePeerValue(attempt.payload.header))
          const core = decodeTransactionCore(encoded)
          const verified = { core, encoded, source, control, receipt: attestation.receipt, dirty: false }
          await this.#checkKey(attempt, authority)
          this.#values.set(attempt.id, verified); this.#owned.set(attempt, verified)
          return verified
        } catch { /* A stale or corrupt cache never substitutes for full origin verification. */ }
      }
    }
    const core = await verifyAttempt(attempt, authority, this.epochKeys)
    const verified = { core, encoded: encodeTransactionCore(core), source, control, receipt: null, dirty: true }
    this.#values.set(attempt.id, verified); this.#owned.set(attempt, verified)
    return verified
  }
  async receipt(receipt: OrderReceipt, attempt: SignedAttempt, authority: PeerAuthority): Promise<Verified> {
    const verified = await this.attempt(attempt, authority), digest = await bytesDigest(encodePeerValue(receipt))
    if (verified.receipt !== digest) {
      await verifyOrderReceipt(receipt, authority.generation(receipt.payload.generation), authority.descriptor)
      verified.receipt = digest; verified.dirty = true
    }
    return verified
  }
  get dirtyCount(): number {
    let count = 0
    for (const value of this.#values.values()) if (value.dirty) count++
    return count
  }
  /** Optional acceleration written periodically and at clean close, never blocking the command critical path. */
  async flush(): Promise<void> {
    const key = await this.#sealKey()
    if (key === null) return
    for (const [id, value] of this.#values) {
      if (!value.dirty) continue
      try {
        const authenticated = new Uint8Array(encodePeerValue([bytesToHex(this.#aad(value)), value.receipt]))
        const mac = await crypto.subtle.sign('HMAC', key, authenticated)
        await this.store.put(`${this.prefix}/verified/${id}`, encodePeerValue({ receipt: value.receipt, mac: bytesToHex(new Uint8Array(mac)) }))
        value.dirty = false
      } catch { /* Cache quota/I/O failure cannot invalidate a committed journal. */ }
    }
  }
}
