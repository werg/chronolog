import { generateX25519KeyPair, HPKE_SUITE, hpkeReceiveExportBase, hpkeSendExportBase, type X25519KeyPair } from '@chronolog/crypto'
import { encodePeerValue } from '@chronolog/peer-generation'
import { bytesToHex, hexToBytes } from '@chronolog/protocol'
import type { FramedPeerConnection, PeerLiveLane } from '@chronolog/records'
import { MAX_SIGNAL_BYTES } from '@chronolog/signals'
import { APPLICATION_NETWORK_LIMITS, requireNetwork } from './network-wire.js'

export const APPLICATION_CHANNEL_SUITE = `${HPKE_SUITE}/peer-record-v1` as const
export const APPLICATION_CHANNEL_LIMITS = Object.freeze({ overheadBytes: 22, records: 2 ** 24, plaintextBytes: 2 ** 32 })
export interface ApplicationChannelHello { readonly suite: typeof APPLICATION_CHANNEL_SUITE; readonly receiverKey: string }
const DOMAIN = 'chronolog/peer-channel/v1'
// These disjoint slices are independent exporter output, never HPKE's own AEAD key.
const EXPORT_CONTEXT = encodePeerValue({ domain: DOMAIN, layout: ['reliable-key:32', 'reliable-nonce:12', 'live-key:32', 'live-nonce:12'] })
const HEADER = 6, TAG = 16
const limit = (live: boolean): number => live ? MAX_SIGNAL_BYTES : APPLICATION_NETWORK_LIMITS.fragmentBytes + 128
const source = (bytes: Uint8Array): ArrayBuffer => Uint8Array.from(bytes).buffer
const context = (sender: unknown, receiver: unknown): Uint8Array => encodePeerValue({ domain: DOMAIN, suite: APPLICATION_CHANNEL_SUITE, sender, receiver })

/** One direction and one lane. A nonce is consumed even when a live dispatch is dropped. */
class RecordCipher {
  #key: CryptoKey | undefined
  readonly #baseNonce: Uint8Array
  readonly #live: boolean
  #sequence = 0
  #bytes = 0
  constructor(key: CryptoKey, nonce: Uint8Array, live: boolean) { this.#key = key; this.#baseNonce = nonce; this.#live = live }
  #nonce(sequence: number): Uint8Array {
    const nonce = this.#baseNonce.slice(), view = new DataView(nonce.buffer)
    view.setUint32(8, view.getUint32(8) ^ sequence)
    return nonce
  }
  #budget(length: number): void {
    requireNetwork(this.#key !== undefined, 'APPLICATION_CHANNEL_CLOSED')
    requireNetwork(this.#sequence < APPLICATION_CHANNEL_LIMITS.records && this.#bytes + length <= APPLICATION_CHANNEL_LIMITS.plaintextBytes,
      'APPLICATION_CHANNEL_KEY_EXHAUSTED')
  }
  async seal(input: Uint8Array): Promise<Uint8Array> {
    requireNetwork(input instanceof Uint8Array && input.length > 0 && input.length <= limit(this.#live), 'APPLICATION_CHANNEL_FRAME_LIMIT')
    this.#budget(input.length)
    const sequence = ++this.#sequence, header = Uint8Array.of(1, this.#live ? 2 : 1, 0, 0, 0, 0)
    new DataView(header.buffer).setUint32(2, sequence)
    this.#bytes += input.length
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: source(this.#nonce(sequence)),
      additionalData: source(header), tagLength: 128 }, this.#key!, source(input)))
    const result = new Uint8Array(header.length + encrypted.length)
    result.set(header); result.set(encrypted, HEADER); return result
  }
  async open(input: Uint8Array): Promise<Uint8Array | null> {
    requireNetwork(input instanceof Uint8Array && input.length > HEADER + TAG && input.length <= limit(this.#live) + HEADER + TAG,
      'APPLICATION_CHANNEL_FRAME_LIMIT')
    requireNetwork(input[0] === 1 && input[1] === (this.#live ? 2 : 1), 'APPLICATION_CHANNEL_FRAME_INVALID')
    const sequence = new DataView(input.buffer, input.byteOffset, HEADER).getUint32(2)
    requireNetwork(sequence > 0 && sequence <= APPLICATION_CHANNEL_LIMITS.records, 'APPLICATION_CHANNEL_SEQUENCE_INVALID')
    // A live transport may legitimately lose or reorder records. Old records
    // never update the accepted sequence or reach the signal owner.
    if (this.#live && sequence <= this.#sequence) return null
    requireNetwork(this.#live || sequence === this.#sequence + 1, 'APPLICATION_CHANNEL_SEQUENCE_INVALID')
    this.#budget(input.length - HEADER - TAG)
    let plaintext: Uint8Array
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: source(this.#nonce(sequence)),
        additionalData: source(input.subarray(0, HEADER)), tagLength: 128 }, this.#key!, source(input.subarray(HEADER))))
    } catch { throw new Error('APPLICATION_CHANNEL_AUTHENTICATION_FAILED') }
    this.#sequence = sequence; this.#bytes += plaintext.length
    return plaintext
  }
  clear(): void { this.#key = undefined; this.#baseNonce.fill(0) }
}
interface Direction { readonly reliable: RecordCipher; readonly live: RecordCipher }
async function direction(secret: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<Direction> {
  requireNetwork(secret.length === 88, 'APPLICATION_CHANNEL_KEY_INVALID')
  try {
    const reliable = await crypto.subtle.importKey('raw', source(secret.subarray(0, 32)), 'AES-GCM', false, [usage])
    const live = await crypto.subtle.importKey('raw', source(secret.subarray(44, 76)), 'AES-GCM', false, [usage])
    return { reliable: new RecordCipher(reliable, secret.slice(32, 44), false), live: new RecordCipher(live, secret.slice(76, 88), true) }
  } finally { secret.fill(0) }
}
function clear(value: Direction | undefined): void { value?.reliable.clear(); value?.live.clear() }

/**
 * Transport-independent channel beneath the single application wire. Public
 * hello/proof messages establish fresh keys; every following record is encrypted.
 * Ed25519 proof verification is owned by NetworkPeer, before accepting an export.
 */
export class ApplicationSecureChannel {
  readonly connection: FramedPeerConnection
  readonly #signal: AbortSignal
  #receiver: X25519KeyPair | undefined
  #outbound: Direction | undefined
  #inbound: Direction | undefined
  #hello = false
  #preparing = false
  #sending = false
  #closed = false
  #reliableBusy = false
  #liveBusy = false
  readonly #onAbort = (): void => this.clear()
  constructor(raw: FramedPeerConnection, signal: AbortSignal) {
    this.#signal = AbortSignal.any([signal, raw.signal])
    const lifetime = this.#signal, channel = this
    const live: PeerLiveLane | undefined = raw.live === undefined ? undefined : {
      signal: AbortSignal.any([lifetime, raw.live.signal]),
      async trySend(frame, options = {}) {
        const signal = options.signal === undefined ? lifetime : AbortSignal.any([lifetime, options.signal])
        channel.#open(); signal.throwIfAborted()
        requireNetwork(channel.#sending && channel.#outbound !== undefined, 'APPLICATION_PEER_AUTHENTICATION_REQUIRED')
        if (channel.#liveBusy) return false
        channel.#liveBusy = true
        try {
          const encrypted = await channel.#outbound.live.seal(frame)
          channel.#open(); signal.throwIfAborted()
          return await raw.live!.trySend(encrypted, { signal })
        } finally { channel.#liveBusy = false }
      },
      async *frames(signal) {
        const lifetime = signal === undefined ? channel.#signal : AbortSignal.any([channel.#signal, signal])
        for await (const frame of raw.live!.frames(lifetime)) {
          channel.#open(); lifetime.throwIfAborted()
          requireNetwork(channel.#inbound !== undefined, 'APPLICATION_PEER_AUTHENTICATION_REQUIRED')
          const plaintext = await channel.#inbound.live.open(frame)
          channel.#open(); lifetime.throwIfAborted()
          if (plaintext !== null) yield plaintext
        }
      },
      close: () => raw.live!.close(),
    }
    this.connection = {
      signal: lifetime, ...(live === undefined ? {} : { live }),
      async send(frame, options = {}) {
        const signal = options.signal === undefined ? lifetime : AbortSignal.any([lifetime, options.signal])
        channel.#open(); signal.throwIfAborted()
        requireNetwork(!channel.#reliableBusy, 'APPLICATION_NETWORK_BACKPRESSURE')
        channel.#reliableBusy = true
        try {
          const bytes = channel.#sending ? await channel.#outbound!.reliable.seal(frame) : frame
          channel.#open(); signal.throwIfAborted()
          await raw.send(bytes, { signal })
        } catch (error) {
          // A sealed reliable record consumes its nonce even if dispatch fails.
          // Retire this connection; never reuse that nonce or leave a sequence gap.
          if (channel.#sending) { channel.clear(); void raw.close().catch(() => undefined) }
          throw error
        } finally { channel.#reliableBusy = false }
      },
      async *frames(signal) {
        const lifetime = signal === undefined ? channel.#signal : AbortSignal.any([channel.#signal, signal])
        for await (const frame of raw.frames(lifetime)) {
          channel.#open(); lifetime.throwIfAborted()
          const plaintext = channel.#inbound === undefined ? frame : await channel.#inbound.reliable.open(frame)
          channel.#open(); lifetime.throwIfAborted()
          yield plaintext!
        }
      },
      close: async () => { channel.clear(); await raw.close() },
    }
    lifetime.addEventListener('abort', this.#onAbort, { once: true })
    if (lifetime.aborted) this.clear()
  }
  #open(): void { this.#signal.throwIfAborted(); requireNetwork(!this.#closed, 'APPLICATION_CHANNEL_CLOSED') }
  async hello(): Promise<ApplicationChannelHello> {
    this.#open(); requireNetwork(!this.#hello, 'APPLICATION_NETWORK_HANDSHAKE_ORDER'); this.#hello = true
    const receiver = await generateX25519KeyPair(false)
    this.#open(); this.#receiver = receiver
    return { suite: APPLICATION_CHANNEL_SUITE, receiverKey: bytesToHex(receiver.publicKeyBytes) }
  }
  async prepare(peerReceiverKey: string, sender: unknown, receiver: unknown): Promise<string> {
    this.#open(); requireNetwork(!this.#preparing, 'APPLICATION_NETWORK_HANDSHAKE_ORDER'); this.#preparing = true
    const exported = await hpkeSendExportBase(hexToBytes(peerReceiverKey), context(sender, receiver), EXPORT_CONTEXT, 88)
    try {
      this.#open()
      const outbound = await direction(exported.exportedSecret, 'encrypt')
      if (this.#closed || this.#signal.aborted) { clear(outbound); this.#open() }
      this.#outbound = outbound
      return bytesToHex(exported.encapsulatedKey)
    } finally { exported.exportedSecret.fill(0) }
  }
  /** Called only when every public proof fragment has been dispatched. */
  enableSending(): void {
    this.#open(); requireNetwork(this.#outbound !== undefined && !this.#sending, 'APPLICATION_NETWORK_HANDSHAKE_ORDER'); this.#sending = true
  }
  async accept(encapsulatedKey: string, sender: unknown, receiver: unknown): Promise<void> {
    this.#open(); requireNetwork(this.#receiver !== undefined && this.#inbound === undefined, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
    const key = this.#receiver; this.#receiver = undefined
    const secret = await hpkeReceiveExportBase(key.privateKey, key.publicKeyBytes, hexToBytes(encapsulatedKey), context(sender, receiver), EXPORT_CONTEXT, 88)
    try {
      this.#open()
      const inbound = await direction(secret, 'decrypt')
      if (this.#closed || this.#signal.aborted) { clear(inbound); this.#open() }
      this.#inbound = inbound
    } finally { secret.fill(0) }
  }
  clear(): void {
    if (this.#closed) return
    this.#closed = true; this.#receiver = undefined
    this.#signal.removeEventListener('abort', this.#onAbort)
    clear(this.#outbound); clear(this.#inbound); this.#outbound = undefined; this.#inbound = undefined
  }
}
