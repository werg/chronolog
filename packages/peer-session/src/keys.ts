import { generateX25519KeyPair, hpkeOpenBase, hpkeSealBase } from '@chronolog/crypto'
import {
  bytesDigest, decodePeerValue, encodePeerValue, peerDigest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerIdentity, type PeerReplica, type PeerStore, type Signed,
} from '@chronolog/peer-generation'
import { bytesToHex, hexToBytes, importEd25519PublicKey } from '@chronolog/protocol'
import type { ApplicationDevice } from './device.js'

export type ApplicationKeyRequest = Signed<{
  readonly applicationId: string
  readonly historyId: string
  readonly generation: string
  readonly controlDigest: string
  readonly recipient: string
  readonly receiverKey: string
  readonly nonce: string
  readonly epochs: readonly number[]
}>
export type ApplicationKeyShare = Signed<{
  readonly requestDigest: string
  readonly issuer: string
  readonly keys: readonly { readonly epoch: number; readonly encapsulatedKey: string; readonly ciphertext: string }[]
}>
const REQUEST_DOMAIN = 'chronolog/peer-generation/key-request/v1'
const SHARE_DOMAIN = 'chronolog/peer-generation/key-share/v1'
const MAX_BATCH = 16

/** Durable enrolled keys, with peer exchange independent of command retry and host storage. */
export class ApplicationKeyring {
  readonly #identity: PeerIdentity
  readonly #store: PeerStore
  readonly #key: string
  readonly #initial: AuthorityBundle
  readonly #keys = new Map<number, Uint8Array>()
  #replica: PeerReplica | undefined
  #closed = false
  #tail: Promise<unknown> = Promise.resolve()
  #pendingRequests = 0
  readonly #listeners = new Set<() => void>()
  readonly #sources = new Map<string, (request: ApplicationKeyRequest) => Promise<ApplicationKeyShare>>()
  #acquiring: Promise<unknown> = Promise.resolve()

  private constructor(device: ApplicationDevice, authority: AuthorityBundle) {
    this.#identity = device.identity; this.#store = device.store; this.#initial = authority
    this.#key = `peer-session/keys/${authority.descriptor.payload.applicationId}/${authority.descriptor.payload.historyId}`
  }
  static async open(options: { readonly device: ApplicationDevice; readonly authority: AuthorityBundle; readonly epochKeys?: ReadonlyMap<number, Uint8Array> }): Promise<ApplicationKeyring> {
    await verifyAuthorityBundle(options.authority)
    const ring = new ApplicationKeyring(options.device, options.authority)
    for (const [epoch, key] of await ring.#load()) ring.#keys.set(epoch, key)
    if (options.epochKeys !== undefined && options.epochKeys.size > 0) await ring.install(options.epochKeys)
    return ring
  }
  /** This live read-only port is shared by the replica and encrypted content owner. */
  get epochKeys(): ReadonlyMap<number, Uint8Array> { return this.#keys }
  bind(replica: PeerReplica): void {
    if (this.#replica !== undefined || replica.device.publicKey !== this.#identity.publicKey ||
        replica.descriptor.applicationId !== this.#initial.descriptor.payload.applicationId) throw new Error('APPLICATION_KEYRING_BINDING_INVALID')
    this.#replica = replica
  }
  missing(requiredEpochs?: readonly number[]): readonly number[] {
    this.#open()
    return [...new Set(requiredEpochs ?? this.#replica?.requiredEpochs ?? [...this.#commitments().keys()])].filter(epoch => !this.#keys.has(epoch)).sort((a, b) => a - b)
  }
  async validate(): Promise<void> {
    const commitments = this.#commitments()
    for (const [epoch, key] of this.#keys) if (commitments.get(epoch) !== await bytesDigest(key)) throw new Error('APPLICATION_EPOCH_KEY_MISMATCH')
  }
  subscribe(listener: () => void): () => void { this.#listeners.add(listener); return () => { this.#listeners.delete(listener) } }

  /** Maintained peer transports supply key sources; content can acquire older epochs lazily. */
  attachSource(peerId: string, offer: (request: ApplicationKeyRequest) => Promise<ApplicationKeyShare>): () => void {
    this.#open(); this.#reader(peerId)
    if (!this.#sources.has(peerId) && this.#sources.size >= 8) throw new Error('APPLICATION_KEY_SOURCE_LIMIT')
    this.#sources.set(peerId, offer)
    return () => { if (this.#sources.get(peerId) === offer) this.#sources.delete(peerId) }
  }
  ensure(requiredEpochs?: readonly number[]): Promise<void> {
    const requested = requiredEpochs === undefined ? undefined : [...requiredEpochs]
    const operation = this.#acquiring.then(async () => {
      for (let batch = 0; batch < 256; batch++) {
        this.#reader(this.#identity.publicKey)
        if (this.missing(requested).length === 0) return
        let obtained = false, failure: unknown = new Error('PEER_EPOCH_KEY_UNAVAILABLE')
        for (const offer of [...this.#sources.values()]) {
          const ticket = await this.request(requested)
          if (ticket === null) return
          try { await ticket.accept(await offer(ticket.request)); obtained = true; break }
          catch (error) { failure = error }
          finally { ticket.cancel() }
        }
        if (!obtained) throw failure
      }
      if (this.missing(requested).length > 0) throw new Error('APPLICATION_KEY_EXCHANGE_LIMIT')
    })
    this.#acquiring = operation.catch(() => undefined)
    return operation
  }

  /** Explicit bootstrap/rotation input must match already authenticated control commitments. */
  install(input: ReadonlyMap<number, Uint8Array>): Promise<void> {
    const keys = new Map([...input].map(([epoch, key]) => [epoch, key.slice()]))
    const operation = this.#tail.then(async () => {
      this.#open()
      const commitments = this.#commitments(), current = await this.#load()
      for (const [epoch, key] of keys) {
        if (!Number.isSafeInteger(epoch) || epoch < 0 || key.length !== 32 || commitments.get(epoch) !== await bytesDigest(key)) throw new Error('APPLICATION_EPOCH_KEY_MISMATCH')
        const existing = current.get(epoch)
        if (existing !== undefined && bytesToHex(existing) !== bytesToHex(key)) throw new Error('APPLICATION_EPOCH_KEY_CONFLICT')
        current.set(epoch, key)
      }
      this.#open()
      await this.#store.put(this.#key, encodePeerValue([...current].sort(([a], [b]) => a - b).map(([epoch, key]) => [epoch, bytesToHex(key)])))
      this.#open()
      for (const [epoch, key] of current) this.#keys.set(epoch, key)
      for (const listener of [...this.#listeners]) { try { listener() } catch { /* Observer failures cannot undo durable enrollment. */ } }
    })
    this.#tail = operation.catch(() => undefined)
    return operation
  }

  /** A fresh ephemeral HPKE receiver is bound to the actual device's signed request. */
  async request(requiredEpochs?: readonly number[]): Promise<{ readonly request: ApplicationKeyRequest; accept(share: ApplicationKeyShare): Promise<void>; cancel(): void } | null> {
    this.#reader(this.#identity.publicKey)
    const epochs = this.missing(requiredEpochs).slice(0, MAX_BATCH)
    if (epochs.length === 0) return null
    if (this.#pendingRequests >= 4) throw new Error('APPLICATION_KEY_REQUEST_LIMIT')
    this.#pendingRequests++
    let finished = false
    const cancel = (): void => { if (!finished) { finished = true; this.#pendingRequests-- } }
    try {
      const receiver = await generateX25519KeyPair(), authority = this.#authority(), generation = authority.generations.at(-1)!
      const controlDigest = await peerDigest(authority.controls[generation.payload.controlRevision]!)
      const request = await sign(REQUEST_DOMAIN, { applicationId: authority.descriptor.payload.applicationId,
        historyId: authority.descriptor.payload.historyId, generation: generation.id, controlDigest,
        recipient: this.#identity.publicKey, receiverKey: bytesToHex(receiver.publicKeyBytes), nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(16))), epochs }, this.#identity)
      await this.#scope(request)
      const requestDigest = await peerDigest(request)
      return { request, cancel, accept: async share => {
        if (finished) throw new Error('APPLICATION_KEY_REQUEST_CLOSED')
        try {
          await this.#scope(request)
          if (share.payload.requestDigest !== requestDigest || !Array.isArray(share.payload.keys) || share.payload.keys.length !== epochs.length) throw new Error('APPLICATION_KEY_SHARE_INVALID')
          this.#reader(share.payload.issuer)
          await verify(SHARE_DOMAIN, share, share.payload.issuer)
          const installed = new Map<number, Uint8Array>()
          for (const [index, item] of (share.payload.keys as ApplicationKeyShare['payload']['keys']).entries()) {
            if (item.epoch !== epochs[index] || !/^[0-9a-f]{64}$/u.test(item.encapsulatedKey) || !/^[0-9a-f]{96}$/u.test(item.ciphertext)) throw new Error('APPLICATION_KEY_SHARE_INVALID')
            const context = wrapContext(requestDigest, item.epoch)
            const key = await hpkeOpenBase(receiver.privateKey, receiver.publicKeyBytes, hexToBytes(item.encapsulatedKey), hexToBytes(item.ciphertext), context, context)
            installed.set(item.epoch, key)
          }
          await this.#scope(request); this.#reader(share.payload.issuer)
          await this.install(installed)
        } finally { cancel() }
      } }
    } catch (error) { cancel(); throw error }
  }

  /** Any current reader holding the committed key can enroll another granted reader. */
  async offer(request: ApplicationKeyRequest): Promise<ApplicationKeyShare> {
    await this.#scope(request); this.#reader(this.#identity.publicKey)
    const requestDigest = await peerDigest(request), keys: ApplicationKeyShare['payload']['keys'][number][] = []
    for (const epoch of request.payload.epochs) {
      const key = this.#keys.get(epoch)
      if (key === undefined) throw new Error('PEER_EPOCH_KEY_UNAVAILABLE')
      if (this.#commitments().get(epoch) !== await bytesDigest(key)) throw new Error('APPLICATION_EPOCH_KEY_MISMATCH')
      const context = wrapContext(requestDigest, epoch), wrapped = await hpkeSealBase(hexToBytes(request.payload.receiverKey), key, context, context)
      keys.push({ epoch, encapsulatedKey: bytesToHex(wrapped.encapsulatedKey), ciphertext: bytesToHex(wrapped.ciphertext) })
    }
    await this.#scope(request); this.#reader(this.#identity.publicKey)
    const share = await sign(SHARE_DOMAIN, { requestDigest, issuer: this.#identity.publicKey, keys }, this.#identity)
    await this.#scope(request)
    return share
  }

  close(): void { this.#closed = true; this.#listeners.clear(); this.#sources.clear(); for (const key of this.#keys.values()) key.fill(0); this.#keys.clear() }
  #open(): void { if (this.#closed) throw new Error('APPLICATION_KEYRING_CLOSED') }
  #authority(): AuthorityBundle { this.#open(); return this.#replica?.authority ?? this.#initial }
  #reader(peer: string): void {
    const authority = this.#authority(), generation = authority.generations.at(-1)
    if (generation === undefined || authority.controls[generation.payload.controlRevision]?.payload.grants.find(grant => grant.publicKey === peer)?.reader !== true) throw new Error('APPLICATION_KEY_ACCESS_DENIED')
  }
  #commitments(): Map<number, string> {
    const result = new Map<number, string>()
    for (const control of this.#authority().controls) {
      const previous = result.get(control.payload.epoch)
      if (previous !== undefined && previous !== control.payload.keyDigest) throw new Error('APPLICATION_EPOCH_KEY_CONFLICT')
      result.set(control.payload.epoch, control.payload.keyDigest)
    }
    return result
  }
  async #scope(request: ApplicationKeyRequest): Promise<void> {
    const value = request.payload, authority = this.#authority(), generation = authority.generations.at(-1)
    const epochs = value.epochs
    if (generation === undefined || value.applicationId !== authority.descriptor.payload.applicationId || value.historyId !== authority.descriptor.payload.historyId ||
        value.generation !== generation.id || value.controlDigest !== await peerDigest(authority.controls[generation.payload.controlRevision]!) ||
        !/^[0-9a-f]{64}$/u.test(value.receiverKey) || !/^[0-9a-f]{32}$/u.test(value.nonce) || !Array.isArray(value.epochs) ||
        epochs.length < 1 || epochs.length > MAX_BATCH || epochs.some((epoch, index) => !Number.isSafeInteger(epoch) || epoch < 0 ||
          index > 0 && epoch <= epochs[index - 1]! || !this.#commitments().has(epoch))) throw new Error('APPLICATION_KEY_REQUEST_INVALID')
    this.#reader(value.recipient)
    await verify(REQUEST_DOMAIN, request, value.recipient)
    this.#reader(value.recipient)
    if (this.#authority().generations.at(-1)?.id !== generation.id) throw new Error('APPLICATION_KEY_REQUEST_EXPIRED')
  }
  async #load(): Promise<Map<number, Uint8Array>> {
    const bytes = await this.#store.get(this.#key)
    if (bytes === null) return new Map()
    const value = decodePeerValue<readonly (readonly [number, string])[]>(bytes)
    if (!Array.isArray(value) || value.length > 4096) throw new Error('APPLICATION_KEY_STORE_INVALID')
    const result = new Map<number, Uint8Array>()
    for (const entry of value as readonly (readonly [number, string])[]) {
      if (!Array.isArray(entry) || entry.length !== 2 || !Number.isSafeInteger(entry[0]) || entry[0] < 0 || !/^[0-9a-f]{64}$/u.test(entry[1]) || result.has(entry[0])) throw new Error('APPLICATION_KEY_STORE_INVALID')
      result.set(entry[0], hexToBytes(entry[1]))
    }
    return result
  }
}

function wrapContext(requestDigest: string, epoch: number): Uint8Array { return encodePeerValue(['chronolog/peer-generation/key-wrap/v1', requestDigest, epoch]) }
async function sign<T>(domain: string, payload: T, identity: PeerIdentity): Promise<Signed<T>> {
  const signature = await crypto.subtle.sign('Ed25519', identity.privateKey, new Uint8Array(encodePeerValue([domain, payload])))
  return { payload, signature: bytesToHex(new Uint8Array(signature)) }
}
async function verify<T>(domain: string, value: Signed<T>, publicKey: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/u.test(publicKey) || !/^[0-9a-f]{128}$/u.test(value.signature) ||
      !await crypto.subtle.verify('Ed25519', await importEd25519PublicKey(hexToBytes(publicKey)), new Uint8Array(hexToBytes(value.signature)),
        new Uint8Array(encodePeerValue([domain, value.payload])))) throw new Error('APPLICATION_KEY_SIGNATURE_INVALID')
}
