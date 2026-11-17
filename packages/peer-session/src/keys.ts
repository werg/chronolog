import type { BytesStore } from '@chronolog/records'
import { generateX25519KeyPair, hpkeOpenBase, hpkeSealBase } from '@chronolog/crypto'
import {
  bytesDigest, decodePeerValue, encodePeerValue, peerDigest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerIdentity, type PeerReplica, type Signed,
} from '@chronolog/peer-generation'
import { bytesToHex, hexToBytes, importEd25519PublicKey } from '@chronolog/protocol'
import type { ApplicationDevice } from './device.js'
import { awaitOwnedTask } from './lifetime.js'

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
interface KeySource { readonly offer: (request: ApplicationKeyRequest) => Promise<ApplicationKeyShare>; readonly lifetime: AbortController }

/** Durable enrolled keys, with peer exchange independent of command retry and host storage. */
export class ApplicationKeyring {
  readonly #identity: PeerIdentity
  readonly #store: BytesStore
  readonly #key: string
  readonly #initial: AuthorityBundle
  readonly #keys = new Map<number, Uint8Array>()
  #replica: PeerReplica | undefined
  readonly #lifetime = new AbortController()
  readonly #tickets = new Set<AbortController>()
  #closeTask: Promise<void> | undefined
  #tail: Promise<unknown> = Promise.resolve()
  #pendingRequests = 0
  readonly #listeners = new Set<() => void>()
  readonly #sources = new Map<string, KeySource>()
  #sourceRequests = 0
  #acquiring: Promise<unknown> = Promise.resolve()

  private constructor(device: ApplicationDevice, authority: AuthorityBundle) {
    this.#identity = device.identity; this.#store = device.store; this.#initial = structuredClone(authority)
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
        bytesToHex(encodePeerValue(replica.authority.descriptor)) !== bytesToHex(encodePeerValue(this.#initial.descriptor))) throw new Error('APPLICATION_KEYRING_BINDING_INVALID')
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
    this.#sources.get(peerId)?.lifetime.abort(new Error('APPLICATION_KEY_SOURCE_DETACHED'))
    const source = { offer, lifetime: new AbortController() }
    this.#sources.set(peerId, source)
    return () => {
      if (this.#sources.get(peerId) !== source) return
      this.#sources.delete(peerId); source.lifetime.abort(new Error('APPLICATION_KEY_SOURCE_DETACHED'))
    }
  }
  ensure(requiredEpochs?: readonly number[]): Promise<void> {
    const requested = requiredEpochs === undefined ? undefined : [...requiredEpochs]
    const operation = this.#acquiring.then(async () => {
      for (let batch = 0; batch < 256; batch++) {
        this.#reader(this.#identity.publicKey)
        if (this.missing(requested).length === 0) return
        let obtained = false, failure: unknown = new Error('PEER_EPOCH_KEY_UNAVAILABLE')
        for (const [peer, source] of [...this.#sources]) {
          const ticket = await this.request(requested)
          if (ticket === null) return
          const detached = (): void => { ticket.cancel() }
          source.lifetime.signal.addEventListener('abort', detached, { once: true })
          if (source.lifetime.signal.aborted) detached()
          try {
            const share = await this.#offer(peer, source, ticket.request)
            await ticket.accept(share); obtained = true; break
          }
          catch (error) { this.#open(); failure = error }
          finally { source.lifetime.signal.removeEventListener('abort', detached); ticket.cancel() }
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
    return this.#install(input, () => this.#open())
  }
  #install(input: ReadonlyMap<number, Uint8Array>, current: () => void): Promise<void> {
    const keys = new Map([...input].map(([epoch, key]) => [epoch, key.slice()]))
    const operation = this.#tail.then(async () => {
      this.#open(); current()
      const commitments = this.#commitments(), stored = await this.#load()
      for (const [epoch, key] of keys) {
        if (!Number.isSafeInteger(epoch) || epoch < 0 || key.length !== 32 || commitments.get(epoch) !== await bytesDigest(key)) throw new Error('APPLICATION_EPOCH_KEY_MISMATCH')
        const existing = stored.get(epoch)
        if (existing !== undefined && bytesToHex(existing) !== bytesToHex(key)) throw new Error('APPLICATION_EPOCH_KEY_CONFLICT')
        stored.set(epoch, key)
      }
      this.#open(); current()
      await this.#store.put(this.#key, encodePeerValue([...stored].sort(([a], [b]) => a - b).map(([epoch, key]) => [epoch, bytesToHex(key)])))
      this.#open(); current()
      for (const [epoch, key] of stored) this.#keys.set(epoch, key)
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
    const lifetime = new AbortController(), signal = AbortSignal.any([this.#lifetime.signal, lifetime.signal])
    this.#tickets.add(lifetime)
    let finished = false, accepting = false, released = false
    const release = (): void => {
      if (released) return
      released = true; this.#pendingRequests--; this.#tickets.delete(lifetime)
    }
    const cancel = (): void => {
      finished = true; lifetime.abort(new Error('APPLICATION_KEY_REQUEST_CLOSED'))
      if (!accepting) release()
    }
    try {
      const receiver = await generateX25519KeyPair(), authority = this.#authority(), generation = authority.generations.at(-1)!
      signal.throwIfAborted()
      const controlDigest = await peerDigest(authority.controls[generation.payload.controlRevision]!)
      const request = await sign(REQUEST_DOMAIN, { applicationId: authority.descriptor.payload.applicationId,
        historyId: authority.descriptor.payload.historyId, generation: generation.id, controlDigest,
        recipient: this.#identity.publicKey, receiverKey: bytesToHex(receiver.publicKeyBytes), nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(16))), epochs }, this.#identity)
      await this.#scope(request); signal.throwIfAborted()
      const requestDigest = await peerDigest(request)
      signal.throwIfAborted()
      return { request, cancel, accept: async share => {
        if (finished || accepting) throw new Error('APPLICATION_KEY_REQUEST_CLOSED')
        accepting = true
        const current = (): void => {
          signal.throwIfAborted()
          if (this.#authority().generations.at(-1)?.id !== request.payload.generation) throw new Error('APPLICATION_KEY_REQUEST_EXPIRED')
          this.#reader(request.payload.recipient); this.#reader(share.payload.issuer)
        }
        const work = (async () => {
          signal.throwIfAborted(); await this.#scope(request); signal.throwIfAborted()
          if (share.payload.requestDigest !== requestDigest || !Array.isArray(share.payload.keys) || share.payload.keys.length !== epochs.length) throw new Error('APPLICATION_KEY_SHARE_INVALID')
          this.#reader(share.payload.issuer)
          await verify(SHARE_DOMAIN, share, share.payload.issuer); current()
          const installed = new Map<number, Uint8Array>()
          for (const [index, item] of (share.payload.keys as ApplicationKeyShare['payload']['keys']).entries()) {
            if (item.epoch !== epochs[index] || !/^[0-9a-f]{64}$/u.test(item.encapsulatedKey) || !/^[0-9a-f]{96}$/u.test(item.ciphertext)) throw new Error('APPLICATION_KEY_SHARE_INVALID')
            const context = wrapContext(requestDigest, item.epoch)
            const key = await hpkeOpenBase(receiver.privateKey, receiver.publicKeyBytes, hexToBytes(item.encapsulatedKey), hexToBytes(item.ciphertext), context, context)
            current(); installed.set(item.epoch, key)
          }
          await this.#scope(request); current()
          await this.#install(installed, current)
        })()
        const complete = (): void => { accepting = false; finished = true; release() }
        void work.then(complete, complete)
        return awaitOwnedTask(signal, () => work)
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

  close(): Promise<void> {
    if (this.#closeTask !== undefined) return this.#closeTask
    this.#lifetime.abort(new Error('APPLICATION_KEYRING_CLOSED'))
    for (const ticket of this.#tickets) ticket.abort(this.#lifetime.signal.reason)
    this.#tickets.clear()
    for (const source of this.#sources.values()) source.lifetime.abort(this.#lifetime.signal.reason)
    this.#listeners.clear(); this.#sources.clear()
    for (const key of this.#keys.values()) key.fill(0)
    this.#keys.clear()
    this.#closeTask = Promise.allSettled([this.#tail, this.#acquiring]).then(() => undefined)
    return this.#closeTask
  }
  #open(): void { this.#lifetime.signal.throwIfAborted() }
  async #offer(peer: string, source: KeySource, request: ApplicationKeyRequest): Promise<ApplicationKeyShare> {
    const signal = AbortSignal.any([this.#lifetime.signal, source.lifetime.signal])
    const current = (): void => {
      signal.throwIfAborted(); this.#reader(peer)
      if (this.#sources.get(peer) !== source) throw new Error('APPLICATION_KEY_SOURCE_DETACHED')
    }
    current()
    const share = await awaitOwnedTask(signal, () => {
      if (this.#sourceRequests >= 8) throw new Error('APPLICATION_KEY_SOURCE_BUSY')
      this.#sourceRequests++
      let pending: Promise<ApplicationKeyShare>
      try { pending = Promise.resolve(source.offer(request)) }
      catch (error) { this.#sourceRequests--; throw error }
      // Ending the wait does not cancel physical provider work or free its slot.
      void pending.then(() => { this.#sourceRequests-- }, () => { this.#sourceRequests-- })
      return pending
    })
    current()
    if (share.payload.issuer !== peer) throw new Error('APPLICATION_KEY_SHARE_INVALID')
    return share
  }
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
