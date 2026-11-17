import { bytesToHex, sha256 } from '@chronolog/canonical'
import { MAX_LEDGER_PAYLOAD_BYTES } from '@chronolog/node-core/ledger'
import {
  assertCanonicalCbor, encodeCanonicalCbor, equalBytes,
} from '@chronolog/protocol'
import type { CborValue, Ed25519KeyPair } from '@chronolog/protocol'
import { ChangeSignal } from '@chronolog/records'
import type { FeedLink } from '@chronolog/records'
import { MAX_SIGNAL_BYTES, SIGNAL_DOMAIN } from '@chronolog/signals'

import type { FramedPeerConnection } from './framing.js'

const PEER_DOMAIN = 'chronolog/peer/v1'
const MAX_RANGE = 64
const MAX_RANGE_BYTES = 64 * 1024 * 1024
const MAX_RECORD_FRAME = 1_048_576 + 65_536

export interface PeerAuthorization {
  readonly authorId: Uint8Array
  readonly grantId: Uint8Array
  readonly feedId: string
}

export interface AuthenticatedPeerLinkOptions {
  readonly connection: FramedPeerConnection
  readonly local: FeedLink
  readonly groupId: Uint8Array
  readonly identity: Ed25519KeyPair
  readonly grantId: Uint8Array
  /** Check an active read grant for this group, independently of host/relay login. */
  readonly authorizePeer: (peer: PeerAuthorization) => boolean | Promise<boolean>
  readonly receiveSignal?: (frame: Uint8Array) => void | Promise<void>
  /** Absolute identity-proof deadline, default 10 seconds. */
  readonly handshakeTimeoutMs?: number
  /** Time allowed to dispatch a request through local framing, default 30 seconds. */
  readonly sendTimeoutMs?: number
  /** Silence after dispatch or validated response progress, default 30 seconds. */
  readonly responseIdleTimeoutMs?: number
  /** Absolute request lifetime, including dispatch and progress, default 120 seconds. */
  readonly requestTimeoutMs?: number
}

interface RemoteHello extends PeerAuthorization { readonly nonce: Uint8Array; readonly encoded: Uint8Array }
interface PendingRequest {
  readonly limit: number
  readonly records: Uint8Array[]
  /** Non-null requests exactly one detached payload by content address. */
  readonly payloadHash: string | null
  bytes: number
  readonly resolve: (values: readonly Uint8Array[]) => void
  readonly reject: (error: unknown) => void
  responseStarted: boolean
  sendTimer: ReturnType<typeof setTimeout> | undefined
  idleTimer: ReturnType<typeof setTimeout> | undefined
  readonly lifetimeTimer: ReturnType<typeof setTimeout>
}

/**
 * Mutual nonce proofs bind a connection to a current Chronolog read grant.
 * Retained feed/evidence ranges then use the existing portable pull protocol.
 * A direct or relayed connection exchanges exactly the same signed bytes.
 */
export async function openAuthenticatedPeerLink(options: AuthenticatedPeerLinkOptions): Promise<{
  readonly link: FeedLink
  readonly peer: PeerAuthorization
  readonly completion: Promise<void>
  sendSignal(frame: Uint8Array, options?: { readonly signal?: AbortSignal }): Promise<void>
  close(): Promise<void>
}> {
  for (const bytes of [options.groupId, options.identity.publicKeyBytes, options.grantId]) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('PEER_IDENTITY_INVALID')
  }
  if (options.local.identity.length === 0 || options.local.identity.length > 256) throw new Error('PEER_FEED_ID_INVALID')
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? 10_000
  const sendTimeoutMs = options.sendTimeoutMs ?? 30_000
  const responseIdleTimeoutMs = options.responseIdleTimeoutMs ?? 30_000
  const requestTimeoutMs = options.requestTimeoutMs ?? 120_000
  if (!Number.isSafeInteger(handshakeTimeoutMs) || handshakeTimeoutMs < 1 || handshakeTimeoutMs > 60_000 ||
      ![sendTimeoutMs, responseIdleTimeoutMs, requestTimeoutMs].every(value => Number.isSafeInteger(value) && value >= 1 && value <= 120_000)) {
    throw new Error('PEER_TIMEOUT_INVALID')
  }
  const groupId = options.groupId.slice(), authorId = options.identity.publicKeyBytes.slice(), grantId = options.grantId.slice()
  const nonce = crypto.getRandomValues(new Uint8Array(32))
  const localHello = encodeCanonicalCbor([1n, PEER_DOMAIN, 'hello', groupId, options.local.identity, authorId, grantId, nonce])
  const controller = new AbortController(), changes = new ChangeSignal()
  const pending = new Map<number, PendingRequest>()
  let remote: RemoteHello | null = null, authenticated = false, nextRequest = 0, inbound = 0, signalsInFlight = 0
  let failure: Error | null = null
  let resolveReady!: () => void, rejectReady!: (error: unknown) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  let rejectOpening: ((error: Error) => void) | undefined
  const openingFailure = new Promise<never>((_resolve, reject) => { rejectOpening = reject })
  // The opening caller observes readiness errors; retain a handler while the
  // transport concurrently sends its first handshake frame.
  void ready.catch(() => undefined)
  void openingFailure.catch(() => undefined)

  const clearRequestTimers = (request: PendingRequest): void => {
    clearTimeout(request.sendTimer); clearTimeout(request.idleTimer); clearTimeout(request.lifetimeTimer)
    request.sendTimer = undefined; request.idleTimer = undefined
  }
  const fail = (error: unknown): void => {
    if (controller.signal.aborted) return
    failure = error instanceof Error ? error : new Error(String(error))
    clearTimeout(handshakeTimer)
    rejectReady(failure)
    rejectOpening?.(failure)
    for (const request of pending.values()) { clearRequestTimers(request); request.reject(failure) }
    pending.clear()
    controller.abort(failure); changes.close()
    void options.connection.close().catch(() => undefined)
  }
  const responseProgress = (request: PendingRequest): void => {
    // A response can arrive before the local send promise settles. From its
    // first validated record onward, only response progress owns the idle
    // deadline. Neither progress nor late send completion extends the lifetime.
    request.responseStarted = true
    clearTimeout(request.sendTimer); request.sendTimer = undefined
    clearTimeout(request.idleTimer)
    request.idleTimer = setTimeout(() => fail(new Error('PEER_RESPONSE_IDLE_TIMEOUT')), responseIdleTimeoutMs)
  }
  const send = (fields: readonly CborValue[]): Promise<void> => options.connection.send(encodeCanonicalCbor([1n, PEER_DOMAIN, ...fields]))
  const authorized = async (): Promise<boolean> => remote !== null &&
    await options.authorizePeer({ authorId: remote.authorId.slice(), grantId: remote.grantId.slice(), feedId: remote.feedId })
  const sendAuthorized = async (fields: readonly CborValue[]): Promise<void> => {
    // Storage reads, payload verification and prior duplex writes can suspend
    // while a grant is revoked. Authorize each release against current state.
    if (!await authorized()) throw new Error('PEER_READ_UNAUTHORIZED')
    await send(fields)
  }

  const serveRange = async (id: number, feed: string | null, after: bigint, limit: number): Promise<void> => {
    try {
      if (!await authorized()) throw new Error('PEER_READ_UNAUTHORIZED')
      const records = feed === null ? await options.local.readEvidence(after, limit) : await options.local.read(feed, after, limit)
      if (records.length > limit) throw new Error('PEER_RANGE_TOO_LARGE')
      let bytes = 0
      for (const record of records) {
        bytes += record.length
        if (record.length > MAX_RECORD_FRAME - 1024 || bytes > MAX_RANGE_BYTES) throw new Error('PEER_RANGE_TOO_LARGE')
        await sendAuthorized(['record', BigInt(id), record])
      }
      await sendAuthorized(['done', BigInt(id)])
    } catch (error) {
      if (!controller.signal.aborted) await send(['error', BigInt(id), error instanceof Error ? error.message.slice(0, 256) : 'PEER_RANGE_UNAVAILABLE'])
    } finally { inbound -= 1 }
  }

  const servePayload = async (id: number, hash: string): Promise<void> => {
    try {
      if (!await authorized()) throw new Error('PEER_READ_UNAUTHORIZED')
      const stored = await options.local.readPayload(hash)
      if (stored !== null && (!(stored instanceof Uint8Array) || stored.length < 1 || stored.length > MAX_LEDGER_PAYLOAD_BYTES)) {
        throw new Error('PEER_PAYLOAD_INVALID')
      }
      const payload = stored === null ? null : new Uint8Array(stored)
      if (payload !== null && bytesToHex(await sha256(payload)) !== hash) throw new Error('PEER_PAYLOAD_INVALID')
      if (payload !== null) await sendAuthorized(['record', BigInt(id), payload])
      await sendAuthorized(['done', BigInt(id)])
    } catch (error) {
      if (!controller.signal.aborted) await send(['error', BigInt(id), error instanceof Error ? error.message.slice(0, 256) : 'PEER_PAYLOAD_UNAVAILABLE'])
    } finally { inbound -= 1 }
  }

  const handle = async (bytes: Uint8Array): Promise<void> => {
    if (bytes.length > MAX_RECORD_FRAME) throw new Error('PEER_FRAME_TOO_LARGE')
    const frame = assertCanonicalCbor(bytes)
    if (!Array.isArray(frame) || frame[0] !== 1n) throw new Error('PEER_FRAME_INVALID')
    if (frame[1] !== PEER_DOMAIN || typeof frame[2] !== 'string') throw new Error('PEER_PROTOCOL_DOMAIN_INVALID')
    if (frame[2] === 'hello') {
      if (remote !== null || frame.length !== 8 || !(frame[3] instanceof Uint8Array) || !equalBytes(frame[3], groupId) ||
          typeof frame[4] !== 'string' || frame[4].length === 0 || frame[4].length > 256 ||
          !(frame[5] instanceof Uint8Array) || frame[5].length !== 32 ||
          !(frame[6] instanceof Uint8Array) || frame[6].length !== 32 ||
          !(frame[7] instanceof Uint8Array) || frame[7].length !== 32) throw new Error('PEER_HELLO_INVALID')
      remote = { feedId: frame[4], authorId: frame[5], grantId: frame[6], nonce: frame[7], encoded: bytes.slice() }
      const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', options.identity.privateKey,
        encodeCanonicalCbor(['chronolog/peer-proof/v1', localHello, remote.encoded]).slice().buffer))
      // Never await a duplex write from the read loop: both sides may be sending
      // proofs or range data while the underlying reliable stream backpressures.
      void send(['proof', signature]).catch(fail)
      return
    }
    if (frame[2] === 'proof') {
      if (remote === null || authenticated || frame.length !== 4 || !(frame[3] instanceof Uint8Array) || frame[3].length !== 64) {
        throw new Error('PEER_PROOF_INVALID')
      }
      const publicKey = await crypto.subtle.importKey('raw', remote.authorId.slice().buffer, 'Ed25519', false, ['verify'])
      if (!await crypto.subtle.verify('Ed25519', publicKey, frame[3].slice().buffer,
        encodeCanonicalCbor(['chronolog/peer-proof/v1', remote.encoded, localHello]).slice().buffer)) throw new Error('PEER_PROOF_INVALID')
      if (!await authorized()) throw new Error('PEER_READ_UNAUTHORIZED')
      authenticated = true
      resolveReady()
      return
    }
    if (!authenticated) throw new Error('PEER_REQUEST_BEFORE_AUTHENTICATION')
    if (frame[2] === 'changed') {
      if (frame.length !== 3) throw new Error('PEER_FRAME_INVALID')
      changes.notify(); return
    }
    if (frame[2] === 'range') {
      if (frame.length !== 7 || typeof frame[3] !== 'bigint' ||
          (frame[4] !== null && (typeof frame[4] !== 'string' || frame[4].length === 0 || frame[4].length > 256)) ||
          typeof frame[5] !== 'bigint' || typeof frame[6] !== 'bigint') throw new Error('PEER_RANGE_INVALID')
      const id = Number(frame[3]), limit = Number(frame[6])
      validateRange(frame[5], limit)
      if (!Number.isSafeInteger(id) || id < 1 || inbound >= 4) throw new Error('PEER_REQUEST_LIMIT_EXCEEDED')
      inbound += 1
      void serveRange(id, frame[4] as string | null, frame[5], limit).catch(fail)
      return
    }
    if (frame[2] === 'payload') {
      if (frame.length !== 5 || typeof frame[3] !== 'bigint' || !validPayloadHash(frame[4])) throw new Error('PEER_PAYLOAD_REQUEST_INVALID')
      const id = Number(frame[3])
      if (!Number.isSafeInteger(id) || id < 1 || inbound >= 4) throw new Error('PEER_REQUEST_LIMIT_EXCEEDED')
      inbound += 1
      void servePayload(id, frame[4]).catch(fail)
      return
    }
    if (typeof frame[3] !== 'bigint') throw new Error('PEER_RESPONSE_INVALID')
    const id = Number(frame[3]), request = pending.get(id)
    if (!Number.isSafeInteger(id) || request === undefined) throw new Error('PEER_RESPONSE_UNEXPECTED')
    if (frame[2] === 'record') {
      if (frame.length !== 5 || !(frame[4] instanceof Uint8Array) || request.records.length >= request.limit) throw new Error('PEER_RANGE_TOO_LARGE')
      if (request.payloadHash !== null && (frame[4].length < 1 || frame[4].length > MAX_LEDGER_PAYLOAD_BYTES ||
          bytesToHex(await sha256(frame[4])) !== request.payloadHash)) throw new Error('PEER_PAYLOAD_HASH_MISMATCH')
      request.bytes += frame[4].length
      if (request.bytes > MAX_RANGE_BYTES) throw new Error('PEER_RANGE_TOO_LARGE')
      // Payload verification may suspend beyond a timeout or explicit close.
      // Never resurrect timers for a request already disposed by that lifetime.
      if (pending.get(id) !== request) return
      request.records.push(frame[4].slice())
      responseProgress(request)
    } else if (frame[2] === 'done') {
      if (frame.length !== 4) throw new Error('PEER_RESPONSE_INVALID')
      clearRequestTimers(request); pending.delete(id); request.resolve(request.records)
    } else if (frame[2] === 'error') {
      if (frame.length !== 5 || typeof frame[4] !== 'string' || frame[4].length > 256) throw new Error('PEER_RESPONSE_INVALID')
      clearRequestTimers(request); pending.delete(id); request.reject(new Error(`PEER_REMOTE_ERROR: ${frame[4]}`))
    } else throw new Error('PEER_RESPONSE_INVALID')
  }

  const handshakeTimer = setTimeout(() => fail(new Error('PEER_HANDSHAKE_TIMEOUT')), handshakeTimeoutMs)
  const reading = (async () => {
    try {
      for await (const bytes of options.connection.frames(controller.signal)) {
        if (controller.signal.aborted) break
        await handle(bytes)
      }
      if (!controller.signal.aborted) fail(new Error('PEER_CONNECTION_ENDED'))
    } catch (error) { fail(error) }
  })()
  const liveReading = (async () => {
    if (options.connection.live === undefined) return
    try {
      await ready
      for await (const bytes of options.connection.live.frames(controller.signal)) {
        if (controller.signal.aborted) break
        if (bytes.length > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
        const frame = assertCanonicalCbor(bytes)
        if (!Array.isArray(frame) || frame[0] !== 1n || frame[1] !== SIGNAL_DOMAIN) throw new Error('SIGNAL_FRAME_INVALID')
        // Verification may suspend independently of the reliable history reader.
        // Once admitted here, failures and overload retire this owned lifetime.
        if (signalsInFlight >= 8) throw new Error('PEER_SIGNAL_BACKPRESSURE')
        const incoming = bytes.slice()
        signalsInFlight += 1
        void (async () => {
          if (!await authorized()) throw new Error('PEER_READ_UNAUTHORIZED')
          if (!controller.signal.aborted) await options.receiveSignal?.(incoming)
        })().catch(fail).finally(() => { signalsInFlight -= 1 })
      }
      if (!controller.signal.aborted) fail(new Error('PEER_LIVE_ENDED'))
    } catch (error) { fail(error) }
  })()
  const hints = (async () => {
    try {
      await ready
      for await (const _changed of options.local.watch(controller.signal)) {
        if (controller.signal.aborted) break
        if (await authorized()) await send(['changed'])
      }
    } catch (error) { fail(error) }
  })()
  const completion = Promise.all([reading, liveReading, hints]).then(() => { if (failure !== null) throw failure })
  void completion.catch(() => undefined)
  // Proof validation can finish before local HELLO dispatch settles. Its ready
  // promise then cannot reject, so opening failures need an independent gate.
  try {
    await Promise.race([Promise.all([options.connection.send(localHello), ready]), openingFailure])
    if (controller.signal.aborted) throw failure ?? new Error('PEER_CONNECTION_CLOSED')
  }
  catch (error) { fail(error); throw failure ?? error }
  finally { clearTimeout(handshakeTimer); rejectOpening = undefined }

  const request = (limit: number, payloadHash: string | null,
    fields: (id: number) => readonly CborValue[]): Promise<readonly Uint8Array[]> => {
    if (controller.signal.aborted) return Promise.reject(failure ?? new Error('PEER_CONNECTION_CLOSED'))
    if (pending.size >= 4 || nextRequest >= Number.MAX_SAFE_INTEGER) return Promise.reject(new Error('PEER_REQUEST_LIMIT_EXCEEDED'))
    const id = ++nextRequest
    return new Promise((resolve, reject) => {
      const state: PendingRequest = { limit, payloadHash, records: [], bytes: 0, resolve, reject, responseStarted: false,
        sendTimer: setTimeout(() => fail(new Error('PEER_REQUEST_SEND_TIMEOUT')), sendTimeoutMs), idleTimer: undefined,
        lifetimeTimer: setTimeout(() => fail(new Error('PEER_REQUEST_LIFETIME_TIMEOUT')), requestTimeoutMs) }
      pending.set(id, state)
      void Promise.resolve().then(() => send(fields(id))).then(() => {
        if (pending.get(id) !== state) return
        clearTimeout(state.sendTimer); state.sendTimer = undefined
        if (!state.responseStarted) responseProgress(state)
      }).catch(fail)
    })
  }
  const requestRange = (feed: string | null, after: bigint, limit: number): Promise<readonly Uint8Array[]> => {
    validateRange(after, limit)
    return request(limit, null, id => ['range', BigInt(id), feed, after, BigInt(limit)])
  }
  const requestPayload = async (hash: string): Promise<Uint8Array | null> => {
    if (!validPayloadHash(hash)) throw new Error('PEER_PAYLOAD_REQUEST_INVALID')
    const values = await request(1, hash, id => ['payload', BigInt(id), hash])
    return values[0] ?? null
  }
  const peer = remote as RemoteHello | null
  if (peer === null) throw new Error('PEER_HELLO_MISSING')
  return {
    peer: { authorId: peer.authorId.slice(), grantId: peer.grantId.slice(), feedId: peer.feedId },
    link: { identity: peer.feedId, read: (feed, after, limit) => requestRange(feed, after, limit),
      readEvidence: (after, limit) => requestRange(null, after, limit), readPayload: requestPayload,
      watch: (signal) => changes.watch(signal) },
    completion,
    async sendSignal(bytes, sendOptions = {}) {
      const live = options.connection.live
      if (live === undefined) throw new Error('PEER_LIVE_UNAVAILABLE')
      const signal = sendOptions.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, sendOptions.signal])
      signal.throwIfAborted()
      if (controller.signal.aborted) throw failure ?? new Error('PEER_CONNECTION_CLOSED')
      if (bytes.length > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
      const frame = assertCanonicalCbor(bytes)
      if (!Array.isArray(frame) || frame[0] !== 1n || frame[1] !== SIGNAL_DOMAIN) throw new Error('SIGNAL_FRAME_INVALID')
      // Signals contain application data too. A completed handshake is not a
      // permanent reader grant, and writer authorization at the signal layer
      // does not authorize this recipient after its read grant is revoked.
      const outgoing = bytes.slice()
      if (!await interruptible(authorized(), signal)) throw new Error('PEER_READ_UNAUTHORIZED')
      signal.throwIfAborted()
      if (controller.signal.aborted) throw failure ?? new Error('PEER_CONNECTION_CLOSED')
      // Live transports must honor cancellation before dispatch. Bound a stuck
      // implementation too; data already handed to the network is not recallable.
      const timer = setTimeout(() => fail(new Error('PEER_SIGNAL_SEND_TIMEOUT')), sendTimeoutMs)
      try { await interruptible(live.send(outgoing, { signal }), signal) }
      catch (error) { if (!signal.aborted) fail(error); throw error }
      finally { clearTimeout(timer) }
    },
    async close() {
      if (!controller.signal.aborted) {
        for (const request of pending.values()) { clearRequestTimers(request); request.reject(new Error('PEER_CONNECTION_CLOSED')) }
        pending.clear(); controller.abort(new Error('PEER_CONNECTION_CLOSED')); changes.close()
        await options.connection.close()
      }
      await completion.catch(() => undefined)
    },
  }
}

function validateRange(after: bigint, limit: number): void {
  if (after < 0n || after > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_RANGE) {
    throw new Error('PEER_RANGE_INVALID')
  }
}

function validPayloadHash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
}

function interruptible<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void operation.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void operation.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}
