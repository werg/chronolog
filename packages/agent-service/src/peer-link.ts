import {
  assertCanonicalCbor, encodeCanonicalCbor, equalBytes,
} from '@chronolog/protocol'
import type { CborValue, Ed25519KeyPair } from '@chronolog/protocol'
import { ChangeSignal } from '@chronolog/records'
import type { FeedLink } from '@chronolog/records'

import type { FramedPeerConnection } from './framing.js'
import { MAX_SIGNAL_BYTES } from './signals.js'

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
  readonly timeoutMs?: number
}

interface RemoteHello extends PeerAuthorization { readonly nonce: Uint8Array; readonly encoded: Uint8Array }
interface PendingRange {
  readonly limit: number
  readonly records: Uint8Array[]
  bytes: number
  readonly resolve: (values: readonly Uint8Array[]) => void
  readonly reject: (error: unknown) => void
  readonly timer: ReturnType<typeof setTimeout>
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
  sendSignal(frame: Uint8Array): Promise<void>
  close(): Promise<void>
}> {
  for (const bytes of [options.groupId, options.identity.publicKeyBytes, options.grantId]) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('PEER_IDENTITY_INVALID')
  }
  if (options.local.identity.length === 0 || options.local.identity.length > 256) throw new Error('PEER_FEED_ID_INVALID')
  const timeoutMs = options.timeoutMs ?? 10_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new Error('PEER_TIMEOUT_INVALID')
  const groupId = options.groupId.slice(), authorId = options.identity.publicKeyBytes.slice(), grantId = options.grantId.slice()
  const nonce = crypto.getRandomValues(new Uint8Array(32))
  const localHello = encodeCanonicalCbor([1n, PEER_DOMAIN, 'hello', groupId, options.local.identity, authorId, grantId, nonce])
  const controller = new AbortController(), changes = new ChangeSignal()
  const pending = new Map<number, PendingRange>()
  let remote: RemoteHello | null = null, authenticated = false, nextRequest = 0, inbound = 0, signalsInFlight = 0
  let failure: Error | null = null
  let resolveReady!: () => void, rejectReady!: (error: unknown) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  // The opening caller observes readiness errors; retain a handler while the
  // transport concurrently sends its first handshake frame.
  void ready.catch(() => undefined)

  const fail = (error: unknown): void => {
    if (controller.signal.aborted) return
    failure = error instanceof Error ? error : new Error(String(error))
    rejectReady(failure)
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(failure) }
    pending.clear()
    controller.abort(); changes.close()
    void options.connection.close().catch(() => undefined)
  }
  const send = (fields: readonly CborValue[]): Promise<void> => options.connection.send(encodeCanonicalCbor([1n, PEER_DOMAIN, ...fields]))
  const authorized = async (): Promise<boolean> => remote !== null &&
    await options.authorizePeer({ authorId: remote.authorId.slice(), grantId: remote.grantId.slice(), feedId: remote.feedId })

  const serveRange = async (id: number, feed: string | null, after: bigint, limit: number): Promise<void> => {
    try {
      if (!await authorized()) throw new Error('PEER_READ_UNAUTHORIZED')
      const records = feed === null ? await options.local.readEvidence(after, limit) : await options.local.read(feed, after, limit)
      if (records.length > limit) throw new Error('PEER_RANGE_TOO_LARGE')
      let bytes = 0
      for (const record of records) {
        bytes += record.length
        if (record.length > MAX_RECORD_FRAME - 1024 || bytes > MAX_RANGE_BYTES) throw new Error('PEER_RANGE_TOO_LARGE')
        await send(['record', BigInt(id), record])
      }
      await send(['done', BigInt(id)])
    } catch (error) {
      if (!controller.signal.aborted) await send(['error', BigInt(id), error instanceof Error ? error.message.slice(0, 256) : 'PEER_RANGE_UNAVAILABLE'])
    } finally { inbound -= 1 }
  }

  const handle = async (bytes: Uint8Array): Promise<void> => {
    if (bytes.length > MAX_RECORD_FRAME) throw new Error('PEER_FRAME_TOO_LARGE')
    const frame = assertCanonicalCbor(bytes)
    if (!Array.isArray(frame) || frame[0] !== 1n) throw new Error('PEER_FRAME_INVALID')
    if (frame[1] === 'chronolog/ephemeral/v1') {
      if (!authenticated || bytes.length > MAX_SIGNAL_BYTES) throw new Error('PEER_SIGNAL_BEFORE_AUTHENTICATION')
      // Signals are replaceable and cannot block durable range processing.
      if (options.receiveSignal !== undefined && signalsInFlight < 8) {
        signalsInFlight += 1
        void Promise.resolve().then(() => options.receiveSignal!(bytes.slice())).catch(() => undefined)
          .finally(() => { signalsInFlight -= 1 })
      }
      return
    }
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
    if (typeof frame[3] !== 'bigint') throw new Error('PEER_RESPONSE_INVALID')
    const id = Number(frame[3]), request = pending.get(id)
    if (!Number.isSafeInteger(id) || request === undefined) throw new Error('PEER_RESPONSE_UNEXPECTED')
    if (frame[2] === 'record') {
      if (frame.length !== 5 || !(frame[4] instanceof Uint8Array) || request.records.length >= request.limit) throw new Error('PEER_RANGE_TOO_LARGE')
      request.bytes += frame[4].length
      if (request.bytes > MAX_RANGE_BYTES) throw new Error('PEER_RANGE_TOO_LARGE')
      request.records.push(frame[4].slice())
    } else if (frame[2] === 'done') {
      if (frame.length !== 4) throw new Error('PEER_RESPONSE_INVALID')
      clearTimeout(request.timer); pending.delete(id); request.resolve(request.records)
    } else if (frame[2] === 'error') {
      if (frame.length !== 5 || typeof frame[4] !== 'string' || frame[4].length > 256) throw new Error('PEER_RESPONSE_INVALID')
      clearTimeout(request.timer); pending.delete(id); request.reject(new Error(`PEER_REMOTE_ERROR: ${frame[4]}`))
    } else throw new Error('PEER_RESPONSE_INVALID')
  }

  const handshakeTimeout = setTimeout(() => fail(new Error('PEER_HANDSHAKE_TIMEOUT')), timeoutMs)
  const reading = (async () => {
    try {
      for await (const bytes of options.connection.frames(controller.signal)) {
        if (controller.signal.aborted) break
        await handle(bytes)
      }
      if (!controller.signal.aborted) fail(new Error('PEER_CONNECTION_ENDED'))
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
  const completion = Promise.all([reading, hints]).then(() => { if (failure !== null) throw failure })
  void completion.catch(() => undefined)
  try { await options.connection.send(localHello); await ready }
  catch (error) { fail(error); throw error }
  finally { clearTimeout(handshakeTimeout) }

  const requestRange = (feed: string | null, after: bigint, limit: number): Promise<readonly Uint8Array[]> => {
    validateRange(after, limit)
    if (controller.signal.aborted) return Promise.reject(failure ?? new Error('PEER_CONNECTION_CLOSED'))
    if (pending.size >= 4 || nextRequest >= Number.MAX_SAFE_INTEGER) return Promise.reject(new Error('PEER_REQUEST_LIMIT_EXCEEDED'))
    const id = ++nextRequest
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => fail(new Error('PEER_RANGE_TIMEOUT')), timeoutMs)
      pending.set(id, { limit, records: [], bytes: 0, resolve, reject, timer })
      void send(['range', BigInt(id), feed, after, BigInt(limit)]).catch(fail)
    })
  }
  const peer = remote as RemoteHello | null
  if (peer === null) throw new Error('PEER_HELLO_MISSING')
  return {
    peer: { authorId: peer.authorId.slice(), grantId: peer.grantId.slice(), feedId: peer.feedId },
    link: { identity: peer.feedId, read: (feed, after, limit) => requestRange(feed, after, limit),
      readEvidence: (after, limit) => requestRange(null, after, limit), watch: (signal) => changes.watch(signal) },
    completion,
    async sendSignal(bytes) {
      if (controller.signal.aborted) throw failure ?? new Error('PEER_CONNECTION_CLOSED')
      if (bytes.length > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
      const frame = assertCanonicalCbor(bytes)
      if (!Array.isArray(frame) || frame[0] !== 1n || frame[1] !== 'chronolog/ephemeral/v1') throw new Error('SIGNAL_FRAME_INVALID')
      await options.connection.send(bytes.slice())
    },
    async close() {
      if (!controller.signal.aborted) {
        for (const request of pending.values()) { clearTimeout(request.timer); request.reject(new Error('PEER_CONNECTION_CLOSED')) }
        pending.clear(); controller.abort(); changes.close()
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
