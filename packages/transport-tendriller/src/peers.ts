import type { FramedPeerConnection } from '@chronolog/agent-service/framing'
import { assertCanonicalCbor } from '@chronolog/protocol'
import { PEER_LIMITS, type PeerConnection, type PeerDomain } from '@tendriller/core/peers'

// A bounded complete Chronolog range reply can exceed one host frame. Every
// record-domain frame carries this small contiguous-fragment envelope; no record
// is dropped, coalesced, or made effective before the verified message is whole.
const HEADER = 10
const MAX_MESSAGE = 1_048_576 + 65_536
function domain(bytes: Uint8Array, maximum: number): PeerDomain {
  const frame = assertCanonicalCbor(bytes, { maxBytes: maximum, maxByteStringBytes: maximum })
  if (!Array.isArray(frame) || frame[0] !== 1n) throw new Error('PEER_PROTOCOL_INVALID')
  if (frame[1] === 'chronolog/peer/v1') return 'records'
  if (frame[1] === 'chronolog/ephemeral/v1') return 'signals'
  throw new Error('PEER_PROTOCOL_DOMAIN_INVALID')
}

/**
 * Adapt only public connection/framing contracts. Tendriller transport domains
 * cannot turn a signal into a durable range message. Authentication and grants
 * are verified by openAuthenticatedPeerLink, not by a host channel or route.
 * At most one bounded record message is assembled; sender calls preserve order.
 */
export function frameTendrillerPeer(peer: PeerConnection, options: { readonly maxMessageBytes?: number } = {}): FramedPeerConnection & {
  readonly route: PeerConnection['route']
  readonly stats: PeerConnection['stats']
} {
  const maximum = options.maxMessageBytes ?? MAX_MESSAGE
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_MESSAGE) throw new Error('PEER_MESSAGE_BOUNDS_INVALID')
  let pending = 0, closed = false
  let tail: Promise<void> = Promise.resolve()
  const close = (): void => { closed = true; peer.close() }
  return {
    get route() { return peer.route },
    get stats() { return peer.stats },
    send(bytes) {
      if (closed) return Promise.reject(new Error('PEER_CONNECTION_CLOSED'))
      if (bytes.length > maximum || !bytes.length) return Promise.reject(new Error('PEER_MESSAGE_TOO_LARGE'))
      if (pending + bytes.length > PEER_LIMITS.queueBytes) return Promise.reject(new Error('PEER_MESSAGE_BACKPRESSURE'))
      const payload = bytes.slice(), selected = domain(payload, maximum)
      if (selected === 'signals' && payload.length > PEER_LIMITS.signalBytes) return Promise.reject(new Error('PEER_SIGNAL_TOO_LARGE'))
      pending += payload.length
      const sent = tail.then(async () => {
        await peer.ready
        if (closed) throw new Error('PEER_CONNECTION_CLOSED')
        if (selected === 'signals') { await peer.send({ domain: selected, payload }); return }
        for (let offset = 0; offset < payload.length; offset += PEER_LIMITS.frameBytes - HEADER) {
          const length = Math.min(PEER_LIMITS.frameBytes - HEADER, payload.length - offset)
          const part = new Uint8Array(HEADER + length), fields = new DataView(part.buffer)
          part.set([0x43, 1]); fields.setUint32(2, payload.length, false); fields.setUint32(6, offset, false)
          part.set(payload.subarray(offset, offset + length), HEADER)
          await peer.send({ domain: 'records', payload: part })
        }
      }).catch((error: unknown) => { close(); throw error }).finally(() => { pending -= payload.length })
      tail = sent.catch(() => undefined)
      return sent
    },
    async *frames(signal) {
      const cancelled = (): boolean => signal?.aborted === true
      if (cancelled()) { close(); return }
      const abort = (): void => close()
      signal?.addEventListener('abort', abort, { once: true })
      let assembling: Uint8Array | undefined, received = 0
      try {
        await peer.ready
        for await (const frame of peer.frames) {
          if (cancelled()) return
          if (frame.domain === 'signals') {
            if (domain(frame.payload, maximum) !== 'signals') throw new Error('PEER_PROTOCOL_DOMAIN_MISMATCH')
            yield frame.payload
            continue
          }
          if (frame.domain !== 'records' || frame.payload.length <= HEADER || frame.payload[0] !== 0x43 || frame.payload[1] !== 1)
            throw new Error('PEER_FRAGMENT_INVALID')
          const fields = new DataView(frame.payload.buffer, frame.payload.byteOffset, frame.payload.byteLength)
          const total = fields.getUint32(2, false), offset = fields.getUint32(6, false), length = frame.payload.length - HEADER
          if (total < 1 || total > maximum || offset !== received || length > total - offset ||
              assembling !== undefined && total !== assembling.length) throw new Error('PEER_FRAGMENT_INVALID')
          assembling ??= new Uint8Array(total)
          assembling.set(frame.payload.subarray(HEADER), offset); received += length
          if (received === total) {
            if (domain(assembling, maximum) !== 'records') throw new Error('PEER_PROTOCOL_DOMAIN_MISMATCH')
            const complete = assembling; assembling = undefined; received = 0
            yield complete
          }
        }
        if (assembling !== undefined) throw new Error('PEER_FRAGMENT_TRUNCATED')
      } finally { signal?.removeEventListener('abort', abort); close() }
    },
    async close() { close() },
  }
}
