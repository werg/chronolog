import { framePeerStream, type FramedPeerConnection } from '@chronolog/records'
import type { ApplicationPeerHint, ApplicationTransportPort } from './participation-types.js'

export interface CelldPeerStream {
  readonly readable: ReadableStream<Uint8Array>
  readonly writable: WritableStream<Uint8Array>
  readonly remoteNodeId: string
  readonly closed: Promise<void>
  close(): Promise<void>
}

/** Carry a peer session on an object-owned celld stream. The session authenticates its application peer. */
export function frameCelldPeerStream(stream: CelldPeerStream): FramedPeerConnection {
  const framed = framePeerStream(stream)
  const transportLifetime = new AbortController()
  const signal = AbortSignal.any([transportLifetime.signal, framed.signal])
  let closing: Promise<void> | undefined
  const close = (): Promise<void> => closing ??= Promise.resolve().then(async () => {
    transportLifetime.abort(new Error('PEER_CONNECTION_CLOSED'))
    await Promise.allSettled([framed.close(), Promise.resolve().then(() => stream.close())])
  })
  void stream.closed.then(
    () => {
      transportLifetime.abort(new Error('PEER_CONNECTION_ENDED'))
      return close()
    },
    (reason: unknown) => {
      transportLifetime.abort(reason)
      return close()
    },
  )
  framed.signal.addEventListener('abort', () => { void close() }, { once: true })
  return { ...framed, signal, close }
}

export interface CelldPeerEndpoint {
  readonly nodeId: string
  readonly addrs?: readonly string[]
  readonly relay?: string
}

export interface CelldPeerBinding {
  connect(nodeId: string, options?: { addrs?: string[]; relay?: string }): Promise<CelldPeerStream>
}

/** Use the application's admitted endpoint directory for both outgoing and handed-off streams. */
export function createCelldPeerTransport(options: {
  readonly binding: CelldPeerBinding
  readonly resolveEndpoint: (peer: ApplicationPeerHint, signal: AbortSignal) => Promise<CelldPeerEndpoint>
  readonly takeInvitation: (peer: ApplicationPeerHint, invitation: unknown, signal: AbortSignal) => Promise<CelldPeerStream>
}): ApplicationTransportPort {
  const connect = options.binding.connect.bind(options.binding)
  const { resolveEndpoint, takeInvitation } = options
  return {
    async open({ peer, invitation }, { signal }) {
      signal.throwIfAborted()
      const endpoint = await resolveEndpoint(peer, signal)
      signal.throwIfAborted()
      const { nodeId, addrs, relay } = endpoint
      if (!/^[0-9a-f]{64}$/u.test(nodeId)) throw new Error('CELLD_PEER_ENDPOINT_INVALID')
      const stream = invitation === undefined
        ? await connect(nodeId, {
          ...(addrs === undefined ? {} : { addrs: [...addrs] }),
          ...(relay === undefined ? {} : { relay }),
        })
        : await takeInvitation(peer, invitation, signal)
      try {
        signal.throwIfAborted()
        if (stream.remoteNodeId !== nodeId) throw new Error('CELLD_PEER_ENDPOINT_MISMATCH')
        return frameCelldPeerStream(stream)
      } catch (error) {
        await Promise.allSettled([Promise.resolve().then(() => stream.close()), stream.closed])
        throw error
      }
    },
  }
}
