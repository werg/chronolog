import { framePeerStream, type FramedPeerConnection } from '@chronolog/records'

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
