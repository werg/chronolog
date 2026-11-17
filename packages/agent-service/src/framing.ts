/** A bounded connection-owned lane. Sending is local dispatch, not delivery. */
export interface PeerFrameLane {
  send(frame: Uint8Array, options?: { readonly signal?: AbortSignal }): Promise<void>
  frames(signal?: AbortSignal): AsyncIterable<Uint8Array>
  close(): Promise<void>
}

/** Independent disposable traffic with no queued retry on congestion. */
export interface PeerLiveLane {
  readonly signal: AbortSignal
  /** False means no bytes were queued or dispatched. Actual failures throw. */
  trySend(frame: Uint8Array, options?: { readonly signal?: AbortSignal }): Promise<boolean>
  frames(signal?: AbortSignal): AsyncIterable<Uint8Array>
  close(): Promise<void>
}

export interface FramedPeerConnection extends PeerFrameLane {
  /** Ends before frame readers finish; preserves the physical failure or close reason. */
  readonly signal: AbortSignal
  /** Never multiplex disposable traffic into reliable history. */
  readonly live?: PeerLiveLane
}

export interface PeerStreamOptions {
  readonly readable: ReadableStream<Uint8Array>
  readonly writable: WritableStream<Uint8Array>
  readonly maxFrameBytes?: number
  readonly maxPendingSends?: number
}

/** A dedicated live stream permits one write in flight and refuses further writes while busy. */
export function frameLivePeerStream(options: Omit<PeerStreamOptions, 'maxPendingSends'>): PeerLiveLane {
  const stream = framePeerStream({ ...options, maxPendingSends: 1 })
  let sending = false
  return {
    signal: stream.signal,
    async trySend(frame, sendOptions = {}) {
      sendOptions.signal?.throwIfAborted()
      stream.signal.throwIfAborted()
      if (sending) return false
      sending = true
      try { await stream.send(frame, sendOptions); return true }
      finally { sending = false }
    },
    frames: signal => stream.frames(signal),
    close: () => stream.close(),
  }
}

/**
 * Four-byte network-order length framing over a reliable browser/native byte
 * stream. It has no database identity or permission semantics: signed Chronolog
 * records, evidence and ephemeral domains remain independently authenticated.
 */
export function framePeerStream(options: PeerStreamOptions): FramedPeerConnection {
  const maximum = options.maxFrameBytes ?? 1_048_576 + 65_536
  const maxPending = options.maxPendingSends ?? 16
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 16 * 1024 * 1024 ||
      !Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 256) throw new Error('PEER_FRAME_BOUNDS_INVALID')
  const reader = options.readable.getReader(), writer = options.writable.getWriter()
  const lifetime = new AbortController()
  let pending = 0, reading = false, closed = false
  let tail: Promise<unknown> = Promise.resolve()
  const close = async (): Promise<void> => {
    if (closed) return
    closed = true
    lifetime.abort(new Error('PEER_CONNECTION_CLOSED'))
    await Promise.allSettled([reader.cancel(), writer.abort(new Error('PEER_CONNECTION_CLOSED'))])
  }
  return {
    signal: lifetime.signal,
    send(input, sendOptions = {}) {
      if (closed) return Promise.reject(new Error('PEER_CONNECTION_CLOSED'))
      if (!(input instanceof Uint8Array) || input.length < 1 || input.length > maximum) return Promise.reject(new Error('PEER_FRAME_TOO_LARGE'))
      if (pending >= maxPending) return Promise.reject(new Error('PEER_FRAME_BACKPRESSURE'))
      const frame = new Uint8Array(input.length + 4)
      new DataView(frame.buffer).setUint32(0, input.length, false)
      frame.set(input, 4)
      pending += 1
      const task = tail.then(async () => {
        let dispatched = false
        try {
          sendOptions.signal?.throwIfAborted()
          if (closed) throw lifetime.signal.reason
          await writer.ready
          sendOptions.signal?.throwIfAborted()
          dispatched = true
          await writer.write(frame)
        } catch (error) {
          if (dispatched || sendOptions.signal?.aborted !== true || error !== sendOptions.signal.reason) {
            lifetime.abort(error); void close()
          }
          throw error
        }
      }).finally(() => { pending -= 1 })
      tail = task.catch(() => undefined)
      return task
    },
    async *frames(signal) {
      if (reading) throw new Error('PEER_CONNECTION_READER_EXISTS')
      if (closed) return
      reading = true
      const abort = (): void => { void close() }
      signal?.addEventListener('abort', abort, { once: true })
      const header = new Uint8Array(4)
      let headerBytes = 0, body: Uint8Array | null = null, bodyBytes = 0
      try {
        while (!closed && signal?.aborted !== true) {
          const chunk = await reader.read()
          if (chunk.done) {
            if (headerBytes !== 0 || body !== null) throw new Error('PEER_FRAME_TRUNCATED')
            lifetime.abort(new Error('PEER_CONNECTION_ENDED'))
            return
          }
          if (!(chunk.value instanceof Uint8Array) || chunk.value.length > maximum + 4) throw new Error('PEER_CHUNK_TOO_LARGE')
          let offset = 0
          while (offset < chunk.value.length) {
            if (body === null) {
              const count = Math.min(4 - headerBytes, chunk.value.length - offset)
              header.set(chunk.value.subarray(offset, offset + count), headerBytes)
              offset += count; headerBytes += count
              if (headerBytes < 4) continue
              const length = new DataView(header.buffer).getUint32(0, false)
              if (length < 1 || length > maximum) throw new Error('PEER_FRAME_TOO_LARGE')
              body = new Uint8Array(length); bodyBytes = 0; headerBytes = 0
            }
            const count = Math.min(body.length - bodyBytes, chunk.value.length - offset)
            body.set(chunk.value.subarray(offset, offset + count), bodyBytes)
            offset += count; bodyBytes += count
            if (bodyBytes === body.length) { const complete = body; body = null; yield complete }
          }
        }
      } catch (error) {
        lifetime.abort(error)
        throw error
      } finally {
        signal?.removeEventListener('abort', abort)
        await close()
      }
    },
    close,
  }
}
