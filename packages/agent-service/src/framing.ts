export interface FramedPeerConnection {
  send(frame: Uint8Array): Promise<void>
  frames(signal?: AbortSignal): AsyncIterable<Uint8Array>
  close(): Promise<void>
}

/**
 * Four-byte network-order length framing over a reliable browser/native byte
 * stream. It has no database identity or permission semantics: signed Chronolog
 * records, evidence and ephemeral domains remain independently authenticated.
 */
export function framePeerStream(options: {
  readonly readable: ReadableStream<Uint8Array>
  readonly writable: WritableStream<Uint8Array>
  readonly maxFrameBytes?: number
  readonly maxPendingSends?: number
}): FramedPeerConnection {
  const maximum = options.maxFrameBytes ?? 1_048_576 + 65_536
  const maxPending = options.maxPendingSends ?? 16
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 16 * 1024 * 1024 ||
      !Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 256) throw new Error('PEER_FRAME_BOUNDS_INVALID')
  const reader = options.readable.getReader(), writer = options.writable.getWriter()
  let pending = 0, reading = false, closed = false
  let tail: Promise<unknown> = Promise.resolve()
  const close = async (): Promise<void> => {
    if (closed) return
    closed = true
    await Promise.allSettled([reader.cancel(), writer.abort(new Error('PEER_CONNECTION_CLOSED'))])
  }
  return {
    send(input) {
      if (closed) return Promise.reject(new Error('PEER_CONNECTION_CLOSED'))
      if (!(input instanceof Uint8Array) || input.length < 1 || input.length > maximum) return Promise.reject(new Error('PEER_FRAME_TOO_LARGE'))
      if (pending >= maxPending) return Promise.reject(new Error('PEER_FRAME_BACKPRESSURE'))
      const frame = new Uint8Array(input.length + 4)
      new DataView(frame.buffer).setUint32(0, input.length, false)
      frame.set(input, 4)
      pending += 1
      const task = tail.then(async () => {
        if (closed) throw new Error('PEER_CONNECTION_CLOSED')
        await writer.ready
        await writer.write(frame)
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
      } finally {
        signal?.removeEventListener('abort', abort)
        await close()
      }
    },
    close,
  }
}
