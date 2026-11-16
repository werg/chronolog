import { utf8 } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { framePeerStream } from './framing.js'

function encoded(text: string): Uint8Array {
  const bytes = utf8(text), frame = new Uint8Array(bytes.length + 4)
  new DataView(frame.buffer).setUint32(0, bytes.length, false)
  frame.set(bytes, 4)
  return frame
}
function readable(chunks: readonly Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({ start(controller) { for (const chunk of chunks) controller.enqueue(chunk); controller.close() } })
}

describe('bounded peer byte framing', () => {
  it('handles fragmented headers/bodies and preserves exact frame bytes', async () => {
    const first = encoded('first'), second = encoded('second')
    const writes: Uint8Array[] = []
    const connection = framePeerStream({
      readable: readable([first.slice(0, 1), first.slice(1, 6), first.slice(6), second]),
      writable: new WritableStream({ write(bytes) { writes.push(bytes) } }),
    })
    await connection.send(utf8('outgoing'))
    const frames: Uint8Array[] = []
    for await (const frame of connection.frames()) frames.push(frame)
    expect(frames).toEqual([utf8('first'), utf8('second')])
    expect(writes).toEqual([encoded('outgoing')])
  })

  it('rejects excessive lengths before allocation and refuses truncated durable frames', async () => {
    const header = new Uint8Array(4)
    new DataView(header.buffer).setUint32(0, 100, false)
    const oversized = framePeerStream({ readable: readable([header]), writable: new WritableStream(), maxFrameBytes: 8 })
    await expect(oversized.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('PEER_FRAME_TOO_LARGE')
    const truncated = framePeerStream({ readable: readable([encoded('body').slice(0, -1)]), writable: new WritableStream() })
    await expect(truncated.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('PEER_FRAME_TRUNCATED')
  })

  it('refuses an unbounded send backlog while the underlying stream is slow', async () => {
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    const connection = framePeerStream({ readable: new ReadableStream(), writable: new WritableStream({ write: () => gate }), maxPendingSends: 1 })
    const first = connection.send(utf8('one'))
    await expect(connection.send(utf8('two'))).rejects.toThrow('PEER_FRAME_BACKPRESSURE')
    release(); await first
    await connection.close()
    await expect(connection.send(utf8('three'))).rejects.toThrow('PEER_CONNECTION_CLOSED')
  })
})
