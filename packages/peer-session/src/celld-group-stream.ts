import { bytesToHex, hexToBytes } from '@chronolog/protocol'
import type { CelldPeerStream } from './celld-peer.js'

const routeSize = 32
const maxChunkBytes = 64 * 1024
const credit = 0, data = 1, finish = 2

export interface CelldGroupSocket {
  binaryType: string
  send(message: ArrayBuffer): void
  close(): void
  addEventListener(type: string, handler: EventListener): void
  removeEventListener(type: string, handler: EventListener): void
}

/** The group address precedes the unchanged Chronolog session framing. */
export async function writeCelldGroupAddress(stream: CelldPeerStream, group: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/u.test(group)) throw new Error('CELLD_GROUP_ADDRESS_INVALID')
  const writer = stream.writable.getWriter()
  try { await writer.write(hexToBytes(group)) }
  finally { writer.releaseLock() }
}

/** Keep the bytes read beyond the short routing prelude on the same stream. */
export async function readCelldGroupAddress(stream: CelldPeerStream): Promise<{ group: string; stream: CelldPeerStream }> {
  const reader = stream.readable.getReader()
  try {
    const route = new Uint8Array(routeSize)
    let offset = 0, remainder: Uint8Array | undefined
    while (offset < route.length) {
      const part = await reader.read()
      if (part.done) throw new Error('CELLD_GROUP_ADDRESS_INCOMPLETE')
      const taken = Math.min(route.length - offset, part.value.byteLength)
      route.set(part.value.subarray(0, taken), offset)
      offset += taken
      if (taken < part.value.byteLength) remainder = part.value.subarray(taken)
    }
    let released = false
    const release = () => { if (!released) { released = true; reader.releaseLock() } }
    const cancel = async (reason?: unknown) => { if (!released) { try { await reader.cancel(reason) } finally { release() } } }
    const readable = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (remainder !== undefined) {
          const initial = remainder
          remainder = undefined
          controller.enqueue(initial)
          return
        }
        const item = await reader.read()
        if (item.done) { release(); controller.close() }
        else controller.enqueue(item.value)
      },
      cancel,
    }, { highWaterMark: 0 })
    return { group: bytesToHex(route), stream: { readable, writable: stream.writable, closed: stream.closed,
      remoteNodeId: stream.remoteNodeId, async close() {
        try { await stream.close() } finally { await cancel().catch(() => undefined) }
      } } }
  } catch (error) { reader.releaseLock(); throw error }
}

/** One reader credit bounds the internal WebSocket hop to one chunk in either direction. */
export function celldGroupSocketStream(socket: CelldGroupSocket, remoteNodeId: string): CelldPeerStream {
  let waitingRead = false, incomingEnded = false, sentEnd = false, availableCredit = false, retired = false
  let readController: ReadableStreamDefaultController<Uint8Array>, writeController: WritableStreamDefaultController
  let waitForCredit: { resolve(): void; reject(error: unknown): void } | undefined
  let resolveClosed!: () => void, rejectClosed!: (error: unknown) => void
  const closed = new Promise<void>((resolve, reject) => { resolveClosed = resolve; rejectClosed = reject })
  void closed.catch(() => undefined)

  const retire = (error?: unknown): void => {
    if (retired) return
    retired = true
    socket.removeEventListener('message', message)
    socket.removeEventListener('close', ended)
    socket.removeEventListener('error', failed)
    waitForCredit?.reject(error ?? new Error('CELLD_GROUP_STREAM_CLOSED'))
    waitForCredit = undefined
    if (!incomingEnded) readController.error(error ?? new Error('CELLD_GROUP_STREAM_CLOSED'))
    if (!sentEnd) writeController.error(error ?? new Error('CELLD_GROUP_STREAM_CLOSED'))
    try { socket.close() } catch { /* The forwarding owner has already ended. */ }
    if (error === undefined) resolveClosed()
    else rejectClosed(error)
  }
  const done = (): void => { if (incomingEnded && sentEnd) retire() }
  const ended = (): void => retire(incomingEnded && sentEnd ? undefined : new Error('CELLD_GROUP_STREAM_ENDED'))
  const failed = (): void => retire(new Error('CELLD_GROUP_STREAM_FAILED'))
  const send = (packet: Uint8Array<ArrayBuffer>): void => {
    try { socket.send(packet.buffer) }
    catch (error) { retire(error); throw error }
  }
  const message: EventListener = event => {
    const wire = (event as MessageEvent<unknown>).data
    if (!(wire instanceof ArrayBuffer)) { retire(new Error('CELLD_GROUP_STREAM_INVALID')); return }
    const bytes = new Uint8Array(wire), kind = bytes[0]
    if (kind === credit && bytes.byteLength === 1 && !availableCredit) {
      availableCredit = true
      waitForCredit?.resolve()
      waitForCredit = undefined
    } else if (kind === data && waitingRead && !incomingEnded && bytes.byteLength > 1 && bytes.byteLength <= maxChunkBytes + 1) {
      waitingRead = false
      readController.enqueue(bytes.subarray(1))
    } else if (kind === finish && bytes.byteLength === 1 && !incomingEnded) {
      incomingEnded = true
      readController.close()
      done()
    } else retire(new Error('CELLD_GROUP_STREAM_INVALID'))
  }

  const readable = new ReadableStream<Uint8Array>({
    start: controller => { readController = controller },
    pull() {
      if (waitingRead) return
      waitingRead = true
      send(new Uint8Array([credit]))
    },
    cancel() { incomingEnded = true; retire() },
  }, { highWaterMark: 0 })
  const writable = new WritableStream<Uint8Array>({
    start: controller => { writeController = controller },
    async write(value) {
      for (let offset = 0; offset < value.byteLength; offset += maxChunkBytes) {
        if (!availableCredit) await new Promise<void>((resolve, reject) => { waitForCredit = { resolve, reject } })
        if (retired) throw new Error('CELLD_GROUP_STREAM_CLOSED')
        availableCredit = false
        const chunk = value.subarray(offset, offset + maxChunkBytes), packet = new Uint8Array(chunk.byteLength + 1)
        packet[0] = data
        packet.set(chunk, 1)
        send(packet)
      }
    },
    close() { sentEnd = true; send(new Uint8Array([finish])); done() },
    abort(reason) { sentEnd = true; retire(reason) },
  })
  socket.binaryType = 'arraybuffer'
  socket.addEventListener('message', message)
  socket.addEventListener('close', ended)
  socket.addEventListener('error', failed)
  return { readable, writable, remoteNodeId, closed, async close() { retire() } }
}
