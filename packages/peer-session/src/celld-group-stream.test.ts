import { expect, it } from 'vitest'
import { readCelldGroupAddress, celldGroupSocketStream, type CelldGroupSocket } from './celld-group-stream.js'

class TestSocket extends EventTarget implements CelldGroupSocket {
  binaryType = ''
  peer?: TestSocket
  #closed = false

  send(message: ArrayBuffer) {
    if (this.#closed) throw new Error('closed')
    queueMicrotask(() => this.peer?.dispatchEvent(new MessageEvent('message', { data: message })))
  }

  close() {
    if (this.#closed) return
    this.#closed = true
    queueMicrotask(() => {
      this.dispatchEvent(new Event('close'))
      this.peer?.close()
    })
  }
}

it('waits for read credit per bounded chunk and joins both internal forwarding directions', async () => {
  const left = new TestSocket(), right = new TestSocket()
  left.peer = right; right.peer = left
  const a = celldGroupSocketStream(left, 'aa'), b = celldGroupSocketStream(right, 'bb')
  const ar = a.readable.getReader(), aw = a.writable.getWriter(), br = b.readable.getReader(), bw = b.writable.getWriter()
  let completed = false
  const forward = aw.write(new Uint8Array(65_537).fill(3)).then(() => { completed = true })
  await expect(br.read()).resolves.toMatchObject({ done: false, value: new Uint8Array(65_536).fill(3) })
  expect(completed).toBe(false)
  const back = bw.write(Uint8Array.of(4))
  await expect(ar.read()).resolves.toMatchObject({ value: Uint8Array.of(4) })
  await back
  await expect(br.read()).resolves.toMatchObject({ value: Uint8Array.of(3) })
  await forward
  await aw.close()
  await expect(br.read()).resolves.toMatchObject({ done: true })
  await bw.close()
  await expect(ar.read()).resolves.toMatchObject({ done: true })
  await Promise.all([a.closed, b.closed])
})

it('keeps a frame that arrived in the final group-address chunk', async () => {
  const chunks = [new Uint8Array(18).fill(0xce), Uint8Array.from([...new Uint8Array(14).fill(0xce), 1, 2, 3])]
  const feed = new ReadableStream<Uint8Array>({ start(controller) { for (const chunk of chunks) controller.enqueue(chunk); controller.close() } })
  const { group, stream } = await readCelldGroupAddress({
    remoteNodeId: 'peer', readable: feed, writable: new WritableStream(), closed: Promise.resolve(), async close() {},
  })
  expect(group).toBe('ce'.repeat(32))
  const reader = stream.readable.getReader()
  await expect(reader.read()).resolves.toMatchObject({ value: Uint8Array.of(1, 2, 3) })
  await expect(reader.read()).resolves.toMatchObject({ done: true })
  expect(feed.locked).toBe(false)
})
