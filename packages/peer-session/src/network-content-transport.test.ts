import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import type { Socket } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import type { FramedPeerConnection } from '@chronolog/records'
import { openWebRtcConnection, type PeerDescription, type PeerSignaling } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import { openWebSocketConnection } from '@chronolog/transport-websocket'
import { CONTENT_CHUNK_BYTES } from './content.js'
import { deferred, payload } from './content-test-fixture.js'
import { sessionFixture } from './test-fixture.js'

const cleanup: Array<() => Promise<unknown>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
function signaling(): readonly [PeerSignaling, PeerSignaling] {
  const left = deferred<PeerDescription>(), right = deferred<PeerDescription>()
  return [
    { messages: { async *[Symbol.asyncIterator]() { yield await left.promise } }, send: async value => { right.resolve(structuredClone(value)) }, close() {} },
    { messages: { async *[Symbol.asyncIterator]() { yield await right.promise } }, send: async value => { left.resolve(structuredClone(value)) }, close() {} },
  ]
}
async function rtc(): Promise<readonly [FramedPeerConnection, FramedPeerConnection]> {
  const [a, b] = signaling()
  const factory = () => createNativePeerConnection({}, { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceAdditionalHostAddresses: ['127.0.0.1'], iceUseIpv6: false, iceUseTcp: false })
  const pair = await Promise.all([
    openWebRtcConnection({ role: 'offerer', signaling: a, createPeerConnection: factory, timeoutMs: 15_000 }),
    openWebRtcConnection({ role: 'answerer', signaling: b, createPeerConnection: factory, timeoutMs: 15_000 }),
  ])
  expect(await pair[0].session.getRoute()).toMatchObject({ route: 'direct' })
  return pair
}

/** Small test-only RFC6455 binary relay. Actual Node WebSocket clients carry the
 * existing two-lane adapter; this is not an in-memory source or transport mock. */
async function relay() {
  const sockets = new Set<Socket>(), lanes = new Map<string, { socket?: Socket; waiting: Buffer[] }>()
  let forwardedBytes = 0
  const frame = (bytes: Buffer, opcode = 2): Buffer => {
    const header = Buffer.alloc(bytes.length < 126 ? 2 : 4)
    header[0] = 0x80 | opcode
    if (bytes.length < 126) header[1] = bytes.length
    else { header[1] = 126; header.writeUInt16BE(bytes.length, 2) }
    return Buffer.concat([header, bytes])
  }
  const server = createServer((_request, response) => { response.writeHead(404); response.end() })
  server.on('upgrade', (request, stream) => {
    const socket = stream as Socket, key = request.headers['sec-websocket-key'], path = request.url ?? ''
    if (typeof key !== 'string' || !/^\/[0-9a-f-]{36}\/(?:reliable|live)\/[01]$/u.test(path)) { socket.destroy(); return }
    const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)
    sockets.add(socket)
    const other = `${path.slice(0, -1)}${path.endsWith('0') ? '1' : '0'}`
    const slot = lanes.get(path) ?? { waiting: [] }; slot.socket = socket; lanes.set(path, slot)
    for (const pending of slot.waiting) socket.write(frame(pending))
    slot.waiting.length = 0
    let buffered = Buffer.alloc(0)
    socket.on('error', () => socket.destroy())
    socket.on('close', () => { sockets.delete(socket); if (slot.socket === socket) delete slot.socket })
    socket.on('data', data => {
      if (buffered.length + data.length > 1024 * 1024) { socket.destroy(); return }
      buffered = Buffer.concat([buffered, data])
      while (buffered.length >= 2) {
        const opcode = buffered[0]! & 15, masked = (buffered[1]! & 0x80) !== 0
        let size = buffered[1]! & 127, offset = 2
        if ((buffered[0]! & 0x80) === 0 || !masked || size === 127) { socket.destroy(); return }
        if (size === 126) { if (buffered.length < 4) return; size = buffered.readUInt16BE(2); offset = 4 }
        if (buffered.length < offset + 4 + size) return
        const mask = buffered.subarray(offset, offset + 4), bytes = Buffer.from(buffered.subarray(offset + 4, offset + 4 + size))
        buffered = buffered.subarray(offset + 4 + size)
        for (let index = 0; index < bytes.length; index++) bytes[index] = bytes[index]! ^ mask[index % 4]!
        if (opcode === 8) { socket.end(frame(bytes, 8)); return }
        if (opcode === 9) { socket.write(frame(bytes, 10)); continue }
        if (opcode !== 2) { socket.destroy(); return }
        const target = lanes.get(other) ?? { waiting: [] }; lanes.set(other, target)
        if (target.socket !== undefined) target.socket.write(frame(bytes))
        else { if (target.waiting.length >= 64) { socket.destroy(); return }; target.waiting.push(bytes) }
        forwardedBytes += bytes.length
      }
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('RELAY_ADDRESS_INVALID')
  return {
    get bytes() { return forwardedBytes },
    async pair(): Promise<readonly [FramedPeerConnection, FramedPeerConnection]> {
      const id = crypto.randomUUID(), root = `ws://127.0.0.1:${address.port}/${id}`
      return Promise.all([
        openWebSocketConnection({ reliable: new WebSocket(`${root}/reliable/0`), live: new WebSocket(`${root}/live/0`) }),
        openWebSocketConnection({ reliable: new WebSocket(`${root}/reliable/1`), live: new WebSocket(`${root}/live/1`) }),
      ])
    },
    async close() { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())) },
  }
}

describe('actual encrypted content transport qualification', () => {
  for (const transport of ['rtc', 'websocket-relay'] as const) it(`${transport}: interrupts an in-flight chunk, reopens cached bytes, reconnects and resumes with authenticated retention`, async () => {
    const f = await sessionFixture(), a = await f.open(0)
    let b = await f.open(1)
    cleanup.push(async () => { await Promise.all([a.close(), b.close()]) })
    const ws = transport === 'websocket-relay' ? await relay() : undefined
    if (ws !== undefined) cleanup.push(() => ws.close())
    const connection = () => ws === undefined ? rtc() : ws.pair()
    const bytes = payload(CONTENT_CHUNK_BYTES * 3 + 37), reference = await a.content.putBytes(bytes), manifest = (await a.content.source().manifest(reference))!
    const hashes = manifest.chunks.map(chunk => chunk.hash), counts = new Map<string, number>(), store = f.stores[0]!, get = store.get.bind(store)
    const entered = deferred<void>(), gate = deferred<void>()
    let hold = true
    store.get = async key => {
      const hash = key.split('/').at(-1)!
      if (key.includes('/chunk/') && hashes.includes(hash)) {
        counts.set(hash, (counts.get(hash) ?? 0) + 1)
        if (hold && hash === hashes[1]) { entered.resolve(); await gate.promise }
      }
      return get(key)
    }
    const connect = async () => {
      const [left, right] = await connection()
      cleanup.push(async () => { await Promise.all([left.close(), right.close()]) })
      return Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    }
    await a.retryMaterialization(); const applicationRevision = a.revision.digest, physicalRevision = a.status.connectionRevision ?? 0
    expect(await a.diagnostics()).toEqual([])
    let links = await connect()
    const firstDiagnostics = await a.diagnostics()
    expect(firstDiagnostics).toHaveLength(1); expect(firstDiagnostics[0]).toMatchObject({ peerId: b.identity.publicKey, kind: 'unknown' })
    expect(firstDiagnostics[0]!.sentReliableBytes).toBeGreaterThan(0); expect(firstDiagnostics[0]!.receivedReliableBytes).toBeGreaterThan(0)
    expect('sentBytes' in firstDiagnostics[0]!).toBe(false); expect(a.status.connectionRevision).toBe(physicalRevision + 1)
    Reflect.set(firstDiagnostics[0]!, 'peerId', 'forged-copy'); expect((await a.diagnostics())[0]!.peerId).toBe(b.identity.publicKey)
    const liveStop = new AbortController(), liveReader = b.signals.subscribe({ topics: ['transport-live-probe'], signal: liveStop.signal })[Symbol.asyncIterator](), liveNext = liveReader.next()
    await a.signals.send('transport-live-probe', { transport, active: true }); expect((await liveNext).value?.payload).toEqual({ transport, active: true })
    liveStop.abort(); await liveReader.return?.()
    const sentLive = (await a.diagnostics())[0]!, receivedLive = (await b.diagnostics())[0]!
    expect(sentLive.sentLiveBytes).toBeGreaterThan(0); expect(receivedLive.receivedLiveBytes).toBeGreaterThan(0)
    expect(links[0].stats.sentLiveBytes).toBe(sentLive.sentLiveBytes); expect(links[1].stats.receivedLiveBytes).toBe(receivedLive.receivedLiveBytes)
    expect(receivedLive.signalRejections).toEqual({ total: 0, clockSkew: 0, expired: 0, unauthorized: 0, duplicate: 0, capacity: 0 })
    Reflect.set(receivedLive.signalRejections!, 'total', 999); expect((await b.diagnostics())[0]!.signalRejections!.total).toBe(0)
    const read = b.content.read(reference)[Symbol.asyncIterator]()
    expect((await read.next()).value).toEqual(bytes.subarray(0, CONTENT_CHUNK_BYTES))
    const interrupted = expect(read.next()).rejects.toThrow()
    await entered.promise
    await Promise.all(links.map(link => link.close()))
    await interrupted
    expect(await a.diagnostics()).toEqual([]); expect(a.status.connectionRevision).toBe(physicalRevision + 2)
    hold = false; gate.resolve()
    await b.close(); b = await f.open(1)
    expect((await b.content.source().manifest(reference))?.chunks).toHaveLength(4)
    expect(counts.get(hashes[0]!)).toBe(1)
    links = await connect()
    expect((await a.diagnostics())[0]!.connectionId).not.toBe(firstDiagnostics[0]!.connectionId)
    expect(await b.content.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
    expect(counts.get(hashes[0]!)).toBe(1)
    expect(counts.get(hashes[1]!)).toBe(2)
    const receipts = await a.content.retention(reference)
    expect(receipts).toHaveLength(1)
    expect(receipts[0]?.signer).toBe(f.identities[1]!.publicKey)
    expect(receipts[0]?.payload.storageId).toBe(b.device.storageId)
    expect(await a.content.retained(reference)).toEqual(receipts)
    expect(links.every(link => link.stats.sentBytes > 0 && link.stats.receivedBytes > 0)).toBe(true)
    await Promise.all(links.map(link => link.close()))
    expect(await b.content.readBytes(reference, { maxBytes: bytes.length })).toEqual(bytes)
    expect(await a.diagnostics()).toEqual([]); expect(a.status.connectionRevision).toBe(physicalRevision + 4); expect(a.revision.digest).toBe(applicationRevision)
    if (ws !== undefined) expect(ws.bytes).toBeGreaterThan(bytes.length)
  }, 90_000)
})
