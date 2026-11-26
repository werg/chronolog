import { openWorkerWebRtcConnection, type ApplicationWorkerEndpoint, type WorkerWebRtcConnection } from '@chronolog/peer-session/webrtc'
import type { PeerSignalingMessage } from '@chronolog/transport-webrtc'

// This fixture owns all test frames and observations inside the Worker. The page
// supplies RTC and forwards bounded signaling; it never creates a session or reads keys.
function attach(endpoint: ApplicationWorkerEndpoint & { start?(): void }) {
  endpoint.start?.()
  let connection: WorkerWebRtcConnection | undefined, wake: (() => void) | undefined, closed = false
  const remoteQueue: PeerSignalingMessage[] = []
  let received = 0, liveReceived = 0, bytes = 0, error: string | undefined, changed = () => {}
  let broadcast: BroadcastChannel | undefined
  const signaling = {
    messages: {
      async *[Symbol.asyncIterator]() {
        while (true) {
          if (remoteQueue.length > 0) { yield remoteQueue.shift()!; continue }
          if (closed) return
          await new Promise<void>(resolve => { wake = resolve })
        }
      },
    },
    async send(description: PeerSignalingMessage) { endpoint.postMessage({ fixture: 'description', description }) },
    close() { closed = true; wake?.(); wake = undefined },
  }
  endpoint.addEventListener('message', event => {
    const value = event.data as { fixture?: string; id: number; action: string; role: 'offerer' | 'answerer'; description: PeerSignalingMessage;
      count: number; size: number; broadcast?: string; configuration?: RTCConfiguration; timeoutMs?: number; trickle?: boolean }
    if (value.fixture !== 'command') return
    if (value.action === 'remote') { remoteQueue.push(value.description); wake?.(); wake = undefined; return }
    const run = async () => {
      switch (value.action) {
        case 'open': {
          const transport = value.broadcast === undefined ? endpoint : (broadcast = new BroadcastChannel(value.broadcast))
          connection = await openWorkerWebRtcConnection(transport, {
            role: value.role, signaling,
            configuration: value.configuration ?? { iceServers: [{ urls: 'stun:stun.cloudflare.com:3478' }] },
            timeoutMs: value.timeoutMs ?? 15_000,
            ...(value.trickle === undefined ? {} : { trickle: value.trickle }),
          })
          const read = async (live: boolean) => {
            try {
              for await (const frame of (live ? connection!.live! : connection!).frames()) {
                const sequence = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0)
                if (!frame.every((byte, index) => index < 4 || byte === sequence % 251)) throw Error('FRAME_CONTENT_CHANGED')
                if (live) liveReceived++
                else { if (sequence !== received + 1) throw Error('FRAME_ORDER_CHANGED'); received++; bytes += frame.length }
                changed()
              }
            } catch (cause) { if (!connection!.signal.aborted) error = String(cause); changed() }
          }
          void read(false); void read(true)
          return { worker: typeof document === 'undefined', route: await connection.getRoute() }
        }
        case 'send':
          for (let sequence = 1; sequence <= value.count; sequence++) {
            const frame = new Uint8Array(value.size).fill(sequence % 251); new DataView(frame.buffer).setUint32(0, sequence)
            await connection!.send(frame)
          }
          return true
        case 'live': {
          const frame = new Uint8Array(1024).fill(1); new DataView(frame.buffer).setUint32(0, 1)
          return connection!.live!.trySend(frame)
        }
        case 'received':
          while (received < value.count || liveReceived < 1) {
            if (error !== undefined) throw Error(error)
            connection!.signal.throwIfAborted()
            await new Promise<void>(resolve => { changed = resolve })
          }
          if (error !== undefined) throw Error(error)
          return { received, liveReceived, bytes }
        case 'route': return connection!.getRoute()
        case 'state': if (error !== undefined) throw Error(error); return { received, liveReceived, bytes }
        case 'close': await connection?.close(); changed(); broadcast?.close(); return true
        default: throw Error('FIXTURE_COMMAND_INVALID')
      }
    }
    void run().then(result => endpoint.postMessage({ fixture: 'reply', id: value.id, result }),
      (cause: unknown) => endpoint.postMessage({ fixture: 'reply', id: value.id, error: String(cause) }))
  })
}
const scope = globalThis as unknown as ApplicationWorkerEndpoint & { onconnect?: (event: MessageEvent) => void }
if ('onconnect' in globalThis) scope.onconnect = event => { attach(event.ports[0]!) }
else attach(scope)
