import { serveWorkerWebRtcConnections, type ApplicationWorkerEndpoint } from '@chronolog/peer-session/webrtc'

export async function qualify(mode: 'shared' | 'dedicated' | 'broadcast') {
  const endpoints: ApplicationWorkerEndpoint[] = [], stop: Array<() => void | Promise<void>> = []
  const pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
  let next = 0, wire = 0
  const command = (index: number, action: string, fields: Record<string, unknown> = {}) => new Promise<unknown>((resolve, reject) => {
    const id = ++next; pending.set(id, { resolve, reject }); endpoints[index]!.postMessage({ fixture: 'command', id, action, ...fields })
  })
  for (let i = 0; i < 2; i++) {
    const workerUrl = new URL('./worker.js', location.href)
    let endpoint: ApplicationWorkerEndpoint
    if (mode === 'shared') {
      const worker = new SharedWorker(workerUrl, { type: 'module', name: crypto.randomUUID() })
      worker.port.start(); endpoint = worker.port; stop.push(() => worker.port.close())
    } else {
      const worker = new Worker(workerUrl, { type: 'module' }); endpoint = worker; stop.push(() => worker.terminate())
    }
    endpoints.push(endpoint)
    const broadcast = mode === 'broadcast' ? new BroadcastChannel(`rtc-fixture-${crypto.randomUUID()}`) : undefined
    const rtcEndpoint = broadcast ?? endpoint
    if (broadcast !== undefined) stop.push(() => broadcast.close())
    rtcEndpoint.addEventListener('message', event => { if ((event.data as { type?: string }).type === 'chronolog/peer-session/rtc-endpoint/v1') wire++ })
    const server = serveWorkerWebRtcConnections(rtcEndpoint); stop.push(() => server.close())
    endpoint.addEventListener('message', event => {
      const value = event.data as { fixture?: string; id: number; description?: unknown; result?: unknown; error?: string }
      if (value.fixture === 'description') endpoints[1 - i]!.postMessage({ fixture: 'command', action: 'remote', description: value.description })
      if (value.fixture === 'reply') {
        const held = pending.get(value.id); if (held === undefined) return
        pending.delete(value.id); if (value.error === undefined) held.resolve(value.result); else held.reject(Error(value.error))
      }
    })
    Object.assign(endpoint, { fixtureBroadcast: broadcast?.name })
  }
  try {
    const ready = await Promise.all(endpoints.map((endpoint, index) => command(index, 'open', { role: index === 0 ? 'offerer' : 'answerer',
      broadcast: (endpoint as ApplicationWorkerEndpoint & { fixtureBroadcast?: string }).fixtureBroadcast })))
    await Promise.all([command(0, 'send', { count: 24, size: 65_536 }), command(1, 'send', { count: 24, size: 65_536 })])
    const live = await Promise.all([command(0, 'live'), command(1, 'live')])
    // send() establishes local dispatch only. Wait for the exact independently
    // received reliable/live frames, rather than using the faster lane as a fence.
    const state = await Promise.all([command(0, 'received', { count: 24 }), command(1, 'received', { count: 24 })])
    // Route requests share the ordered bridge with frame ACKs, so their replies
    // drain both directions before the quiet-idle boundary, including BroadcastChannel.
    await Promise.all([command(0, 'route'), command(1, 'route')])
    const before = wire; await new Promise(resolve => setTimeout(resolve, 300))
    return { mode, ready, live, state, idleMessages: wire - before }
  } finally {
    await Promise.allSettled(endpoints.map((_, index) => command(index, 'close')))
    for (const close of stop.reverse()) await close()
  }
}
Object.assign(globalThis, { qualifyWorkerRtc: qualify })
