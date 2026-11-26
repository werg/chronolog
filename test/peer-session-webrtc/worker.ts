import { sha256 } from '@chronolog/canonical'
import { bytesToHex, hexToBytes } from '@chronolog/protocol'
import { createApplicationSession, openBrowserDevice } from '@chronolog/peer-session/worker'
import { openWorkerWebRtcConnection, type WorkerWebRtcConnection } from '@chronolog/peer-session/webrtc'
import { createHttpWebRtcSignaling } from '@chronolog/transport-webrtc'
import type { ApplicationDevice, ApplicationSession, ApplicationPeerLink, ContentReference } from '@chronolog/peer-session'
import type { EphemeralSignal } from '@chronolog/signals'
import { definition, type Bootstrap, type BrowserState } from './contract.js'

const endpoint = globalThis as unknown as {
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  postMessage(value: unknown, transfer?: Transferable[]): void
}
let device: ApplicationDevice | undefined, session: ApplicationSession<typeof definition> | undefined
let connection: WorkerWebRtcConnection | undefined, link: ApplicationPeerLink | undefined
const introductions: Array<ReturnType<typeof createHttpWebRtcSignaling>> = []
let name = '', bootstrap: Bootstrap | undefined, signalFailure: Error | undefined
const observed: EphemeralSignal[] = []

async function open(cached = false): Promise<void> {
  if (device === undefined || bootstrap === undefined) throw new Error('AUTHORED_RTC_BOOTSTRAP_REQUIRED')
  session = await createApplicationSession({
    device,
    definition,
    ...(cached
      ? { chainId: bootstrap.chainId }
      : { genesis: bootstrap.genesisBytes, casNodes: bootstrap.casNodes, epochKeys: new Map([[bootstrap.epoch, hexToBytes(bootstrap.epochKey)]]) }),
  })
  const owned = session
  void (async () => {
    try {
      for await (const value of owned.signals.subscribe({ signal: owned.signal })) {
        observed.push(value); if (observed.length > 16) observed.shift()
      }
    } catch (error) { if (!owned.signal.aborted) signalFailure = error instanceof Error ? error : new Error(String(error)) }
  })()
}
async function disconnect(): Promise<void> { await link?.close(); await connection?.close(); link = undefined; connection = undefined }
async function close(): Promise<void> { await disconnect(); await session?.close(); await device?.close() }
async function state(): Promise<BrowserState> {
  if (signalFailure !== undefined) throw signalFailure
  if (session === undefined || device === undefined) throw new Error('AUTHORED_RTC_SESSION_REQUIRED')
  const view = await session.readView()
  try { return { publicKey: session.identity.publicKey, storageId: device.storageId, workerOwnsSession: typeof document === 'undefined',
    revision: view.revision, events: view.readEvents().events, signals: structuredClone(observed), status: session.status } }
  finally { view.release() }
}

endpoint.addEventListener('message', event => {
  const input = event.data as { type?: string; id: number; method: string; name?: string; bootstrap?: Bootstrap;
    operationId?: string; text?: string; reference?: ContentReference; options?: { url: string; token: string; peerIdentity: string } }
  if (input.type !== 'authored-rtc-fixture') return
  const run = async (): Promise<unknown> => {
    switch (input.method) {
      case 'prepare':
        name = input.name!; device = await openBrowserDevice({ name, create: true })
        return { publicKey: device.identity.publicKey, storageId: device.storageId }
      case 'open': bootstrap = input.bootstrap!; await open(); return state()
      case 'connect': {
        const options = input.options!, owned = session!
        const signaling = createHttpWebRtcSignaling({ url: options.url, headers: { Authorization: `Bearer ${options.token}` } })
        introductions.push(signaling)
        connection = await openWorkerWebRtcConnection(endpoint, { role: 'offerer', signaling, signal: owned.signal,
          configuration: { iceServers: [] }, timeoutMs: 30_000 })
        try {
          link = await owned.connectPeer({ connection, peerIdentity: options.peerIdentity })
          await link.synchronize()
          return { peerIdentity: link.peerIdentity, route: await connection.getRoute(), stats: link.stats, signaling: signaling.stats, state: await state() }
        } catch (error) { await connection.close(); throw error }
      }
      case 'disconnect': await disconnect(); return null
      case 'transport':
        await link!.synchronize()
        return { stats: link!.stats, signaling: introductions.map(value => value.stats), route: await connection!.getRoute() }
      case 'save': {
        const operation = await session!.command('say', input.text!, { operationId: input.operationId! })
        const facts = await session!.exportFacts()
        const raw = facts.encryptedEnvelopes.at(-1)!
        return { state: operation.inspect(), intent: { proposalId: operation.id, bytesHex: bytesToHex(raw) } }
      }
      case 'publish': {
        const operation = await session!.command('say', input.text!, { operationId: input.operationId! })
        const materialized = await operation.materialized({ signal: AbortSignal.timeout(20_000) })
        await link?.synchronize()
        const facts = await session!.exportFacts()
        const raw = facts.encryptedEnvelopes.at(-1)!
        return { materialized, intent: { proposalId: operation.id, bytesHex: bytesToHex(raw) } }
      }
      case 'retained': { await link!.synchronize(); return session!.operations.get(input.operationId!)!.retained({ signal: AbortSignal.timeout(20_000) }) }
      case 'signal': return session!.signals.send('typing', { text: input.text! })
      case 'content': {
        const reference = input.reference!, bytes = new Uint8Array(reference.bytes)
        let offset = 0
        for await (const chunk of session!.content.read(reference, { signal: AbortSignal.timeout(30_000) })) {
          bytes.set(chunk, offset); offset += chunk.length
        }
        if (offset !== bytes.length) throw new Error('AUTHORED_RTC_CONTENT_LENGTH')
        const retained = await session!.content.retain(reference, { signal: AbortSignal.timeout(30_000) })
        return { bytes: offset, sha256: bytesToHex(await sha256(bytes)), retained }
      }
      case 'finalize': {
        const current = await state(), throughMs = current.events.reduce((time, event) => BigInt(event.authorTimestampMs) > time ? BigInt(event.authorTimestampMs) : time, 0n)
        const cp = await session!.finality.createCheckpoint({ throughMs }), final = await session!.readView({ view: 'final' })
        try { return { closedThroughMs: cp.checkpoint.payload.closedThroughMs.toString(), events: final.readEvents().events, revision: final.revision, signer: session!.identity.publicKey } } finally { final.release() }
      }
      case 'state': return state()
      case 'reopen':
        await close(); device = await openBrowserDevice({ name }); await open(true); return state()
      case 'close': await close(); return null
      default: throw new Error('AUTHORED_RTC_FIXTURE_COMMAND_INVALID')
    }
  }
  void run().then(value => endpoint.postMessage({ type: 'authored-rtc-fixture-reply', id: input.id, value }),
    (error: unknown) => endpoint.postMessage({ type: 'authored-rtc-fixture-reply', id: input.id, error: error instanceof Error ? error.stack : String(error) }))
})
