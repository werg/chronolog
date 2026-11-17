import { decodeSignedGenesis } from '@chronolog/capabilities'
import { base64UrlToBytes, bytesToBase64Url, decodeExecutionManifest } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { prepareBrowserIdentity, openBrowserPeer, serveBrowserPeer, type BrowserPeer, type WorkerEndpoint } from '@chronolog/runtime-browser'
import { frameRtcPeerChannels, type PeerDataChannelConnection, type WebRtcChannels } from '@chronolog/transport-webrtc'

import type { BrowserEventIdentity } from '../browser/event-contract.js'
import type { PilotPeerBootstrap, PilotProgress, PilotRouteStats } from './contract.js'
import { routeState } from './route-state.js'

const endpoint = globalThis as unknown as WorkerEndpoint
let peer: BrowserPeer | undefined
let connection: { close(): Promise<void>; stats(): PilotRouteStats } | undefined
let opening: PeerDataChannelConnection | undefined, connectionGeneration = 0
let bootstrap: PilotPeerBootstrap | undefined
const connectionHistory: PilotRouteStats[] = []

/** The Window transfers an untouched channel; keys and application frames stay here. */
async function connect(channels: WebRtcChannels, connectionId: number): Promise<void> {
  if (peer === undefined || bootstrap === undefined) throw new Error('PILOT_NOT_OPEN')
  await disconnect()
  const generation = ++connectionGeneration
  const framed = frameRtcPeerChannels(channels)
  opening = framed
  try {
    const started = performance.now()
    await framed.ready
    const authenticated = await peer.connectPeer({ connection: framed, peerIdentity: base64UrlToBytes(bootstrap.nativeIdentity) })
    const authenticatedMs = performance.now() - started
    if (generation !== connectionGeneration) { await authenticated.close(); throw new Error('PILOT_CONNECTION_SUPERSEDED') }
    let closed = false
    const current = { stats: (): PilotRouteStats => { const stats = framed.stats; return { route: 'webrtc', authenticatedMs,
        sentBytes: stats.sentBytes, receivedBytes: stats.receivedBytes, queuedBytes: stats.queuedSendBytes + stats.queuedReceiveBytes } },
      async close() { if (closed) return; closed = true; await authenticated.close() } }
    connection = current
    const ended = () => {
      if (!closed && connection === current) endpoint.postMessage({ pilot: 'connection-error', connectionId, error: 'Authenticated peer session ended' })
    }
    authenticated.signal.addEventListener('abort', ended, { once: true })
    if (authenticated.signal.aborted) ended()
    void authenticated.completion.catch(() => undefined).finally(() => {
      authenticated.signal.removeEventListener('abort', ended)
      if (connection === current) { connection = undefined; connectionHistory.push(current.stats()) }
    })
  } catch (error) { await framed.close(); throw error }
  finally { if (opening === framed) opening = undefined }
}
async function disconnect(): Promise<void> {
  connectionGeneration++
  const pending = opening
  opening = undefined
  const previous = connection
  connection = undefined
  await Promise.all([pending?.close(), previous?.close()])
  if (previous !== undefined) connectionHistory.push(previous.stats())
}

endpoint.addEventListener('message', (event) => {
  const request = event.data as { pilot?: string; id?: number; name?: string; bootstrap?: PilotPeerBootstrap;
    createIdentity?: boolean;
    channels?: WebRtcChannels; connectionId?: number }
  if (request.pilot === undefined) return
  const run = async (): Promise<unknown> => {
    switch (request.pilot) {
      case 'prepare': {
        const prepared = await prepareBrowserIdentity(request.name!, request.createIdentity === true ? true : undefined)
        return { identity: bytesToBase64Url(prepared.signing.publicKeyBytes), readerKey: bytesToBase64Url(prepared.reader.publicKeyBytes),
          transportAuthor: feedIdFromPublicKey(prepared.signing.publicKeyBytes) } satisfies BrowserEventIdentity
      }
      case 'open': {
        bootstrap = request.bootstrap!
        const genesis = decodeSignedGenesis(base64UrlToBytes(bootstrap.genesis))
        peer = await openBrowserPeer({ name: request.name!, engineUrl: new URL('./engine/', globalThis.location.href), configure() {
          return { materializer: { executionManifest: decodeExecutionManifest(base64UrlToBytes(bootstrap!.executionManifest)), rootAdministrator: genesis.manifest.schemaAdminPublicKey },
            governed: { genesis, groupRoute: base64UrlToBytes(bootstrap!.groupRoute), initialEpochContentKey: base64UrlToBytes(bootstrap!.epochContentKey) },
            close: disconnect }
        } })
        serveBrowserPeer(endpoint, peer)
        return { groupId: bytesToBase64Url(genesis.manifest.groupId), identity: bytesToBase64Url(peer.node.identity) }
      }
      case 'channel': await connect(request.channels!, request.connectionId!); return null
      case 'sync': await peer!.transport.catchUp(); await peer!.node.waitForIdle(); return null
      case 'disconnect': await disconnect(); return null
      case 'routeStats': return [...connectionHistory, ...(connection === undefined ? [] : [connection.stats()])]
      // Neither diagnostic takes the materialization mutex or starts another replay.
      case 'progress': {
        const status = await peer!.node.status()
        return { connected: connection !== undefined, records: status.transport.records,
          processedRecords: status.processedTransportRecords, finalOrderLength: status.finalOrderLength ?? 0,
          materializationPending: status.materializationPending,
          ...(status.lastError === undefined ? {} : { error: status.lastError }),
          ...(status.transport.lastCatchUpError === undefined ? {} : { transportError: status.transport.lastCatchUpError }),
          ...(status.ingest === undefined ? {} : { ingest: status.ingest }) } satisfies PilotProgress
      }
      case 'routeState': return routeState(peer!.transport, peer!.governed!.activeSnapshot, peer!.node.finalOrderLength)
      default: throw new Error('PILOT_COMMAND_UNKNOWN')
    }
  }
  void run().then(value => endpoint.postMessage({ pilot: 'response', id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ pilot: 'response', id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
