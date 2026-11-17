import { EphemeralChannel, type EphemeralSignal } from '@chronolog/agent-service/signals'
import { decodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, decodeExecutionManifest, equalBytes, type EventPayload } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { prepareBrowserIdentity, openBrowserPeer, serveBrowserPeer, type BrowserPeer, type WorkerEndpoint } from '@chronolog/runtime-browser'
import { frameRtcDataChannel, type DataChannelConnection, type RtcDataChannel } from '@chronolog/transport-webrtc'

import type { BrowserEventIdentity } from '../browser/event-contract.js'
import type { PilotPeerBootstrap, PilotProgress, PilotRouteStats } from './contract.js'
import { attachPilotPeer } from './peer.js'
import { routeState } from './route-state.js'

const endpoint = globalThis as unknown as WorkerEndpoint
let peer: BrowserPeer | undefined, identity: EnrollmentIdentity | undefined, signals: EphemeralChannel | undefined
let connection: { close(): Promise<void>; sendSignal(bytes: Uint8Array): Promise<void>; stats(): PilotRouteStats } | undefined
let opening: DataChannelConnection | undefined, connectionGeneration = 0
let bootstrap: PilotPeerBootstrap | undefined
const connectionHistory: PilotRouteStats[] = []
const subscriptions = new Map<string, { readonly abort: AbortController; readonly iterator: AsyncIterator<EphemeralSignal> }>()

/** The Window transfers an untouched channel; keys and application frames stay here. */
async function connect(channel: RtcDataChannel, connectionId: number): Promise<void> {
  if (peer === undefined || identity === undefined || bootstrap === undefined || signals === undefined) throw new Error('PILOT_NOT_OPEN')
  await disconnect()
  const generation = ++connectionGeneration
  const framed = frameRtcDataChannel(channel)
  opening = framed
  try {
    const authenticated = await attachPilotPeer({ connection: framed, transport: peer.transport, identity,
      nativeIdentity: bootstrap.nativeIdentity, activeMembership: () => peer!.governed!.activeSnapshot,
      receiveSignal: async frame => { await signals!.receive(frame) } })
    if (generation !== connectionGeneration) { await authenticated.close(); throw new Error('PILOT_CONNECTION_SUPERSEDED') }
    let closed = false
    const current = { sendSignal: (bytes: Uint8Array) => authenticated.sendSignal(bytes),
      stats: (): PilotRouteStats => { const stats = framed.stats; return { route: 'webrtc', authenticatedMs: authenticated.authenticatedMs,
        sentBytes: stats.sentBytes, receivedBytes: stats.receivedBytes, queuedBytes: stats.queuedSendBytes + stats.queuedReceiveBytes } },
      async close() { if (closed) return; closed = true; await authenticated.close() } }
    connection = current
    void authenticated.completion.catch((error: unknown) => {
      if (!closed && connection === current) endpoint.postMessage({ pilot: 'connection-error', connectionId, error: String(error) })
    }).finally(() => {
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
    subscriptionId?: string; topics?: readonly string[]; topic?: string; payload?: EventPayload; ttlMs?: number; createIdentity?: boolean;
    channel?: RtcDataChannel; connectionId?: number }
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
        peer = await openBrowserPeer({ name: request.name!, engineUrl: new URL('./engine/', globalThis.location.href), configure(context) {
          identity = context.identity
          return { materializer: { executionManifest: decodeExecutionManifest(base64UrlToBytes(bootstrap!.executionManifest)), rootAdministrator: genesis.manifest.schemaAdminPublicKey },
            governed: { genesis, groupRoute: base64UrlToBytes(bootstrap!.groupRoute), initialEpochContentKey: base64UrlToBytes(bootstrap!.epochContentKey) },
            close: async () => {
              for (const subscription of subscriptions.values()) subscription.abort.abort()
              subscriptions.clear(); signals?.close(); await disconnect()
            } }
        } })
        const snapshot = peer.governed!.activeSnapshot
        const writer = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'writer' &&
          isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, identity!.signing.publicKeyBytes))
        if (writer === undefined) throw new Error('PILOT_SIGNAL_GRANT_REQUIRED')
        signals = await EphemeralChannel.open({ groupId: genesis.manifest.groupId, identity: identity!.signing, grantId: writer.id,
          send: async frame => { if (connection === undefined) throw new Error('PILOT_PEER_DISCONNECTED'); await connection.sendSignal(frame) },
          authorize: ({ authorId, grantId, topic }) => {
            const current = peer!.governed!.activeSnapshot, capability = current.capabilities.get(bytesToHex(grantId))
            const allowed = capability?.grant.program?.signals
            return capability !== undefined && capability.grant.role === 'writer' && isCapabilityActive(capability, current.revision) &&
              equalBytes(capability.grant.signingPublicKey, authorId) && allowed !== undefined && (allowed.includes('*') || allowed.includes(topic))
          } })
        serveBrowserPeer(endpoint, peer)
        return { groupId: bytesToBase64Url(genesis.manifest.groupId), identity: bytesToBase64Url(peer.node.identity) }
      }
      case 'channel': await connect(request.channel!, request.connectionId!); return null
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
      case 'signalPublish': return signals!.publish(request.topic!, request.payload!, { ttlMs: request.ttlMs ?? 2500 })
      case 'signalNext': {
        const id = request.subscriptionId!
        let subscription = subscriptions.get(id)
        if (subscription === undefined) {
          const abort = new AbortController()
          subscription = { abort, iterator: signals!.subscribe({ ...(request.topics === undefined ? {} : { topics: request.topics }), signal: abort.signal })[Symbol.asyncIterator]() }
          subscriptions.set(id, subscription)
        }
        return subscription.iterator.next()
      }
      case 'signalCancel': {
        const subscription = subscriptions.get(request.subscriptionId!)
        subscriptions.delete(request.subscriptionId!)
        subscription?.abort.abort(); await subscription?.iterator.return?.(); return null
      }
      default: throw new Error('PILOT_COMMAND_UNKNOWN')
    }
  }
  void run().then(value => endpoint.postMessage({ pilot: 'response', id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ pilot: 'response', id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
