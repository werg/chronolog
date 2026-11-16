import { EphemeralChannel, type EphemeralSignal } from '@chronolog/agent-service/signals'
import { decodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import { loadOrCreateEnrollmentIdentity, type EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, decodeExecutionManifest, equalBytes, type EventPayload } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { acquireBrowserStorage, openBrowserPeer, serveBrowserPeer, type BrowserPeer, type WorkerEndpoint } from '@chronolog/runtime-browser'

import { connectGovernedBrowserPeer } from '../browser/event-connection.js'
import type { BrowserEventBootstrap, BrowserEventIdentity } from '../browser/event-contract.js'

const endpoint = globalThis as unknown as WorkerEndpoint
let peer: BrowserPeer | undefined, identity: EnrollmentIdentity | undefined, signals: EphemeralChannel | undefined
let connection: Awaited<ReturnType<typeof connectGovernedBrowserPeer>> | undefined
let bootstrap: BrowserEventBootstrap | undefined, connected = false
const subscriptions = new Map<string, { readonly abort: AbortController; readonly iterator: AsyncIterator<EphemeralSignal> }>()

async function connect(): Promise<void> {
  if (connected) return
  if (peer === undefined || identity === undefined || bootstrap === undefined || signals === undefined) throw new Error('PILOT_NOT_OPEN')
  connected = true
  try {
    connection = await connectGovernedBrowserPeer({ bootstrap, identity, transport: peer.transport,
      activeMembership: () => peer!.governed!.activeSnapshot,
      receiveSignal: async frame => { await signals!.receive(frame) } })
    void connection.completion.catch((error: unknown) => {
      if (connected) endpoint.postMessage({ pilot: 'connection-error', error: String(error) })
    })
    await peer.transport.catchUp(); await peer.node.waitForIdle()
  } catch (error) { connected = false; throw error }
}
async function disconnect(): Promise<void> {
  connected = false
  const previous = connection
  connection = undefined
  await previous?.close()
}

endpoint.addEventListener('message', (event) => {
  const request = event.data as { pilot?: string; id?: number; name?: string; bootstrap?: BrowserEventBootstrap;
    subscriptionId?: string; topics?: readonly string[]; topic?: string; payload?: EventPayload; ttlMs?: number }
  if (request.pilot === undefined) return
  const run = async (): Promise<unknown> => {
    switch (request.pilot) {
      case 'prepare': {
        const storage = await acquireBrowserStorage(request.name!)
        try {
          const prepared = await loadOrCreateEnrollmentIdentity(storage.bytes, 'peer')
          return { identity: bytesToBase64Url(prepared.signing.publicKeyBytes), readerKey: bytesToBase64Url(prepared.reader.publicKeyBytes),
            transportAuthor: feedIdFromPublicKey(prepared.signing.publicKeyBytes) } satisfies BrowserEventIdentity
        } finally { await storage.close() }
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
        await connect()
        serveBrowserPeer(endpoint, peer)
        return { groupId: bytesToBase64Url(genesis.manifest.groupId), identity: bytesToBase64Url(peer.node.identity) }
      }
      case 'sync': await peer!.transport.catchUp(); await peer!.node.waitForIdle(); return null
      case 'disconnect': await disconnect(); return null
      case 'reconnect': await connect(); return null
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

