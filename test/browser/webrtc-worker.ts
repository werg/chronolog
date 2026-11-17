import { sha256 } from '@chronolog/canonical'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { decodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, equalBytes } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { openBrowserEventPeer, prepareBrowserIdentity, type BrowserEventPeer } from '@chronolog/runtime-browser/events'
import { frameRtcDataChannel, type DataChannelConnection } from '@chronolog/transport-webrtc'

import type { BrowserEventBootstrap } from './event-contract.js'

let peer: BrowserEventPeer | undefined, identity: EnrollmentIdentity | undefined, client: ChronologClient | undefined
let channel: DataChannelConnection | undefined, session: Awaited<ReturnType<typeof openAuthenticatedPeerLink>> | undefined
let detach: (() => void) | undefined, completionError: string | undefined
let generation = 0
let attachmentId: number | undefined

async function disconnect(expected?: number): Promise<void> {
  if (expected !== undefined && expected !== attachmentId) return
  generation++
  const active = session, framed = channel, previousId = attachmentId
  session = undefined; channel = undefined; attachmentId = undefined
  detach?.(); detach = undefined
  if (previousId !== undefined) endpoint.postMessage({ kind: 'peer-ended', attachmentId: previousId })
  await Promise.all([active?.close(), framed?.close()])
}

const endpoint = globalThis as unknown as { addEventListener(type: 'message', listener: (event: MessageEvent) => void): void; postMessage(value: unknown): void }
endpoint.addEventListener('message', event => {
  const request = event.data as { id: number; method: string; name?: string; bootstrap?: BrowserEventBootstrap;
    channel?: RTCDataChannel; attachmentId?: number; operationId?: string; text?: string; hash?: string }
  const run = async (): Promise<unknown> => {
    switch (request.method) {
      case 'prepare': {
        const prepared = await prepareBrowserIdentity(request.name!, true)
        return { identity: bytesToBase64Url(prepared.signing.publicKeyBytes), readerKey: bytesToBase64Url(prepared.reader.publicKeyBytes),
          transportAuthor: feedIdFromPublicKey(prepared.signing.publicKeyBytes) }
      }
      case 'open': {
        const bootstrap = request.bootstrap!, genesis = decodeSignedGenesis(base64UrlToBytes(bootstrap.genesis))
        peer = await openBrowserEventPeer({ name: request.name!, configure(context) {
          identity = context.identity
          return { governed: { genesis, groupRoute: base64UrlToBytes(bootstrap.groupRoute),
            initialEpochContentKey: base64UrlToBytes(bootstrap.epochContentKey) },
            close: disconnect }
        } })
        client = new ChronologClient({ groupId: bytesToBase64Url(genesis.manifest.groupId), transport: peer.rpc, unaryRetryAttempts: 1 })
        return { identity: bytesToBase64Url(identity!.signing.publicKeyBytes) }
      }
      case 'channel': {
        await disconnect()
        const currentGeneration = ++generation
        const framed = frameRtcDataChannel(request.channel!)
        channel = framed; attachmentId = request.attachmentId; completionError = undefined
        try {
          await framed.ready
          const snapshot = peer!.governed!.activeSnapshot
          const reader = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
            equalBytes(capability.grant.signingPublicKey, identity!.signing.publicKeyBytes) && isCapabilityActive(capability, snapshot.revision))
          if (reader === undefined) throw new Error('WEBRTC_BROWSER_READER_MISSING')
          const authenticated = await openAuthenticatedPeerLink({ connection: framed, local: peer!.transport.asLink(), groupId: snapshot.groupId,
            identity: identity!.signing, grantId: reader.id, authorizePeer: ({ authorId, grantId }) => {
              const current = peer!.governed!.activeSnapshot, capability = current.capabilities.get(bytesToHex(grantId))
              return capability !== undefined && capability.grant.role === 'reader' && isCapabilityActive(capability, current.revision) &&
                equalBytes(capability.grant.signingPublicKey, authorId)
            } })
          if (currentGeneration !== generation) { await authenticated.close(); throw new Error('WEBRTC_ATTACHMENT_SUPERSEDED') }
          session = authenticated
          const disconnectFeed = peer!.transport.connect(authenticated.link)
          detach = disconnectFeed
          void authenticated.completion.catch((error: unknown) => { if (session === authenticated) completionError = String(error) }).finally(() => {
            disconnectFeed()
            if (session === authenticated) {
              session = undefined; channel = undefined; attachmentId = undefined
              endpoint.postMessage({ kind: 'peer-ended', attachmentId: request.attachmentId, error: completionError })
            }
          })
          return { workerOwnsChannel: true }
        } catch (error) {
          if (currentGeneration === generation) await disconnect(request.attachmentId)
          else await framed.close()
          throw error
        }
      }
      case 'disconnect': await disconnect(request.attachmentId); return null
      case 'publish': {
        const handle = await client!.events.publish('chat', { text: request.text! }, { operationId: request.operationId! })
        try { return { proposalId: handle.proposalId, outcome: await handle.final({ signal: AbortSignal.timeout(20_000) }) } }
        finally { handle.dispose() }
      }
      case 'payload': {
        const bytes = await session!.link.readPayload(request.hash!)
        if (bytes === null) throw new Error('WEBRTC_PAYLOAD_MISSING')
        return { bytes: bytes.length, sha256: bytesToHex(await sha256(bytes)) }
      }
      case 'state': {
        if (completionError !== undefined) throw new Error(completionError)
        await peer!.transport.catchUp(); await peer!.node.waitForIdle()
        const records = (await peer!.transport.history()).map(record => ({ id: record.id, author: record.author })).sort((a, b) => a.id.localeCompare(b.id))
        return { records, historySha256: bytesToHex(await sha256(new TextEncoder().encode(records.map(record => record.id).join('\n')))),
          events: await client!.events.read(), stats: channel!.stats }
      }
      case 'close': await client?.close(); await peer?.close(); return null
      default: throw new Error('WEBRTC_FIXTURE_COMMAND_INVALID')
    }
  }
  void run().then(value => endpoint.postMessage({ id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
