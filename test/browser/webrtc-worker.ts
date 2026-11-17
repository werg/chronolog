import { sha256 } from '@chronolog/canonical'
import type { GovernedPeerSession } from '@chronolog/agent-service/governed-peer'
import { decodeSignedGenesis } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToBase64Url, bytesToHex } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { openBrowserEventPeer, prepareBrowserIdentity, type BrowserEventPeer } from '@chronolog/runtime-browser/events'
import { frameRtcPeerChannels, type PeerDataChannelConnection, type WebRtcChannels } from '@chronolog/transport-webrtc'

import type { BrowserEventBootstrap } from './event-contract.js'

let peer: BrowserEventPeer | undefined, identity: EnrollmentIdentity | undefined, client: ChronologClient | undefined
let channel: PeerDataChannelConnection | undefined, session: GovernedPeerSession | undefined
let completionError: string | undefined
let generation = 0
let nativeIdentity: Uint8Array | undefined
let attachmentId: number | undefined

async function disconnect(expected?: number): Promise<void> {
  if (expected !== undefined && expected !== attachmentId) return
  generation++
  const active = session, framed = channel, previousId = attachmentId
  session = undefined; channel = undefined; attachmentId = undefined
  if (previousId !== undefined) endpoint.postMessage({ kind: 'peer-ended', attachmentId: previousId })
  await Promise.all([active?.close(), framed?.close()])
}

const endpoint = globalThis as unknown as { addEventListener(type: 'message', listener: (event: MessageEvent) => void): void; postMessage(value: unknown): void }
endpoint.addEventListener('message', event => {
  const request = event.data as { id: number; method: string; name?: string; bootstrap?: BrowserEventBootstrap;
    channels?: WebRtcChannels; attachmentId?: number; operationId?: string; text?: string; hash?: string }
  const run = async (): Promise<unknown> => {
    switch (request.method) {
      case 'prepare': {
        const prepared = await prepareBrowserIdentity(request.name!, true)
        return { identity: bytesToBase64Url(prepared.signing.publicKeyBytes), readerKey: bytesToBase64Url(prepared.reader.publicKeyBytes),
          transportAuthor: feedIdFromPublicKey(prepared.signing.publicKeyBytes) }
      }
      case 'open': {
        const bootstrap = request.bootstrap!, genesis = decodeSignedGenesis(base64UrlToBytes(bootstrap.genesis))
        nativeIdentity = base64UrlToBytes(bootstrap.nativeIdentity)
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
        const framed = frameRtcPeerChannels(request.channels!)
        channel = framed; attachmentId = request.attachmentId; completionError = undefined
        try {
          await framed.ready
          const authenticated = await peer!.connectPeer({ connection: framed, peerIdentity: nativeIdentity! })
          if (currentGeneration !== generation) { await authenticated.close(); throw new Error('WEBRTC_ATTACHMENT_SUPERSEDED') }
          session = authenticated
          void authenticated.completion.catch((error: unknown) => { if (session === authenticated) completionError = String(error) }).finally(() => {
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
        const bytes = await peer!.transport.getPayload(request.hash!)
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
