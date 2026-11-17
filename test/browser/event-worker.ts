import { CheckpointStore } from '@chronolog/agent-service/workers'
import { decodeSignedGenesis } from '@chronolog/capabilities'
import { loadEnrollmentIdentity, type EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, utf8 } from '@chronolog/protocol'
import { feedIdFromPublicKey, type AtomicBytesStore } from '@chronolog/records'
import { openBrowserEventPeer, prepareBrowserIdentity, serveBrowserEventPeer, type BrowserEventPeer } from '@chronolog/runtime-browser/events'

import { acquireBrowserStorage } from '../../packages/runtime-browser/src/opfs.js'
import { openSyncControl } from '../../packages/runtime-browser/src/sync-control.js'
import type { WorkerEndpoint } from '../../packages/runtime-browser/src/worker-rpc.js'
import { connectGovernedBrowserPeer } from './event-connection.js'
import type { BrowserEventBootstrap, BrowserEventIdentity } from './event-contract.js'
import { qualifyStorageQuota } from './storage-quota.js'

const endpoint = globalThis as unknown as WorkerEndpoint
let peer: BrowserEventPeer | undefined, identity: EnrollmentIdentity | undefined, operations: AtomicBytesStore | undefined
let name = ''
let connection: Awaited<ReturnType<BrowserEventPeer['connectPeer']>> | undefined
let bootstrap: BrowserEventBootstrap | undefined
let checkpointPause: 'before' | 'after' | undefined
const checkpointBinding = utf8('events-browser-fixture/v1')
const pause = async (point: string): Promise<never> => {
  endpoint.postMessage({ fixture: 'paused', point })
  return new Promise(() => { /* The qualification runner terminates this real Worker. */ })
}
const checkpoint = () => new CheckpointStore(operations!, { id: 'browser-projection', binding: checkpointBinding })
async function connect(): Promise<void> {
  await connection?.close()
  connection = await connectGovernedBrowserPeer({ bootstrap: bootstrap!, peer: peer! })
  void connection.completion.catch((error: unknown) => endpoint.postMessage({ fixture: 'connection-error', error: String(error) }))
}

endpoint.addEventListener('message', (event) => {
  const request = event.data as { fixture?: string; id?: number; name?: string; bootstrap?: BrowserEventBootstrap;
    cutoff?: string; pause?: 'before' | 'after'; cursor?: string; revision?: string; state?: string; manifest?: string; binding?: string }
  if (request.fixture === undefined) return
  const run = async (): Promise<unknown> => {
    switch (request.fixture) {
      case 'prepare': {
        const prepared = await prepareBrowserIdentity(request.name!, true)
        const value: BrowserEventIdentity = { identity: bytesToBase64Url(prepared.signing.publicKeyBytes),
          readerKey: bytesToBase64Url(prepared.reader.publicKeyBytes), transportAuthor: feedIdFromPublicKey(prepared.signing.publicKeyBytes) }
        return value
      }
      case 'removeFeedMetadata':
      case 'restoreFeedMetadata': {
        const storage = await acquireBrowserStorage(request.name!)
        try {
          const device = await loadEnrollmentIdentity(storage.bytes, 'peer')
          if (request.fixture === 'restoreFeedMetadata') {
            await storage.bytes.put('feed/manifest', base64UrlToBytes(request.manifest!))
            await storage.bytes.put('browser/feed-initialized', base64UrlToBytes(request.binding!))
            return null
          }
          const manifest = await storage.bytes.get('feed/manifest'), binding = await storage.bytes.get('browser/feed-initialized')
          if (manifest === null || binding === null) throw new Error('FIXTURE_FEED_METADATA_MISSING')
          // Lose both feed metadata files while retaining the original signer.
          for (const key of ['feed/manifest', 'browser/feed-initialized']) {
            const fileHash = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(key).slice().buffer))
            await storage.directory.removeEntry(`value-${bytesToHex(fileHash)}`)
          }
          return { manifest: bytesToBase64Url(manifest), binding: bytesToBase64Url(binding), identity: bytesToBase64Url(device.signing.publicKeyBytes) }
        } finally { await storage.close() }
      }
      case 'open': {
        name = request.name!
        bootstrap = request.bootstrap!
        const enrollment = bootstrap
        const genesis = decodeSignedGenesis(base64UrlToBytes(enrollment.genesis))
        peer = await openBrowserEventPeer({ name, configure(context) {
          identity = context.identity; operations = context.operations
          const original = operations.put.bind(operations)
          operations.put = async (key, bytes) => {
            if (checkpointPause === 'before' && key.startsWith('agent/checkpoint/')) await pause('checkpoint-before')
            await original(key, bytes)
            if (checkpointPause === 'after' && key.startsWith('agent/checkpoint/')) await pause('checkpoint-after')
          }
          return { governed: { genesis, groupRoute: base64UrlToBytes(enrollment.groupRoute),
            initialEpochContentKey: base64UrlToBytes(enrollment.epochContentKey) },
            close: async () => { await connection?.close() } }
        } })
        await connect()
        await peer.transport.catchUp()
        await peer.node.waitForIdle()
        serveBrowserEventPeer(endpoint, peer)
        return { identity: bytesToBase64Url(peer.node.identity), groupId: bytesToBase64Url(genesis.manifest.groupId),
          isolated: globalThis.crossOriginIsolated }
      }
      case 'connect': await connect(); return null
      case 'disconnect': await connection?.close(); connection = undefined; return null
      case 'state': {
        await peer!.transport.catchUp()
        await peer!.node.waitForIdle()
        return { events: await peer!.node.events.read(), records: (await peer!.transport.history()).length,
          finalThrough: peer!.node.finalThrough, status: await peer!.node.status() }
      }
      case 'checkpoint': {
        checkpointPause = request.pause
        await checkpoint().commit({ cursor: request.cursor!, revision: request.revision!, state: utf8(request.state!) })
        return null
      }
      case 'checkpointState': {
        const saved = await checkpoint().load()
        return saved === null ? null : { cursor: saved.cursor, revision: saved.revision, state: new TextDecoder().decode(saved.state) }
      }
      case 'privateValue': {
        const key = 'qualification/private-device-value'
        if (request.state !== undefined) await operations!.put(key, utf8(request.state))
        const value = await operations!.get(key)
        return value === null ? null : new TextDecoder().decode(value)
      }
      case 'quota': return qualifyStorageQuota()
      case 'privateCutoff':
      case 'crashCutoff': {
        const root = await navigator.storage.getDirectory()
        const directory = await (await root.getDirectoryHandle(`chronolog-${name}`)).getDirectoryHandle('cutoff-probe', { create: true })
        const control = await openSyncControl(directory)
        try {
          if (request.cutoff !== undefined) control.saveValidatorCutoff({ validatorId: identity!.signing.publicKeyBytes,
            acceptedAboveMs: BigInt(request.cutoff) })
          if (request.fixture === 'crashCutoff') await pause('private-cutoff-flushed')
          return control.loadValidatorCutoffs().map((entry) => String(entry.acceptedAboveMs))
        } finally { control.close() }
      }
      default: throw new Error('UNKNOWN_EVENT_BROWSER_COMMAND')
    }
  }
  void run().then((value) => endpoint.postMessage({ fixture: 'response', id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ fixture: 'response', id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
