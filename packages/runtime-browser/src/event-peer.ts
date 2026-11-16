import { ControlStore } from '@chronolog/control-store/browser'
import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import {
  ChronologNode, createGovernedNode, createEnrollmentService,
  type ChronologNodeOptions, type EnrollmentIdentity, type GovernedNodeOptions,
} from '@chronolog/node-core/browser'
import { PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner, type AtomicBytesStore, type ChronologTransport } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService, type GovernanceRpcAdmin } from '@chronolog/rpc/browser'
import { acquireBrowserStorage } from './opfs.js'
import { openBrowserDeviceRecords } from './device-records.js'
import { openSyncControl, type SyncControlPersistence } from './sync-control.js'
import { serveWorkerRpc, type WorkerEndpoint } from './worker-rpc.js'
export { WorkerRpcTransport } from './worker-rpc.js'

export interface BrowserEventPeerContext {
  readonly identity: EnrollmentIdentity
  readonly operations: AtomicBytesStore
  readonly transport: PortableFeedTransport
  readonly executionManifestDigest: Uint8Array
}
interface ConfigurationBase {
  readonly transport?: ChronologTransport
  readonly governanceAdmin?: GovernanceRpcAdmin
  readonly start?: () => Promise<void>
  readonly close?: () => Promise<void>
}
export type BrowserEventPeerConfiguration = ConfigurationBase & ({
  readonly governed: Omit<GovernedNodeOptions, 'identity' | 'transport' | 'operationStore' | 'controlStore' | 'materialization' | 'recipient'>
  readonly node?: never
} | {
  readonly node: Omit<ChronologNodeOptions, 'identity' | 'transport' | 'operationStore' | 'controlStore' | 'materialization'>
  readonly governed?: never
})

/** A durable browser peer whose dependency graph contains no SQL/WASM engine. */
export async function openBrowserEventPeer(options: {
  readonly name: string
  /** Only explicit first-device setup may create keys. Reopening fails if they are missing. */
  readonly createIdentity?: true
  readonly maxHistoryBytes?: number
  readonly configure: (context: BrowserEventPeerContext) => BrowserEventPeerConfiguration | Promise<BrowserEventPeerConfiguration>
}) {
  if (typeof document !== 'undefined') throw new Error('BROWSER_PEER_WORKER_REQUIRED')
  const storage = await acquireBrowserStorage(options.name)
  let control: SyncControlPersistence | undefined, runtime: ChronologMaterializationRuntime | undefined
  let transport: PortableFeedTransport | undefined, node: ChronologNode | undefined
  let governed: Awaited<ReturnType<typeof createGovernedNode>> | undefined
  let configuration: BrowserEventPeerConfiguration | undefined
  let service: NodeRpcService | undefined
  try {
    const { identity, records } = await openBrowserDeviceRecords(storage.bytes, options.createIdentity)
    transport = new PortableFeedTransport({ store: records,
      signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey), crypto: webFeedCrypto })
    runtime = await createEventMaterializationRuntime({ store: storage.bytes, namespace: 'application',
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) })
    configuration = await options.configure({ identity, operations: storage.bytes, transport, executionManifestDigest: runtime.queries.executionManifestDigest })
    control = await openSyncControl(storage.directory)
    const historyKind = configuration.governed?.genesis.manifest.historyPolicy?.kind ?? configuration.node?.historyPolicy?.kind ?? 'peer'
    const owned = { identity: identity.signing, transport: configuration.transport ?? transport,
      operationStore: storage.bytes, controlStore: new ControlStore(control, { orderPolicy: historyKind }), materialization: runtime }
    if (configuration.governed !== undefined) {
      governed = await createGovernedNode({ ...configuration.governed, ...owned,
        recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
      node = governed.node
    } else node = new ChronologNode({ ...configuration.node, ...owned })
    await configuration.start?.()
    if (governed === undefined) await node.start(); else await governed.start()
    const enrollment = governed === undefined ? undefined : createEnrollmentService({
      descriptor: governed.descriptor, store: storage.bytes, identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: owned.transport.identity,
      governance: governed.governance, activeMembership: () => governed!.activeSnapshot,
      ...(governed.enrollmentIssuer === undefined ? {} : { issuer: governed.enrollmentIssuer }),
      connected: async () => { const status = await owned.transport.status(); return governed!.governance.ownsCapabilityFeed || (status.connected ?? status.peers.length > 0) },
      executionManifestDigest: node.executionManifestDigest, isFinalTargetApplied: (target) => node!.isFinalTargetApplied(target.frontier),
    })
    service = new NodeRpcService({ node, ...(enrollment === undefined ? {} : { enrollment }),
      ...(configuration.governanceAdmin === undefined ? {} : { governanceAdmin: configuration.governanceAdmin }) })
    const rpc = new InProcessRpcTransport(service)
    let closed = false
    return { node, transport, rpc, ...(governed === undefined ? {} : { governed }),
      async close() {
        if (closed) return
        closed = true
        try {
          await rpc.close()
          try { await configuration!.close?.() }
          finally { if (governed === undefined) await node!.close(); else await governed.close() }
        } finally { try { control!.close() } finally { await storage.close() } }
      },
    }
  } catch (error) {
    try { await service?.close() } catch { /* Preserve the startup error. */ }
    try { await configuration?.close?.() } catch { /* Preserve the startup error. */ }
    try {
      if (governed !== undefined) await governed.close()
      else if (node !== undefined) await node.close()
      else { await runtime?.close(); await transport?.close() }
    } finally { try { control?.close() } finally { await storage.close() } }
    throw error
  }
}
export type BrowserEventPeer = Awaited<ReturnType<typeof openBrowserEventPeer>>
export function serveBrowserEventPeer(endpoint: WorkerEndpoint, peer: BrowserEventPeer): () => Promise<void> {
  return serveWorkerRpc(endpoint, peer.rpc, () => peer.close())
}
