import { ControlStore } from '@chronolog/control-store/browser'
import {
  DeterministicMaterializer, createDoltLiteMaterializationRuntime,
  type MaterializerOptions,
} from '@chronolog/materializer-doltlite/browser'
import {
  ChronologNode, createGovernedNode, createEnrollmentService, loadOrCreateEnrollmentIdentity,
  type ChronologNodeOptions, type EnrollmentIdentity, type GovernedNodeOptions,
} from '@chronolog/node-core/browser'
import {
  DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner,
  type AtomicBytesStore, type ChronologTransport,
} from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService, type GovernanceRpcAdmin } from '@chronolog/rpc/browser'

import { BrowserControlPersistence } from './control-persistence.js'
import { acquireBrowserStorage } from './opfs.js'
import { loadBrowserEngine, type LoadedBrowserEngine } from './load-engine.js'
import { createWasmEngineFactory, type OpfsSqlitePool } from './wasm-engine.js'
import { serveWorkerRpc, type WorkerEndpoint } from './worker-rpc.js'

export interface BrowserPeerContext {
  /** Private keys stay in the owner Worker and its private OPFS store. */
  readonly identity: EnrollmentIdentity
  readonly operations: AtomicBytesStore
  readonly transport: PortableFeedTransport
  readonly engine: LoadedBrowserEngine
}

interface BrowserPeerConfigurationBase {
  readonly materializer: Pick<MaterializerOptions, 'executionManifest' | 'rootAdministrator'> &
    Pick<Partial<MaterializerOptions>, 'checkpointEvery' | 'forkSeeding' | 'publicationFaultInjector'>
  /** Optional connection adapter wraps the same durable local signed feed. */
  readonly transport?: ChronologTransport
  readonly governanceAdmin?: GovernanceRpcAdmin
  readonly start?: () => Promise<void>
  readonly close?: () => Promise<void>
}

export type BrowserPeerConfiguration = BrowserPeerConfigurationBase & ({
  /** Production composition: one signed group descriptor selects governance and finality. */
  readonly governed: Omit<GovernedNodeOptions, 'identity' | 'transport' | 'operationStore' | 'controlStore' | 'materialization' | 'recipient'>
  readonly node?: never
} | {
  /** Low-level composition for applications with their own membership resolver. */
  readonly node: Omit<ChronologNodeOptions, 'identity' | 'transport' | 'operationStore' | 'controlStore' | 'materialization'>
  readonly governed?: never
})

export interface BrowserPeer {
  readonly node: ChronologNode
  readonly transport: PortableFeedTransport
  readonly materializer: DeterministicMaterializer
  readonly governed?: Awaited<ReturnType<typeof createGovernedNode>>
  readonly rpc: InProcessRpcTransport
  close(): Promise<void>
}

/**
 * Opens a complete local peer: signed records, private durable operations and
 * keys, control index, and real DoltLite SQL all live in the owning Worker.
 * Application code supplies the same membership/history policy as native peers.
 */
export async function openBrowserPeer(options: {
  readonly name: string
  readonly engineUrl: string | URL
  readonly configure: (context: BrowserPeerContext) => BrowserPeerConfiguration | Promise<BrowserPeerConfiguration>
}): Promise<BrowserPeer> {
  if (typeof document !== 'undefined' || !globalThis.crossOriginIsolated) throw new Error('BROWSER_PEER_ISOLATED_WORKER_REQUIRED')
  const storage = await acquireBrowserStorage(options.name)
  let transport: PortableFeedTransport | undefined
  let materializer: DeterministicMaterializer | undefined
  let control: BrowserControlPersistence | undefined
  let node: ChronologNode | undefined
  let governed: Awaited<ReturnType<typeof createGovernedNode>> | undefined
  let configuration: BrowserPeerConfiguration | undefined
  let sqlStorage: OpfsSqlitePool | undefined
  try {
    const engine = await loadBrowserEngine(options.engineUrl)
    const identity = await loadOrCreateEnrollmentIdentity(storage.bytes, 'peer')
    const records = await DurableFeedStore.open(storage.bytes, webFeedCrypto)
    transport = new PortableFeedTransport({ store: records, signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey), crypto: webFeedCrypto })
    configuration = await options.configure({ identity, operations: storage.bytes, transport, engine })
    const directory = `/chronolog-${options.name}`
    if (engine.module.installOpfsSAHPoolVfs === undefined) throw new Error('BROWSER_SQLITE_OPFS_POOL_UNAVAILABLE')
    sqlStorage = await engine.module.installOpfsSAHPoolVfs({
      name: 'chronolog-opfs', directory: `${directory}/sql`, initialCapacity: 16,
    })
    const factory = createWasmEngineFactory(engine.module, engine.manifest, sqlStorage.vfsName)
    control = new BrowserControlPersistence(factory({ path: `${directory}/control.db` }).database)
    materializer = await DeterministicMaterializer.open({
      ...configuration.materializer, path: `${directory}/application.db`, openDatabase: factory,
    })
    const historyKind = configuration.governed?.genesis.manifest.historyPolicy?.kind ?? configuration.node?.historyPolicy?.kind ?? 'peer'
    const owned = {
      identity: identity.signing, transport: configuration.transport ?? transport,
      operationStore: storage.bytes,
      controlStore: new ControlStore(control, { orderPolicy: historyKind }),
      materialization: createDoltLiteMaterializationRuntime(materializer),
    }
    if (configuration.governed !== undefined) {
      governed = await createGovernedNode({
        ...configuration.governed, ...owned,
        recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey },
      })
      node = governed.node
    } else node = new ChronologNode({ ...configuration.node, ...owned })
    await configuration.start?.()
    if (governed === undefined) await node.start()
    else await governed.start()
    const enrollment = governed === undefined ? undefined : createEnrollmentService({
      descriptor: governed.descriptor, store: storage.bytes, identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: owned.transport.identity,
      governance: governed.governance, activeMembership: () => governed!.activeSnapshot,
      ...(governed.enrollmentIssuer === undefined ? {} : { issuer: governed.enrollmentIssuer }),
      connected: async () => {
        const status = await owned.transport.status()
        return governed!.governance.ownsCapabilityFeed || (status.connected ?? status.peers.length > 0)
      },
      executionManifestDigest: node.executionManifestDigest,
      isFinalTargetApplied: (target) => node!.isFinalTargetApplied(target.frontier),
    })
    const rpc = new InProcessRpcTransport(new NodeRpcService({
      node, ...(enrollment === undefined ? {} : { enrollment }),
      ...(configuration.governanceAdmin === undefined ? {} : { governanceAdmin: configuration.governanceAdmin }),
    }))
    let closed = false
    return {
      node, transport, materializer, rpc, ...(governed === undefined ? {} : { governed }),
      async close() {
        if (closed) return
        closed = true
        await rpc.close()
        try { await configuration!.close?.(); if (governed === undefined) await node!.close(); else await governed.close() }
        finally { try { control!.close(); sqlStorage!.pauseVfs() } finally { await storage.close() } }
      },
    }
  } catch (error) {
    try { await configuration?.close?.() } catch { /* Keep the startup error. */ }
    if (governed !== undefined) { try { await governed.close() } catch { /* Keep the startup error. */ } }
    else if (node !== undefined) { try { await node.close() } catch { /* Keep the startup error. */ } }
    else { materializer?.close(); await transport?.close() }
    try { control?.close(); sqlStorage?.pauseVfs() } finally { await storage.close() }
    throw error
  }
}

/** Attach the shared client contract only after recovery has opened the local peer. */
export function serveBrowserPeer(endpoint: WorkerEndpoint, peer: BrowserPeer): () => Promise<void> {
  return serveWorkerRpc(endpoint, peer.rpc, () => peer.close())
}
