import { decodeSignedGenesis, encodeGenesisManifest, isCapabilityActive } from '@chronolog/capabilities'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { LedgerRecordError } from '@chronolog/node-core/ledger'
import {
  DOMAINS, base64UrlToBytes, bytesToBase64Url, decodeExecutionManifest,
  digestExecutionManifest, equalBytes, hashDomain,
} from '@chronolog/protocol'
import { ChangeSignal, type FeedLink } from '@chronolog/records'
import { openBrowserPeer, serveBrowserPeer, type BrowserPeer, type WorkerEndpoint } from '@chronolog/runtime-browser'
import { createCertificateFetcher, TendrillerTransport } from '@chronolog/transport-tendriller'
import { createRecordLogClient } from '@tendriller/core/records'

import type { BrowserBridgeBootstrap, BrowserBridgeIdentity, BrowserBridgeSnapshot } from './bridge-contract.js'
import { connectGovernedBrowserPeer } from './event-connection.js'

const endpoint = globalThis as unknown as WorkerEndpoint
const closing = new AbortController()
const ports = new Set<MessagePort>()
let peer: BrowserPeer | undefined
let relay: TendrillerTransport | undefined
let nativeBootstrap: BrowserBridgeBootstrap | undefined
let localIdentity: EnrollmentIdentity | undefined
let nativePeer: Awaited<ReturnType<typeof connectGovernedBrowserPeer>> | undefined

async function connectNative(): Promise<void> {
  if (nativeBootstrap === undefined || nativePeer !== undefined || peer?.governed === undefined || localIdentity === undefined) return
  const snapshot = peer.governed.activeSnapshot
  const reader = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
    isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, localIdentity!.signing.publicKeyBytes))
  if (reader === undefined) return
  const connected = await connectGovernedBrowserPeer({ bootstrap: nativeBootstrap, peer })
  nativePeer = connected
  void connected.completion.finally(() => { if (nativePeer === connected) nativePeer = undefined }).catch(() => undefined)
}

interface FixtureRequest {
  readonly fixture?: string
  readonly id?: number
  readonly name?: string
  readonly createIdentity?: true
  readonly bootstrap?: BrowserBridgeBootstrap
  readonly relay?: boolean
  readonly port?: MessagePort
  readonly identity?: string
}

type LinkRequestFields = {
  readonly method: 'read' | 'evidence'
  readonly feed?: string
  readonly after: bigint
  readonly limit: number
} | { readonly method: 'payload'; readonly hash: string }
type LinkRequest = LinkRequestFields & { readonly id: number }
interface LinkResponse {
  readonly id?: number
  readonly hint?: true
  readonly bytes?: readonly Uint8Array[]
  readonly error?: string
}

/** A real peer range link; the receiver verifies and persists every returned byte. */
function receiveLink(port: MessagePort, identity: string): FeedLink {
  ports.add(port)
  const changes = new ChangeSignal()
  let next = 0
  const pending = new Map<number, { resolve(value: readonly Uint8Array[]): void; reject(error: Error): void }>()
  port.addEventListener('message', (event: MessageEvent<LinkResponse>) => {
    const message = event.data
    if (message.hint) { changes.notify(); return }
    if (message.id === undefined) return
    const request = pending.get(message.id)
    pending.delete(message.id)
    if (message.error !== undefined) request?.reject(new Error(message.error))
    else request?.resolve(message.bytes ?? [])
  })
  port.start()
  closing.signal.addEventListener('abort', () => {
    changes.close()
    for (const request of pending.values()) request.reject(new Error('BROWSER_PEER_LINK_CLOSED'))
    pending.clear()
  }, { once: true })
  const request = (fields: LinkRequestFields): Promise<readonly Uint8Array[]> => new Promise((resolve, reject) => {
    const id = ++next
    pending.set(id, { resolve, reject })
    port.postMessage({ id, ...fields } satisfies LinkRequest)
  })
  return {
    identity,
    read: (feed, after, limit) => request({ method: 'read', feed, after, limit }),
    readEvidence: (after, limit) => request({ method: 'evidence', after, limit }),
    async readPayload(hash) {
      const values = await request({ method: 'payload', hash })
      if (values.length > 1) throw new Error('BROWSER_PEER_PAYLOAD_RESPONSE_INVALID')
      return values[0] ?? null
    },
    watch: (signal) => changes.watch(signal),
  }
}

function serveLink(port: MessagePort): void {
  ports.add(port)
  const link = peer!.transport.asLink()
  port.addEventListener('message', (event: MessageEvent<LinkRequest>) => {
    const request = event.data, id = request.id
    const result = request.method === 'payload'
      ? link.readPayload(request.hash).then(bytes => bytes === null ? [] : [bytes])
      : request.method === 'read' ? link.read(request.feed!, request.after, request.limit) : link.readEvidence(request.after, request.limit)
    void result.then((bytes) => port.postMessage({ id, bytes } satisfies LinkResponse),
      (error: unknown) => port.postMessage({ id, error: error instanceof Error ? error.message : String(error) } satisfies LinkResponse))
  })
  port.start()
  void (async () => {
    for await (const _hint of link.watch(closing.signal)) {
      if (closing.signal.aborted) return
      port.postMessage({ hint: true } satisfies LinkResponse)
    }
  })()
}

endpoint.addEventListener('message', (event) => {
  const request = event.data as FixtureRequest
  if (request.fixture === undefined) return
  const run = async (): Promise<unknown> => {
    switch (request.fixture) {
      case 'open': {
        const bootstrap = request.bootstrap!
        const genesis = decodeSignedGenesis(base64UrlToBytes(bootstrap.genesis))
        const executionManifest = decodeExecutionManifest(base64UrlToBytes(bootstrap.executionManifest))
        const policy = genesis.manifest.historyPolicy
        if (policy?.kind !== 'coordinated' || policy.historyId === undefined || policy.authorityPublicKey === undefined) {
          throw new Error('BROWSER_BRIDGE_REQUIRES_COORDINATED_GENESIS')
        }
        const configuration = {
          kind: 'coordinated' as const, historyId: policy.historyId, authorityPublicKey: policy.authorityPublicKey,
          groupId: genesis.manifest.groupId,
          genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)),
          executionManifestDigest: await digestExecutionManifest(executionManifest),
        }
        const groupRoute = base64UrlToBytes(bootstrap.groupRoute)
        peer = await openBrowserPeer({
          name: request.name!, ...(request.createIdentity === true ? { createIdentity: true } : {}), engineUrl: new URL('/engine/', globalThis.location.href),
          configure(context) {
            localIdentity = context.identity
            if (request.relay) {
              nativeBootstrap = bootstrap
              const headers = () => ({ Authorization: `Bearer ${bootstrap.token}` })
              relay = new TendrillerTransport({
                local: context.transport, groupRoute, configuration, watch: false,
                records: createRecordLogClient({ base: bootstrap.hubUrl, headers }),
                certificate: createCertificateFetcher({ url: `${bootstrap.hubUrl}/_chronolog/certificate`, headers }),
              })
            }
            return {
              materializer: { executionManifest, rootAdministrator: genesis.manifest.schemaAdminPublicKey, checkpointEvery: 1 },
              governed: { genesis, groupRoute },
              ...(relay === undefined ? {} : { transport: relay, start: () => relay!.catchUp() }),
              async close() { closing.abort(); await nativePeer?.close(); for (const port of ports) port.close() },
            }
          },
        })
        await connectNative()
        serveBrowserPeer(endpoint, peer)
        return {
          identity: bytesToBase64Url(peer.node.identity), groupId: bytesToBase64Url(peer.node.groupId),
          transportAuthor: peer.transport.identity,
        } satisfies BrowserBridgeIdentity
      }
      case 'sync': {
        if (relay !== undefined) await relay.catchUp()
        // Certified inline controls establish the reader grant before the
        // authenticated peer link can supply any detached application bodies.
        try { await peer!.node.waitForIdle() }
        catch (error) {
          if (!(error instanceof Error && error.cause instanceof LedgerRecordError && error.cause.code === 'LEDGER_PAYLOAD_UNAVAILABLE')) throw error
        }
        await connectNative()
        await peer!.transport.catchUp()
        await peer!.node.waitForIdle()
        return null
      }
      case 'state': {
        await peer!.node.waitForIdle()
        const status = await peer!.node.status()
        return {
          identity: bytesToBase64Url(peer!.node.identity), hash: peer!.materializer.databaseContentHash,
          finalOrderLength: peer!.node.finalOrderLength, finalThrough: peer!.node.finalThrough,
          rows: peer!.node.localSql('SELECT id, claimed_by FROM tasks ORDER BY id', [], { view: 'final' }).rows,
          ...(status.lastError === undefined ? {} : { lastError: status.lastError }),
        } satisfies Omit<BrowserBridgeSnapshot, 'outcomes'>
      }
      case 'serveLink': serveLink(request.port!); return null
      case 'receiveLink': peer!.transport.connect(receiveLink(request.port!, request.identity!)); return null
      default: throw new Error('UNKNOWN_BROWSER_BRIDGE_COMMAND')
    }
  }
  void run().then((value) => endpoint.postMessage({ fixture: 'response', id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ fixture: 'response', id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
